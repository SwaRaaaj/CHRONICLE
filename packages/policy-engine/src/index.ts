import type {
  ActionRequest,
  ActionContext,
  AuthorizationDecision,
  DecisionEffect,
  ReasonCode,
  RiskClass,
  PolicySimulationRequest,
  PolicySimulationResult,
  ActionHistoryRecord,
  TaskIntent
} from '@chronicle/core-types';
import {
  createAuthorizationGrant,
  canonicalHash
} from '@chronicle/crypto-primitives';
import { DelegationManager } from '@chronicle/delegation-manager';
import { SequenceDetector } from '@chronicle/sequence-detector';

export interface PolicyRule {
  id: string;
  name: string;
  effect: DecisionEffect;
  conditions: {
    tools?: string[];
    actionTypes?: string[];
    resourceSensitivities?: string[];
    maxAmount?: number;
    requireApprovalAbove?: number;
    environments?: string[];
  };
  reasonCode: ReasonCode;
  explanation: string;
}

export class PolicyEngine {
  private delegationManager: DelegationManager;
  private sequenceDetector: SequenceDetector;
  private controlPlanePrivateKeyPem: string;
  private policyVersion: string = 'v1.4.0-enterprise';
  private customRules: PolicyRule[] = [];
  private killSwitchActive: boolean = false;
  private quarantinedAgents: Set<string> = new Set();

  constructor(
    delegationManager: DelegationManager,
    sequenceDetector: SequenceDetector,
    controlPlanePrivateKeyPem: string
  ) {
    this.delegationManager = delegationManager;
    this.sequenceDetector = sequenceDetector;
    this.controlPlanePrivateKeyPem = controlPlanePrivateKeyPem;
  }

  public setKillSwitch(active: boolean): void {
    this.killSwitchActive = active;
  }

  public quarantineAgent(agentId: string): void {
    this.quarantinedAgents.add(agentId);
    this.delegationManager.setAgentStatus(agentId, 'QUARANTINED');
  }

  public unquarantineAgent(agentId: string): void {
    this.quarantinedAgents.delete(agentId);
    this.delegationManager.setAgentStatus(agentId, 'ACTIVE');
  }

  public isAgentQuarantined(agentId: string): boolean {
    return this.quarantinedAgents.has(agentId);
  }

  public calculateRiskScore(
    request: ActionRequest,
    context?: Partial<ActionContext>,
    anomalyScore: number = 0
  ): { riskScore: number; riskClass: RiskClass } {
    let score = 0;

    // 1. Resource sensitivity weight
    switch (request.resource.sensitivity) {
      case 'PUBLIC': score += 5; break;
      case 'INTERNAL': score += 20; break;
      case 'CONFIDENTIAL': score += 45; break;
      case 'SENSITIVE': score += 70; break;
      case 'CRITICAL': score += 90; break;
      default: score += 25; break;
    }

    // 2. Monetary value impact
    const amount = typeof request.parameters.amount === 'number' ? request.parameters.amount : 0;
    if (amount > 0) {
      if (amount <= 100) score = Math.max(score, 20);
      else if (amount <= 500) score = Math.max(score, 40);
      else if (amount <= 2500) score = Math.max(score, 75);
      else score = Math.max(score, 95);
    }

    // 3. Environment weighting
    if (request.resource.environment === 'production') {
      score = Math.min(100, score + 15);
    }

    // 4. Anomaly score blend
    score = Math.min(100, Math.max(score, anomalyScore));

    // Determine RiskClass
    let riskClass: RiskClass = 'LOW';
    if (score >= 85) riskClass = 'CRITICAL';
    else if (score >= 65) riskClass = 'HIGH';
    else if (score >= 35) riskClass = 'MEDIUM';

    return { riskScore: score, riskClass };
  }

  /**
   * Evaluate full AACT Pipeline:
   * 1. Kill-Switch / Quarantine Check
   * 2. Delegation Chain & Monotonic Narrowing Check
   * 3. Sequence & Anomaly Check
   * 4. Parameter & Value Threshold Policies
   * 5. Step-Up Approval Determination
   * 6. Cryptographic Grant Generation on ALLOW
   */
  public async evaluate(
    request: ActionRequest,
    context?: Partial<ActionContext>
  ): Promise<AuthorizationDecision> {
    const startTime = performance.now();
    const evaluatedAt = new Date().toISOString();

    // 1. Global Kill-Switch Check
    if (this.killSwitchActive) {
      const latencyMs = Math.round((performance.now() - startTime) * 100) / 100;
      return {
        actionId: request.actionId,
        decision: 'DENY',
        reasonCodes: ['TOOL_LOCKED_DOWN'],
        explanation: 'Global emergency control plane kill switch is currently ACTIVE. All actions suspended.',
        policyVersion: this.policyVersion,
        riskScore: 100,
        riskClass: 'CRITICAL',
        evaluatedAt,
        latencyMs
      };
    }

    // 2. Agent Quarantine Check
    if (this.quarantinedAgents.has(request.agentId)) {
      const latencyMs = Math.round((performance.now() - startTime) * 100) / 100;
      return {
        actionId: request.actionId,
        decision: 'DENY',
        reasonCodes: ['AGENT_QUARANTINED'],
        explanation: `Agent '${request.agentId}' is under active security quarantine.`,
        policyVersion: this.policyVersion,
        riskScore: 100,
        riskClass: 'CRITICAL',
        evaluatedAt,
        latencyMs
      };
    }

    // 3. Verify Delegation Chain
    const delegationResult = this.delegationManager.verifyDelegationChain(
      request.delegationId,
      request.agentId
    );

    if (!delegationResult.valid) {
      const latencyMs = Math.round((performance.now() - startTime) * 100) / 100;
      return {
        actionId: request.actionId,
        decision: 'DENY',
        reasonCodes: [delegationResult.reasonCode || 'DELEGATION_INVALID'],
        explanation: delegationResult.explanation || 'Delegation chain verification failed',
        policyVersion: this.policyVersion,
        riskScore: 90,
        riskClass: 'CRITICAL',
        evaluatedAt,
        latencyMs
      };
    }

    const delegationEnvelope = this.delegationManager.getDelegation(request.delegationId)!;
    const constraints = delegationEnvelope.constraints;

    // 4. Verify Constraints from Delegation
    // A. Tool authorization
    if (!constraints.allowedTools.includes('*') && !constraints.allowedTools.includes(request.tool)) {
      const latencyMs = Math.round((performance.now() - startTime) * 100) / 100;
      return {
        actionId: request.actionId,
        decision: 'DENY',
        reasonCodes: ['POLICY_DENY'],
        explanation: `Tool '${request.tool}' is not authorized by delegation envelope constraints`,
        policyVersion: this.policyVersion,
        riskScore: 85,
        riskClass: 'HIGH',
        evaluatedAt,
        latencyMs
      };
    }

    // B. Transaction Value Ceiling
    const amount = typeof request.parameters.amount === 'number' ? request.parameters.amount : 0;
    if (constraints.maxTransactionValue !== undefined && amount > constraints.maxTransactionValue) {
      const latencyMs = Math.round((performance.now() - startTime) * 100) / 100;
      return {
        actionId: request.actionId,
        decision: 'DENY',
        reasonCodes: ['LIMIT_EXCEEDED'],
        explanation: `Transaction amount $${amount} exceeds delegation limit of $${constraints.maxTransactionValue}`,
        policyVersion: this.policyVersion,
        riskScore: 85,
        riskClass: 'HIGH',
        evaluatedAt,
        latencyMs
      };
    }

    // 5. Sequence & Anomaly Detection
    const seqResult = this.sequenceDetector.evaluateSequence(
      request,
      context?.task,
      delegationEnvelope
    );

    if (!seqResult.valid) {
      const latencyMs = Math.round((performance.now() - startTime) * 100) / 100;
      return {
        actionId: request.actionId,
        decision: 'DENY',
        reasonCodes: [seqResult.reasonCode || 'SEQUENCE_ANOMALY'],
        explanation: seqResult.explanation || 'Action sequence policy violated',
        policyVersion: this.policyVersion,
        riskScore: seqResult.anomalyScore,
        riskClass: seqResult.anomalyScore >= 85 ? 'CRITICAL' : 'HIGH',
        evaluatedAt,
        latencyMs
      };
    }

    // 6. Compute Dynamic Risk Score
    const { riskScore, riskClass } = this.calculateRiskScore(request, context, seqResult.anomalyScore);

    // 7. Step-Up Human Approval Check (HOLD)
    const approvalThreshold = constraints.requireApprovalAbove ?? 1000;
    if (amount > approvalThreshold) {
      const approvalId = 'appr_' + Math.random().toString(36).substring(2, 12);
      const latencyMs = Math.round((performance.now() - startTime) * 100) / 100;
      return {
        actionId: request.actionId,
        decision: 'HOLD',
        reasonCodes: ['MISSING_REQUIRED_APPROVAL'],
        explanation: `Action amount $${amount} exceeds auto-approval threshold ($${approvalThreshold}). Held for human sponsor sign-off.`,
        policyVersion: this.policyVersion,
        riskScore,
        riskClass,
        approvalId,
        requiredApprovalRole: 'FINANCE_SPONSOR',
        evaluatedAt,
        latencyMs
      };
    }

    // 8. Authorization Grant Creation (ALLOW)
    // Compute exact canonical hash of parameters to bind grant to payload
    const parametersHash = canonicalHash(request.parameters);
    const grantId = 'grant_' + Math.random().toString(36).substring(2, 12);

    const grant = createAuthorizationGrant(
      grantId,
      request.actionId,
      request.tenantId,
      request.agentId,
      request.actionType,
      request.tool,
      request.resource.id,
      parametersHash,
      request.delegationId,
      this.controlPlanePrivateKeyPem,
      60 // 60 seconds TTL
    );

    const latencyMs = Math.round((performance.now() - startTime) * 100) / 100;
    return {
      actionId: request.actionId,
      decision: 'ALLOW',
      reasonCodes: ['POLICY_PERMIT'],
      explanation: 'Action verified against delegation constraints, monotonic narrowing, and sequence invariant rules.',
      policyVersion: this.policyVersion,
      riskScore,
      riskClass,
      grant,
      evaluatedAt,
      latencyMs
    };
  }

  /**
   * Run Counterfactual Policy Simulation:
   * Evaluate what would happen if a different policy or limit was applied across historic transactions.
   */
  public simulatePolicy(
    request: PolicySimulationRequest,
    history: ActionHistoryRecord[]
  ): PolicySimulationResult {
    const simulationId = 'sim_' + Math.random().toString(36).substring(2, 10);
    const affectedAgentsSet = new Set<string>();
    const highRiskNewlyAllowed: PolicySimulationResult['highRiskNewlyAllowed'] = [];

    let unchangedCount = 0;
    let newlyAllowedCount = 0;
    let newlyDeniedCount = 0;
    let newlyHeldCount = 0;

    // Parse simulation policy threshold (example: lowered or raised limits)
    let parsedThreshold = 1000;
    try {
      const parsed = JSON.parse(request.proposedPolicyContent);
      if (parsed.requireApprovalAbove !== undefined) {
        parsedThreshold = parsed.requireApprovalAbove;
      }
    } catch {
      // fallback
    }

    for (const record of history) {
      affectedAgentsSet.add(record.agentId);
      const amount = typeof record.parameters.amount === 'number' ? record.parameters.amount : 0;
      
      let hypotheticalDecision: DecisionEffect = record.decision;
      if (amount > parsedThreshold) {
        hypotheticalDecision = 'HOLD';
      } else if (record.decision === 'HOLD' && amount <= parsedThreshold) {
        hypotheticalDecision = 'ALLOW';
      }

      if (hypotheticalDecision === record.decision) {
        unchangedCount++;
      } else if (hypotheticalDecision === 'ALLOW') {
        newlyAllowedCount++;
        if (amount > 500) {
          highRiskNewlyAllowed.push({
            actionId: record.actionId,
            actionType: record.actionType,
            agentId: record.agentId,
            amount,
            resourceId: record.resourceId
          });
        }
      } else if (hypotheticalDecision === 'DENY') {
        newlyDeniedCount++;
      } else if (hypotheticalDecision === 'HOLD') {
        newlyHeldCount++;
      }
    }

    return {
      simulationId,
      totalEvaluated: history.length,
      unchangedCount,
      newlyAllowedCount,
      newlyDeniedCount,
      newlyHeldCount,
      affectedAgents: Array.from(affectedAgentsSet),
      highRiskNewlyAllowed,
      summaryText: `Simulated policy against ${history.length} historical action records. Result: ${newlyHeldCount} actions shifted to HOLD, ${newlyAllowedCount} newly allowed.`
    };
  }
}
