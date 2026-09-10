import type {
  ActionRequest,
  ActionHistoryRecord,
  SequenceSummary,
  TaskIntent,
  DelegationEnvelope,
  ReasonCode,
  SessionId,
  TaskId,
  AgentId
} from '@chronicle/core-types';

export interface SequenceValidationResult {
  valid: boolean;
  reasonCode?: ReasonCode;
  explanation?: string;
  anomalyScore: number; // 0 to 100
}

export interface ForbiddenSequenceRule {
  id: string;
  name: string;
  sequence: string[]; // e.g. ["read_customer_pii", "send_external_email"]
  maxWindowSeconds?: number;
  reasonCode: ReasonCode;
  severity: 'HIGH' | 'CRITICAL';
  description: string;
}

export interface PrerequisiteRule {
  targetAction: string; // e.g. "send_wire_transfer"
  requiredPriorActions: string[]; // e.g. ["verify_identity"]
  description: string;
}

export class SequenceDetector {
  private history: ActionHistoryRecord[] = [];
  private forbiddenRules: ForbiddenSequenceRule[] = [];
  private prerequisiteRules: PrerequisiteRule[] = [];

  constructor() {
    this.initializeDefaultRules();
  }

  private initializeDefaultRules(): void {
    // 1. Data Exfiltration sequence: Reading sensitive customer PII, then sending external communications
    this.forbiddenRules.push({
      id: 'SEQ_DATA_EXFILTRATION',
      name: 'Sensitive PII Exfiltration via Outbound Communication',
      sequence: ['read_customer_pii', 'send_external_email'],
      maxWindowSeconds: 3600,
      reasonCode: 'FORBIDDEN_SEQUENCE',
      severity: 'CRITICAL',
      description: 'Agent accessed customer PII and subsequently attempted external email transmission'
    });

    this.forbiddenRules.push({
      id: 'SEQ_SLACK_EXFILTRATION',
      name: 'PII Exfiltration via Slack Announcement',
      sequence: ['read_customer_pii', 'post_slack_announcement'],
      maxWindowSeconds: 3600,
      reasonCode: 'FORBIDDEN_SEQUENCE',
      severity: 'CRITICAL',
      description: 'Agent accessed customer PII and subsequently attempted Slack broadcast'
    });

    // 2. Cloud Infrastructure privilege escalation
    this.forbiddenRules.push({
      id: 'SEQ_INFRA_ESCALATION',
      name: 'Firewall Alteration followed by DB Query',
      sequence: ['modify_security_group', 'query_production_database'],
      maxWindowSeconds: 1800,
      reasonCode: 'FORBIDDEN_SEQUENCE',
      severity: 'CRITICAL',
      description: 'Agent modified security firewall rules and subsequently queried production database'
    });

    // 3. Prerequisites: Wire transfer requires identity verification
    this.prerequisiteRules.push({
      targetAction: 'send_wire_transfer',
      requiredPriorActions: ['verify_identity'],
      description: 'Wire transfers strictly require prior identity verification within the same task session'
    });

    this.prerequisiteRules.push({
      targetAction: 'deploy_container',
      requiredPriorActions: ['run_security_scan'],
      description: 'Production container deployment requires prior security scanning'
    });
  }

  public recordAction(record: ActionHistoryRecord): void {
    this.history.push({ ...record });
  }

  public getSessionHistory(sessionId: SessionId): ActionHistoryRecord[] {
    return this.history.filter(h => h.sessionId === sessionId);
  }

  public getTaskHistory(taskId: TaskId): ActionHistoryRecord[] {
    return this.history.filter(h => h.taskId === taskId);
  }

  public getSequenceSummary(sessionId: SessionId, taskId: TaskId): SequenceSummary {
    const sessionRecords = this.history.filter(h => h.sessionId === sessionId || h.taskId === taskId);
    const recentActions = sessionRecords.map(r => r.actionType);
    const cumulativeAmounts: Record<string, number> = {};
    const actionCounts: Record<string, number> = {};

    for (const r of sessionRecords) {
      actionCounts[r.actionType] = (actionCounts[r.actionType] || 0) + 1;
      
      // Extract numeric amount from parameters if present
      if (r.parameters && typeof r.parameters.amount === 'number') {
        cumulativeAmounts[r.actionType] = (cumulativeAmounts[r.actionType] || 0) + r.parameters.amount;
      }
    }

    const firstTime = sessionRecords.length > 0 ? sessionRecords[0].timestamp : new Date().toISOString();
    const lastTime = sessionRecords.length > 0 ? sessionRecords[sessionRecords.length - 1].timestamp : firstTime;

    return {
      sessionId,
      taskId,
      recentActions,
      cumulativeAmounts,
      actionCounts,
      firstActionTime: firstTime,
      lastActionTime: lastTime
    };
  }

  /**
   * Evaluate whether the proposed ActionRequest violates sequence rules,
   * prerequisite requirements, cumulative limits, loop limits, or declared intent.
   */
  public evaluateSequence(
    request: ActionRequest,
    task?: TaskIntent,
    delegation?: DelegationEnvelope
  ): SequenceValidationResult {
    const sessionHistory = this.getSessionHistory(request.sessionId);
    const taskHistory = this.getTaskHistory(request.taskId);
    const relevantHistory = [...new Set([...sessionHistory, ...taskHistory])].sort(
      (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
    );

    const now = new Date(request.timestamp).getTime();

    // 1. Intent Drift Check: Compare action with TaskIntent
    if (task) {
      // Check expected tools
      if (task.expectedTools && task.expectedTools.length > 0) {
        if (!task.expectedTools.includes('*') && !task.expectedTools.includes(request.tool)) {
          return {
            valid: false,
            reasonCode: 'INTENT_DRIFT',
            explanation: `Action tool '${request.tool}' is not within declared task expected tools: [${task.expectedTools.join(', ')}]`,
            anomalyScore: 90
          };
        }
      }

      // Check max allowed value declared in task intent
      if (task.maxAllowedValue !== undefined && typeof request.parameters.amount === 'number') {
        if (request.parameters.amount > task.maxAllowedValue) {
          return {
            valid: false,
            reasonCode: 'LIMIT_EXCEEDED',
            explanation: `Requested amount $${request.parameters.amount} exceeds task max allowed value ($${task.maxAllowedValue})`,
            anomalyScore: 85
          };
        }
      }
    }

    // 2. Missing Prerequisite Sequences
    for (const prereq of this.prerequisiteRules) {
      if (prereq.targetAction === request.actionType) {
        const hasPrereq = relevantHistory.some(
          h => prereq.requiredPriorActions.includes(h.actionType) && h.decision === 'ALLOW'
        );
        if (!hasPrereq) {
          return {
            valid: false,
            reasonCode: 'MISSING_PREREQUISITE_SEQUENCE',
            explanation: `Action '${request.actionType}' requires prior execution of [${prereq.requiredPriorActions.join(', ')}]. ${prereq.description}`,
            anomalyScore: 80
          };
        }
      }
    }

    // 3. Forbidden Sequences
    for (const rule of this.forbiddenRules) {
      const targetStep = rule.sequence[rule.sequence.length - 1];
      if (targetStep === request.actionType) {
        const priorSteps = rule.sequence.slice(0, rule.sequence.length - 1);
        // Look for prior step in relevant history
        const match = relevantHistory.find(h => {
          if (!priorSteps.includes(h.actionType)) return false;
          if (rule.maxWindowSeconds) {
            const historyTime = new Date(h.timestamp).getTime();
            if ((now - historyTime) / 1000 > rule.maxWindowSeconds) return false;
          }
          return true;
        });

        if (match) {
          return {
            valid: false,
            reasonCode: rule.reasonCode,
            explanation: `Forbidden sequence detected: '${match.actionType}' -> '${request.actionType}'. ${rule.description}`,
            anomalyScore: rule.severity === 'CRITICAL' ? 95 : 75
          };
        }
      }
    }

    // 4. Cumulative Limit Check (Smurfing / Structuring evasion defense)
    const proposedAmount = typeof request.parameters.amount === 'number' ? request.parameters.amount : 0;
    if (proposedAmount > 0 && delegation?.constraints.cumulativeValueLimit !== undefined) {
      let currentCumulative = 0;
      for (const h of relevantHistory) {
        if (h.decision === 'ALLOW' && typeof h.parameters.amount === 'number') {
          currentCumulative += h.parameters.amount;
        }
      }

      if (currentCumulative + proposedAmount > delegation.constraints.cumulativeValueLimit) {
        return {
          valid: false,
          reasonCode: 'CUMULATIVE_LIMIT_EXCEEDED',
          explanation: `Cumulative transaction sum ($${currentCumulative} + $${proposedAmount} = $${currentCumulative + proposedAmount}) exceeds delegation cumulative limit ($${delegation.constraints.cumulativeValueLimit})`,
          anomalyScore: 88
        };
      }
    }

    // 5. Runaway Loop Detection (Rapid identical calls)
    const recentWindowRecords = relevantHistory.filter(h => {
      const recTime = new Date(h.timestamp).getTime();
      return (now - recTime) <= 15000; // Last 15 seconds
    });

    const identicalCalls = recentWindowRecords.filter(
      h => h.actionType === request.actionType && h.tool === request.tool && JSON.stringify(h.parameters) === JSON.stringify(request.parameters)
    );

    if (identicalCalls.length >= 4) {
      return {
        valid: false,
        reasonCode: 'SEQUENCE_ANOMALY',
        explanation: `Runaway agent loop detected: 5 rapid calls to '${request.actionType}' in under 15 seconds`,
        anomalyScore: 92
      };
    }

    return {
      valid: true,
      anomalyScore: 10
    };
  }

  public addForbiddenRule(rule: ForbiddenSequenceRule): void {
    this.forbiddenRules.push(rule);
  }

  public addPrerequisiteRule(rule: PrerequisiteRule): void {
    this.prerequisiteRules.push(rule);
  }
}
