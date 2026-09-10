import type {
  AgentId,
  BlastRadiusReport,
  RiskClass,
  ResourceSensitivity
} from '@chronicle/core-types';
import { DelegationManager } from '@chronicle/delegation-manager';

export class BlastRadiusAnalyzer {
  private delegationManager: DelegationManager;

  constructor(delegationManager: DelegationManager) {
    this.delegationManager = delegationManager;
  }

  /**
   * Compute comprehensive blast radius and risk exposure report for an agent.
   */
  public calculateBlastRadius(agentId: AgentId): BlastRadiusReport | null {
    const agent = this.delegationManager.getAgent(agentId);
    if (!agent) return null;

    // 1. Gather all active delegations for this agent
    const allDelegations = this.delegationManager.listDelegations();
    const agentDelegations = allDelegations.filter(
      d => d.delegateeId === agentId && !d.revoked
    );

    // 2. Discover reachable tools and maximum financial exposures
    const toolsSet = new Set<string>(agent.allowedCapabilities);
    let maximumFinancialExposure = 0;

    for (const d of agentDelegations) {
      for (const t of d.constraints.allowedTools) {
        toolsSet.add(t);
      }
      const exposure = d.constraints.cumulativeValueLimit ?? d.constraints.maxTransactionValue ?? 0;
      if (exposure > maximumFinancialExposure) {
        maximumFinancialExposure = exposure;
      }
    }

    const reachableTools: BlastRadiusReport['reachableTools'] = [];
    for (const tool of toolsSet) {
      let risk: RiskClass = 'LOW';
      let exposure: number | undefined = undefined;

      if (tool.includes('wire') || tool.includes('transfer')) {
        risk = 'CRITICAL';
        exposure = maximumFinancialExposure;
      } else if (tool.includes('refund') || tool.includes('payment')) {
        risk = 'HIGH';
        exposure = maximumFinancialExposure;
      } else if (tool.includes('database') || tool.includes('firewall')) {
        risk = 'CRITICAL';
      } else if (tool.includes('pii') || tool.includes('customer')) {
        risk = 'HIGH';
      } else if (tool.includes('email') || tool.includes('slack')) {
        risk = 'MEDIUM';
      }

      reachableTools.push({
        tool,
        risk,
        maxExposure: exposure
      });
    }

    // 3. Estimate reachable resource types and sensitivities
    const reachableResources: BlastRadiusReport['reachableResources'] = [
      {
        resourceType: 'CUSTOMER_CRM_RECORDS',
        sensitivity: toolsSet.has('crm_read_pii') ? 'CONFIDENTIAL' : 'INTERNAL',
        countEstimate: 2500
      },
      {
        resourceType: 'PAYMENT_LEDGER',
        sensitivity: toolsSet.has('stripe_refund') || toolsSet.has('send_wire_transfer') ? 'CRITICAL' : 'INTERNAL',
        countEstimate: 12000
      },
      {
        resourceType: 'COMMUNICATION_CHANNELS',
        sensitivity: toolsSet.has('send_external_email') ? 'SENSITIVE' : 'INTERNAL',
        countEstimate: 50
      }
    ];

    // 4. Discover reachable downstream sub-agents
    const childDelegations = allDelegations.filter(
      d => d.delegatorId === agentId && !d.revoked
    );
    const reachableAgents = childDelegations.map(d => d.delegateeId);

    // 5. Detect potential privilege escalation paths
    const privilegeEscalationPaths: BlastRadiusReport['privilegeEscalationPaths'] = [];

    if (toolsSet.has('crm_read_pii') && toolsSet.has('send_external_email')) {
      privilegeEscalationPaths.push({
        description: 'Exfiltration Path: Direct read access to customer PII combined with outbound email capability',
        severity: 'CRITICAL',
        hops: ['crm_read_pii', 'send_external_email']
      });
    }

    if (toolsSet.has('modify_security_group') && toolsSet.has('query_production_database')) {
      privilegeEscalationPaths.push({
        description: 'Lateral Movement Path: Firewall modification capability combined with DB query access',
        severity: 'CRITICAL',
        hops: ['modify_security_group', 'query_production_database']
      });
    }

    return {
      agentId,
      calculatedAt: new Date().toISOString(),
      agentStatus: agent.status,
      riskClass: agent.riskClass,
      directCapabilities: agent.allowedCapabilities,
      reachableTools,
      reachableResources,
      reachableAgents,
      maximumFinancialExposure,
      privilegeEscalationPaths,
      killSwitchActive: agent.status === 'QUARANTINED'
    };
  }
}
