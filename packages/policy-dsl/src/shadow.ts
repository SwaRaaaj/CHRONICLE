/**
 * Chronicle Shadow Policy Comparator (§29, §30, §51, §52, §61, §62)
 * Evaluates current and candidate policy versions side-by-side on historical
 * audit logs to compute divergence, newly allowed high-risk transactions,
 * and safety regression reports prior to production deployment.
 */

import type {
  ActionRequest,
  DecisionEffect,
  ActionHistoryRecord,
  PolicyAST
} from '@chronicle/core-types';
import { evaluatePolicyDSL, parsePolicyDSL } from './index.ts';

export interface DivergenceItem {
  actionId: string;
  tool: string;
  parameters: Record<string, unknown>;
  currentDecision: DecisionEffect;
  proposedDecision: DecisionEffect;
  divergenceType: 'EXPANSION' | 'CONTRACTION' | 'STEP_UP_MODIFIED' | 'NEUTRAL';
  riskImplication: 'HIGH_RISK_EXPANSION' | 'LOW_RISK_EXPANSION' | 'STRICTER_ENFORCEMENT' | 'NEUTRAL';
  reason?: string;
}

export interface ShadowComparisonReport {
  totalEvaluated: number;
  concordanceCount: number;
  concordanceRate: number; // 0-100%
  divergenceCount: number;
  summary: {
    newlyAllowed: number;
    newlyDenied: number;
    newlyHeld: number;
    highRiskExpansions: number;
  };
  divergences: DivergenceItem[];
  recommendation: 'SAFE_TO_DEPLOY' | 'REVIEW_REQUIRED' | 'DANGEROUS_EXPANSION';
}

export class ShadowPolicyComparator {
  /**
   * Compares current policy against proposed policy across historical action records.
   */
  public static compare(
    current: PolicyAST | string,
    proposed: PolicyAST | string,
    historicalActions: ActionHistoryRecord[]
  ): ShadowComparisonReport {
    const currentAst = typeof current === 'string' ? parsePolicyDSL(current) : current;
    const proposedAst = typeof proposed === 'string' ? parsePolicyDSL(proposed) : proposed;

    let concordanceCount = 0;
    let newlyAllowed = 0;
    let newlyDenied = 0;
    let newlyHeld = 0;
    let highRiskExpansions = 0;
    const divergences: DivergenceItem[] = [];

    for (const record of historicalActions) {
      const mockReq: ActionRequest = {
        actionId: record.actionId,
        tenantId: 'tenant_default',
        sessionId: record.sessionId,
        taskId: record.taskId,
        agentId: record.agentId,
        delegationId: record.delegationId || 'del_default',
        actionType: record.actionType,
        tool: record.tool,
        resource: {
          id: record.resourceId,
          type: record.tool.split('_')[0] || 'resource',
          sensitivity: 'INTERNAL',
          environment: 'production',
        },
        parameters: record.parameters || {},
        parametersHash: 'sha256:dummy',
        timestamp: record.timestamp || new Date().toISOString(),
      };

      const currentEval = evaluatePolicyDSL(currentAst, mockReq);
      const proposedEval = evaluatePolicyDSL(proposedAst, mockReq);

      const curDecision: DecisionEffect = currentEval.matched ? currentEval.effect : 'DENY';
      const propDecision: DecisionEffect = proposedEval.matched ? proposedEval.effect : 'DENY';

      if (curDecision === propDecision) {
        concordanceCount++;
      } else {
        let divType: DivergenceItem['divergenceType'] = 'NEUTRAL';
        let riskImp: DivergenceItem['riskImplication'] = 'NEUTRAL';

        const amount = Number(record.parameters?.amount ?? 0);

        if (curDecision !== 'ALLOW' && propDecision === 'ALLOW') {
          divType = 'EXPANSION';
          newlyAllowed++;
          if (amount > 1000 || record.tool.includes('delete') || record.tool.includes('wire')) {
            riskImp = 'HIGH_RISK_EXPANSION';
            highRiskExpansions++;
          } else {
            riskImp = 'LOW_RISK_EXPANSION';
          }
        } else if (curDecision === 'ALLOW' && propDecision !== 'ALLOW') {
          divType = 'CONTRACTION';
          riskImp = 'STRICTER_ENFORCEMENT';
          if (propDecision === 'DENY') newlyDenied++;
          if (propDecision === 'HOLD') newlyHeld++;
        } else if (curDecision === 'HOLD' && propDecision === 'DENY') {
          divType = 'CONTRACTION';
          newlyDenied++;
          riskImp = 'STRICTER_ENFORCEMENT';
        } else if (curDecision === 'DENY' && propDecision === 'HOLD') {
          divType = 'STEP_UP_MODIFIED';
          newlyHeld++;
          riskImp = 'LOW_RISK_EXPANSION';
        }

        divergences.push({
          actionId: record.actionId,
          tool: record.tool,
          parameters: record.parameters || {},
          currentDecision: curDecision,
          proposedDecision: propDecision,
          divergenceType: divType,
          riskImplication: riskImp,
          reason: proposedEval.reason || currentEval.reason
        });
      }
    }

    const total = historicalActions.length;
    const concordanceRate = total === 0 ? 100 : Math.round((concordanceCount / total) * 100);

    let recommendation: ShadowComparisonReport['recommendation'] = 'SAFE_TO_DEPLOY';
    if (highRiskExpansions > 0) {
      recommendation = 'DANGEROUS_EXPANSION';
    } else if (divergences.length > 0) {
      recommendation = 'REVIEW_REQUIRED';
    }

    return {
      totalEvaluated: total,
      concordanceCount,
      concordanceRate,
      divergenceCount: divergences.length,
      summary: {
        newlyAllowed,
        newlyDenied,
        newlyHeld,
        highRiskExpansions
      },
      divergences,
      recommendation
    };
  }
}
