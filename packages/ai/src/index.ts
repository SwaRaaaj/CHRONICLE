/**
 * Chronicle AI Policy Assistant (§60, §61, §116)
 * Deterministic NLP translation and advisory assistant:
 * - Translates human intent into declarative Policy ASTs
 * - Explains authorization decisions and risk factors in plain English
 * - Recommends safeguard constraints based on blast radius analysis
 * - Enforces pre-deployment simulation & validation gates (§61)
 */

import type {
  PolicyAST,
  PolicyCondition,
  AuthorizationDecision,
  BlastRadiusReport
} from '@chronicle/core-types';
import { parsePolicyDSL } from '@chronicle/policy-dsl';

export interface GeneratedPolicyResult {
  dsl: string;
  ast: PolicyAST;
  explanation: string;
  warnings: string[];
  requiresValidation: boolean;
}

export interface PolicySafetyAnalysis {
  safe: boolean;
  score: number; // 0-100 (100 = strictest safety)
  issues: string[];
  recommendations: string[];
}

export class AIPolicyAssistant {
  /**
   * Translates natural language descriptions into valid Policy DSL and AST (§60)
   */
  public naturalLanguageToPolicy(prompt: string): GeneratedPolicyResult {
    const text = prompt.trim().toLowerCase();
    const warnings: string[] = [];

    let effect: 'ALLOW' | 'DENY' | 'HOLD' = 'ALLOW';
    if (text.startsWith('deny') || text.startsWith('block') || text.startsWith('prohibit') || text.startsWith('prevent') || text.includes('must be denied')) {
      effect = 'DENY';
    } else if (text.startsWith('hold') || text.startsWith('require approval for') || text.startsWith('require review for')) {
      effect = 'HOLD';
    } else if (text.includes('allow') || text.includes('permit')) {
      effect = 'ALLOW';
    } else if (text.includes('deny') || text.includes('block')) {
      effect = 'DENY';
    } else if (text.includes('hold') || text.includes('review')) {
      effect = 'HOLD';
    }

    // Identify target action / tool
    let targetAction = 'stripe_refund';
    if (text.includes('wire transfer') || text.includes('wire_transfer') || text.includes('send_wire')) {
      targetAction = 'send_wire_transfer';
    } else if (text.includes('email') || text.includes('broadcast')) {
      targetAction = 'send_external_email';
    } else if (text.includes('customer') || text.includes('search_customer')) {
      targetAction = 'search_customers';
    } else if (text.includes('deploy') || text.includes('release')) {
      targetAction = 'deploy_production';
    } else if (text.includes('refund') || text.includes('stripe')) {
      targetAction = 'stripe_refund';
    } else {
      const toolMatch = text.match(/(?:for|on|tool)\s+([a-z_][a-z0-9_]*)/);
      if (toolMatch) {
        targetAction = toolMatch[1];
      } else {
        targetAction = '*';
        warnings.push("Target action defaulted to wildcard '*'. Wildcard targets broaden blast radius (§61).");
      }
    }

    const conditions: string[] = [];

    // Extract amount ceiling: e.g. "under $1000", "up to 2500", "<= 5000", "maximum 500"
    const amountMatch = text.match(/(?:under|below|less than|up to|max(?:imum)?|ceiling|<=?)\s*\$?(\d+)/i);
    if (amountMatch) {
      conditions.push(`amount <= ${amountMatch[1]}`);
    }

    // Extract approval threshold: e.g. "require approval above $1500"
    let requireApprovalAbove: number | undefined;
    const approvalMatch = text.match(/(?:require approval above|approval over|human review over|step-up above)\s*\$?(\d+)/i);
    if (approvalMatch) {
      requireApprovalAbove = parseInt(approvalMatch[1]);
    }

    // Extract workflow state requirement: e.g. "when workflow is approved", "only if approved"
    if (text.includes('approved') || text.includes('workflow state is approved') || text.includes('pr is approved')) {
      conditions.push('workflow.state == "APPROVED"');
    }

    // Extract environment condition: e.g. "in production", "internal environment"
    if (text.includes('in production') || text.includes('production environment')) {
      conditions.push('resource.environment == "production"');
    } else if (text.includes('in staging') || text.includes('staging environment')) {
      conditions.push('resource.environment == "staging"');
    }

    // Extract sensitivity condition: e.g. "not restricted", "internal only"
    if (text.includes('restricted') && (text.includes('not') || text.includes('no'))) {
      conditions.push('NOT resource.sensitivity == "RESTRICTED"');
    } else if (text.includes('confidential')) {
      conditions.push('resource.sensitivity == "CONFIDENTIAL"');
    }

    // Extract sequence prerequisite: e.g. "only after searching customers"
    if (text.includes('after search') || text.includes('after customer lookup')) {
      conditions.push('sequence.has_occurred == "search_customers"');
    }

    // Build canonical DSL string
    const policyName = `policy_ai_${Date.now().toString(36)}`;
    let dsl = `POLICY ${policyName}\n${effect} ${targetAction}`;
    if (conditions.length > 0) {
      dsl += `\nWHEN ${conditions.join(' AND ')}`;
    }
    if (requireApprovalAbove !== undefined) {
      dsl += `\nREQUIRE_APPROVAL_ABOVE ${requireApprovalAbove}`;
    }

    const ast = parsePolicyDSL(dsl);

    return {
      dsl,
      ast,
      explanation: `Synthesized ${effect} policy for action '${targetAction}' with ${conditions.length} condition(s)${requireApprovalAbove ? ` and approval ceiling $${requireApprovalAbove}` : ''}.`,
      warnings,
      requiresValidation: true // Mandated by §61: all AI-generated policies must be validated prior to activation
    };
  }

  /**
   * Produces an interpretable, human-readable explanation of an authorization decision (§18, §116)
   */
  public explainDecision(decision: AuthorizationDecision): string {
    const parts: string[] = [];

    parts.push(`Decision: ${decision.decision} (Risk Score: ${decision.riskScore}/100, Tier: ${decision.riskClass})`);
    parts.push(`Primary Explanation: ${decision.explanation}`);

    if (decision.reasonCodes.length > 0) {
      parts.push(`Reason Codes: ${decision.reasonCodes.join(', ')}`);
    }

    if (decision.decision === 'HOLD') {
      parts.push('Next Steps: Requires human sponsor review. Step-up ticket created. Temporary authorization will activate upon sponsor signature.');
    } else if (decision.decision === 'DENY') {
      if (decision.reasonCodes.includes('AGENT_QUARANTINED')) {
        parts.push('Security Note: Agent is under emergency quarantine. Contact security team to investigate potential compromise.');
      } else if (decision.reasonCodes.includes('MONOTONIC_NARROWING_VIOLATION')) {
        parts.push('Security Note: Privilege escalation attempt blocked. Sub-agents cannot claim privileges not held by their parent delegator.');
      } else if (decision.reasonCodes.includes('CUMULATIVE_LIMIT_EXCEEDED')) {
        parts.push('Security Note: Cumulative financial limit reached. Further spend requires parent delegation expansion.');
      }
    } else if (decision.decision === 'ALLOW') {
      if (decision.grant) {
        parts.push(`Cryptographic Grant: Single-use grant issued (${decision.grant.grantId}). Valid for 60 seconds with strict parameter SHA-256 binding.`);
      }
    }

    return parts.join('\n');
  }

  /**
   * Generates defensive policy recommendations based on blast radius analysis (§38, §60)
   */
  public suggestPolicySafeguards(report: BlastRadiusReport): string[] {
    const suggestions: string[] = [];

    if (report.maximumFinancialExposure > 5000) {
      suggestions.push(
        `High Financial Exposure ($${report.maximumFinancialExposure.toLocaleString()}): Add 'REQUIRE_APPROVAL_ABOVE 2500' to cap autonomous transfer volume.`
      );
    }

    const dangerousTools = report.reachableTools.filter(t => t.risk === 'CRITICAL' || t.risk === 'HIGH');
    if (dangerousTools.length > 0) {
      const names = dangerousTools.map(t => t.tool).join(', ');
      suggestions.push(
        `High-Risk Tool Access [${names}]: Implement prerequisite sequence checks (e.g. sequence.has_occurred) or restrict to staging environments.`
      );
    }

    if (report.reachableResources.some(r => r.sensitivity === 'CRITICAL' || r.sensitivity === 'SENSITIVE')) {
      suggestions.push(
        `Restricted Resource Reachability: Add 'WHEN NOT resource.sensitivity == "CRITICAL"' to guarantee sensitive data isolation.`
      );
    }

    if (suggestions.length === 0) {
      suggestions.push('Agent has tightly scoped permissions with acceptable risk parameters.');
    }

    return suggestions;
  }

  /**
   * Validates policy safety (§61)
   */
  public validatePolicySafety(ast: PolicyAST): PolicySafetyAnalysis {
    const issues: string[] = [];
    const recommendations: string[] = [];
    let score = 100;

    if (ast.targetAction === '*') {
      issues.push("Target action is wildcard '*' — grants unconditional tool coverage.");
      score -= 30;
      recommendations.push('Specify explicit tools (e.g. stripe_refund) instead of wildcard.');
    }

    if (ast.effect === 'ALLOW' && ast.conditions.length === 0) {
      issues.push('Policy has effect ALLOW with no conditions — unconditional permit.');
      score -= 40;
      recommendations.push('Add at least one condition restricting amount, resource environment, or workflow state.');
    }

    if (ast.effect === 'ALLOW' && ast.requireApprovalAbove === undefined) {
      const hasAmountCondition = ast.conditions.some(c => c.field === 'amount');
      if (!hasAmountCondition) {
        issues.push('No financial ceiling or approval threshold defined.');
        score -= 20;
        recommendations.push("Add 'REQUIRE_APPROVAL_ABOVE <amount>' or 'amount <= <ceiling>'.");
      }
    }

    return {
      safe: issues.length === 0,
      score: Math.max(0, score),
      issues,
      recommendations
    };
  }
}
