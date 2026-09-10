/**
 * Test Suite: AI Policy Assistant (§60, §61, §116)
 */

import { AIPolicyAssistant } from '../packages/ai/src/index.ts';
import type { AuthorizationDecision, BlastRadiusReport } from '../packages/core-types/src/index.ts';

let passed = 0;
let failed = 0;

function assert(condition: boolean, message: string) {
  if (condition) {
    console.log(`  ✔ ${message}`);
    passed++;
  } else {
    console.error(`  ✘ FAIL: ${message}`);
    failed++;
  }
}

async function runAIAssistantTests() {
  console.log('\n=== TESTING AI POLICY ASSISTANT (§60, §61, §116) ===\n');

  const ai = new AIPolicyAssistant();

  // 1. Natural language policy translation
  const res1 = ai.naturalLanguageToPolicy('Allow refund up to $2500 when workflow is approved and require approval above $1500');
  assert(res1.ast.targetAction === 'stripe_refund', 'identifies target action stripe_refund from prompt');
  assert(res1.ast.effect === 'ALLOW', 'identifies decision effect ALLOW');
  assert(res1.ast.requireApprovalAbove === 1500, 'extracts REQUIRE_APPROVAL_ABOVE 1500');
  assert(res1.ast.conditions.length >= 2, 'extracts amount and workflow conditions');
  assert(res1.requiresValidation === true, 'enforces mandatory pre-activation validation flag (§61)');

  // 2. Deny policy translation with restricted sensitivity
  const res2 = ai.naturalLanguageToPolicy('Deny wire transfer on restricted sensitivity');
  assert(res2.ast.targetAction === 'send_wire_transfer', 'identifies target action send_wire_transfer');
  assert(res2.ast.effect === 'DENY', 'identifies decision effect DENY');

  // 3. Explain decision
  const mockDecision: AuthorizationDecision = {
    decision: 'HOLD',
    riskScore: 75,
    riskClass: 'HIGH',
    reasonCodes: ['APPROVAL_REQUIRED', 'HIGH_VALUE_TRANSACTION'],
    explanation: 'Transaction $3,500 exceeds autonomous approval threshold $2,500',
    latencyMs: 1.2
  };
  const explanation = ai.explainDecision(mockDecision);
  assert(explanation.includes('HOLD') && explanation.includes('3,500') && explanation.includes('sponsor review'), 'generates clear human-readable explanation for HOLD');

  // 4. Suggest policy safeguards from blast radius
  const mockBlast: BlastRadiusReport = {
    agentId: 'agent_devops',
    riskClass: 'CRITICAL',
    maximumFinancialExposure: 50000,
    reachableTools: [
      { tool: 'deploy_production', risk: 'CRITICAL', maxExposure: 50000 },
      { tool: 'k8s_delete_pod', risk: 'HIGH', maxExposure: 0 }
    ],
    reachableResources: [
      { resourceType: 'cluster', sensitivity: 'RESTRICTED', environment: 'production' }
    ],
    reachableDataDomains: ['infrastructure'],
    maxPrivilegePathLength: 2,
    generatedAt: new Date().toISOString()
  };
  const safeguards = ai.suggestPolicySafeguards(mockBlast);
  assert(safeguards.length >= 2, 'suggests multiple safeguard recommendations for critical blast radius');
  assert(safeguards.some(s => s.includes('Financial Exposure')), 'includes financial exposure safeguard');
  assert(safeguards.some(s => s.includes('Restricted Resource')), 'includes restricted resource safeguard');

  // 5. Policy safety validation gate
  const unsafeDsl = ai.naturalLanguageToPolicy('Allow all tools with no conditions');
  const safety = ai.validatePolicySafety(unsafeDsl.ast);
  assert(safety.safe === false, 'detects unsafe policy with wildcards or missing constraints');
  assert(safety.score < 100, 'penalizes safety score for permissive policy');
  assert(safety.issues.length > 0, 'provides specific safety issues');

  console.log(`\nResults: ${passed} passed, ${failed} failed\n`);
  if (failed > 0) {
    process.exit(1);
  }
}

runAIAssistantTests().catch(err => {
  console.error(err);
  process.exit(1);
});
