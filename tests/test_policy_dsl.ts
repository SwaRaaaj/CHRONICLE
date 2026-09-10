/**
 * Test Suite: Declarative Policy DSL, AST Parser, Evaluator, and Test Runner (§22, §50, §51, §52, §53)
 */

import {
  tokenizePolicyDSL,
  parsePolicyDSL,
  evaluatePolicyDSL,
  runPolicyTests,
  analyzePolicyCoverage,
} from '../packages/policy-dsl/src/index.ts';
import type { ActionRequest, ActionContext, PolicyTestCase, ActionHistoryRecord } from '../packages/core-types/src/index.ts';

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

async function runPolicyDSLTests() {
  console.log('\n=== TESTING DECLARATIVE POLICY DSL ENGINE (§22, §50, §51, §52, §53) ===\n');

  // 1. Lexer & Tokenizer
  const dslSource = `
    POLICY customer_support_refund_v2
    ALLOW stripe_refund
    WHEN amount <= 5000
      AND resource.sensitivity IN ["INTERNAL", "CONFIDENTIAL"]
      AND workflow.state == "APPROVED"
    REQUIRE_APPROVAL_ABOVE 2500
  `;

  const tokens = tokenizePolicyDSL(dslSource);
  assert(tokens.length > 10, 'tokenizes policy DSL source into distinct syntactic tokens');
  assert(tokens.some(t => t.type === 'KEYWORD' && t.value === 'ALLOW'), 'identifies ALLOW keyword');
  assert(tokens.some(t => t.type === 'OPERATOR' && t.value === '<='), 'identifies <= operator');

  // 2. Parser: DSL text -> PolicyAST
  const ast = parsePolicyDSL(dslSource);
  assert(ast.policyId === 'customer_support_refund_v2', 'parses policy ID correctly');
  assert(ast.targetAction === 'stripe_refund', 'parses target action correctly');
  assert(ast.effect === 'ALLOW', 'parses decision effect ALLOW');
  assert(ast.conditions.length === 3, 'parses all 3 WHEN conditions');
  assert(ast.requireApprovalAbove === 2500, 'parses REQUIRE_APPROVAL_ABOVE threshold (2500)');

  // 3. Evaluator: Valid sub-$2500 refund
  const mockReq: ActionRequest = {
    actionId: 'act_dsl_1',
    tenantId: 'tenant_acme',
    sessionId: 'sess_1',
    taskId: 'task_1',
    agentId: 'agent_refund',
    delegationId: 'del_1',
    actionType: 'refund',
    tool: 'stripe_refund',
    resource: { id: 'charge_1', type: 'charge', sensitivity: 'CONFIDENTIAL', environment: 'production' },
    parameters: { amount: 1500, chargeId: 'ch_1' },
    parametersHash: 'sha256:dummy',
    timestamp: new Date().toISOString(),
  };

  const mockCtx: Partial<ActionContext> = {
    workflowState: 'APPROVED',
  };

  const resAllow = evaluatePolicyDSL(ast, mockReq, mockCtx);
  assert(resAllow.matched && resAllow.effect === 'ALLOW', 'evaluates to ALLOW when conditions met and amount <= 2500');

  // 4. Evaluator: High-value refund ($3500 > $2500 threshold) -> HOLD
  const highReq: ActionRequest = {
    ...mockReq,
    parameters: { amount: 3500, chargeId: 'ch_1' },
  };
  const resHold = evaluatePolicyDSL(ast, highReq, mockCtx);
  assert(resHold.matched && resHold.effect === 'HOLD', 'evaluates to HOLD when amount exceeds REQUIRE_APPROVAL_ABOVE (3500 > 2500)');

  // 5. Evaluator: Condition violation (amount > 5000 ceiling) -> DENY
  const exceedReq: ActionRequest = {
    ...mockReq,
    parameters: { amount: 6000, chargeId: 'ch_1' },
  };
  const resDeny = evaluatePolicyDSL(ast, exceedReq, mockCtx);
  assert(!resDeny.matched && resDeny.effect === 'DENY', 'evaluates to DENY when amount > 5000 condition fails');

  // 6. Evaluator: Workflow state condition violation -> DENY
  const unapprovedCtx: Partial<ActionContext> = { workflowState: 'INVESTIGATING' };
  const resStateDeny = evaluatePolicyDSL(ast, mockReq, unapprovedCtx);
  assert(!resStateDeny.matched && resStateDeny.effect === 'DENY', 'evaluates to DENY when workflow.state == "APPROVED" condition fails');

  // 7. Policy Test Runner (§51)
  const testCases: PolicyTestCase[] = [
    {
      testId: 'test_1',
      name: 'Legitimate refund under approval limit',
      policyId: ast.policyId,
      mockAction: mockReq,
      mockContext: mockCtx as ActionContext,
      expectedDecision: 'ALLOW',
    },
    {
      testId: 'test_2',
      name: 'High value refund triggers hold',
      policyId: ast.policyId,
      mockAction: highReq,
      mockContext: mockCtx as ActionContext,
      expectedDecision: 'HOLD',
    },
    {
      testId: 'test_3',
      name: 'Excessive refund ceiling violation denied',
      policyId: ast.policyId,
      mockAction: exceedReq,
      mockContext: mockCtx as ActionContext,
      expectedDecision: 'DENY',
    },
  ];

  const testReport = runPolicyTests(ast, testCases);
  assert(testReport.totalTests === 3 && testReport.passed === 3, 'policy test runner executes all 3 test cases with 100% pass rate (§51)');

  // 8. Policy Coverage & Regression Analyzer (§52, §53)
  const historicalActions: ActionHistoryRecord[] = [
    {
      actionId: 'hist_1',
      sessionId: 'sess_h',
      taskId: 'task_h',
      agentId: 'agent_refund',
      actionType: 'refund',
      tool: 'stripe_refund',
      resourceId: 'charge_h1',
      parameters: { amount: 500 },
      decision: 'ALLOW',
      timestamp: new Date().toISOString(),
    },
    {
      actionId: 'hist_2',
      sessionId: 'sess_h',
      taskId: 'task_h',
      agentId: 'agent_refund',
      actionType: 'unknown_tool',
      tool: 'unmanaged_tool',
      resourceId: 'res_h2',
      parameters: {},
      decision: 'DENY',
      timestamp: new Date().toISOString(),
    },
  ];

  const coverageReport = analyzePolicyCoverage([ast], historicalActions);
  assert(coverageReport.totalHistoricalActions === 2, 'analyzes historical actions total');
  assert(coverageReport.coveragePercentage === 50, 'computes 50% explicit policy coverage (1 covered, 1 unmanaged fall-through) (§53)');
  assert(coverageReport.denyRate === 50, 'correctly registers 50% default fail-closed deny rate (§54)');

  console.log(`\nResults: ${passed} passed, ${failed} failed\n`);
  if (failed > 0) {
    process.exit(1);
  }
}

runPolicyDSLTests().catch((err) => {
  console.error(err);
  process.exit(1);
});
