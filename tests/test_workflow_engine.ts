/**
 * Test Suite: Workflow State Machine & Business Invariant Engine (§41, §42, §43, §44)
 */

import { WorkflowEngine } from '../packages/workflow-engine/src/index.ts';
import type { WorkflowDefinition, ActionRequest, ActionContext } from '../packages/core-types/src/index.ts';

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

async function runWorkflowEngineTests() {
  console.log('\n=== TESTING WORKFLOW ENGINE & BUSINESS INVARIANTS (§41, §42, §43, §44) ===\n');

  const engine = new WorkflowEngine();

  // 1. Define customer support refund workflow (§42)
  const refundWorkflow: WorkflowDefinition = {
    workflowId: 'wf_customer_refund_v1',
    tenantId: 'tenant_enterprise',
    name: 'Customer Refund Resolution Workflow',
    description: 'Ticket -> Investigation -> Refund Requested -> Approved -> Executed -> Closed',
    initialState: 'TICKET_OPEN',
    terminalStates: ['CLOSED', 'REJECTED'],
    states: [
      'TICKET_OPEN',
      'INVESTIGATING',
      'REFUND_REQUESTED',
      'APPROVED',
      'REFUND_EXECUTED',
      'CLOSED',
      'REJECTED',
    ],
    transitions: [
      { fromState: 'TICKET_OPEN', toState: 'INVESTIGATING' },
      { fromState: 'INVESTIGATING', toState: 'REFUND_REQUESTED' },
      {
        fromState: 'REFUND_REQUESTED',
        toState: 'APPROVED',
        triggerEvent: 'fraud_check_passed', // Event-Aware prerequisite (§44)
        requiredApprovals: 1,
      },
      { fromState: 'REFUND_REQUESTED', toState: 'REJECTED' },
      { fromState: 'APPROVED', toState: 'REFUND_EXECUTED' },
      { fromState: 'REFUND_EXECUTED', toState: 'CLOSED' },
    ],
    actionStateRequirements: {
      stripe_refund: ['APPROVED'], // State-Aware requirement (§43)
    },
  };

  engine.registerWorkflow(refundWorkflow);
  assert(engine.getWorkflow('wf_customer_refund_v1') !== undefined, 'registers workflow definition successfully');

  // 2. Instantiate workflow instance
  const instance = engine.createInstance(
    'wf_customer_refund_v1',
    'tenant_enterprise',
    'task_support_901',
    { customerId: 'cust_882' }
  );

  assert(instance.currentState === 'TICKET_OPEN', 'new instance begins at initialState TICKET_OPEN');

  // 3. State-aware action authorization (§43)
  const mockAction: ActionRequest = {
    actionId: 'act_test_01',
    tenantId: 'tenant_enterprise',
    sessionId: 'sess_1',
    taskId: 'task_support_901',
    agentId: 'agent_refund',
    delegationId: 'del_root',
    actionType: 'refund',
    tool: 'stripe_refund',
    resource: {
      id: 'charge_991',
      type: 'charge',
      sensitivity: 'CONFIDENTIAL',
      environment: 'production',
    },
    parameters: { chargeId: 'charge_991', amount: 500, originalAmount: 1000 },
    parametersHash: 'sha256:dummy',
    timestamp: new Date().toISOString(),
  };

  // Check action while in TICKET_OPEN
  const checkEarly = engine.checkActionAllowed(mockAction, instance);
  assert(
    !checkEarly.allowed && (checkEarly.reason?.includes('requires workflow state [APPROVED]') ?? false),
    'blocks stripe_refund when workflow is in TICKET_OPEN (§43 State-Aware Authorization)'
  );

  // 4. Perform valid transitions
  engine.transition(instance.instanceId, 'INVESTIGATING', 'agent_support');
  assert(instance.currentState === 'INVESTIGATING', 'transitions from TICKET_OPEN to INVESTIGATING');

  engine.transition(instance.instanceId, 'REFUND_REQUESTED', 'agent_support');
  assert(instance.currentState === 'REFUND_REQUESTED', 'transitions from INVESTIGATING to REFUND_REQUESTED');

  // 5. Test Event-Aware transition (§44)
  // Attempting transition to APPROVED without prerequisite 'fraud_check_passed' should fail
  let transitionError = false;
  try {
    engine.transition(instance.instanceId, 'APPROVED', 'finance_manager');
  } catch (err: any) {
    transitionError = true;
    assert(
      err.message.includes("required prerequisite event 'fraud_check_passed'"),
      'blocks transition to APPROVED when prerequisite event is missing (§44 Event-Aware Transition)'
    );
  }
  assert(transitionError, 'throws error when transitioning without required event');

  // Emit prerequisite event and retry
  engine.emitEvent(instance.instanceId, 'fraud_check_passed');
  engine.transition(instance.instanceId, 'APPROVED', 'finance_manager');
  assert(instance.currentState === 'APPROVED', 'transitions to APPROVED after prerequisite event emitted');

  // 6. Check action now in APPROVED state
  const checkApproved = engine.checkActionAllowed(mockAction, instance);
  assert(checkApproved.allowed, 'allows stripe_refund once workflow reaches APPROVED state (§43)');

  // 7. Business Invariant Evaluation (§41)
  const mockContext: ActionContext = {
    task: {
      taskId: 'task_support_901',
      tenantId: 'tenant_enterprise',
      sponsorId: 'user_ciso',
      declaredPurpose: 'Customer Support',
      intendedCapabilities: ['stripe_refund'],
      expectedTools: ['stripe_refund'],
      workflowState: 'APPROVED',
      createdAt: new Date().toISOString(),
    },
    delegation: {} as any,
    sponsor: {} as any,
    agent: {} as any,
    workflowState: 'APPROVED',
    environment: 'production',
    currentTime: new Date().toISOString(),
  };

  // Valid Invariant Check
  const invResultValid = engine.evaluateInvariants(mockAction, mockContext, instance);
  assert(invResultValid.passed, 'passes all invariants when amount <= originalAmount and no duplicates');

  // Invariant Violation 1: Refund exceeds original payment (§41)
  const excessiveRefundAction: ActionRequest = {
    ...mockAction,
    parameters: { chargeId: 'charge_exceed', amount: 8000, originalAmount: 2000 },
  };
  const invResultExceed = engine.evaluateInvariants(excessiveRefundAction, mockContext, instance);
  assert(
    !invResultExceed.passed && invResultExceed.violatedInvariants[0].invariantId === 'inv_refund_not_exceed_original',
    'enforces invariant: refund ($8000) cannot exceed original payment ($2000) (§41)'
  );

  // Invariant Violation 2: Double refund prevention (§41)
  // mockAction already succeeded once for charge_991
  const doubleRefundAction: ActionRequest = {
    ...mockAction,
    parameters: { chargeId: 'charge_991', amount: 300, originalAmount: 1000 },
  };
  const invResultDouble = engine.evaluateInvariants(doubleRefundAction, mockContext, instance);
  assert(
    !invResultDouble.passed && invResultDouble.violatedInvariants[0].invariantId === 'inv_double_refund_prevention',
    'enforces invariant: double refund prevention on same charge (§41)'
  );

  // Invariant Violation 3: Production deployment requires approved PR (§41)
  const deployAction: ActionRequest = {
    ...mockAction,
    tool: 'deploy_production',
    resource: {
      id: 'k8s_prod_cluster',
      type: 'infrastructure',
      sensitivity: 'CRITICAL',
      environment: 'production',
    },
    parameters: { cluster: 'us-east-1-prod' },
  };
  const invResultDeploy = engine.evaluateInvariants(deployAction, mockContext, instance);
  assert(
    !invResultDeploy.passed && invResultDeploy.violatedInvariants[0].invariantId === 'inv_prod_deploy_requires_pr',
    'enforces invariant: production deploy requires approved PR (§41)'
  );

  // Invariant Violation 4: Sensitive customer data export restriction (§41)
  const exportAction: ActionRequest = {
    ...mockAction,
    tool: 'customer_bulk_export',
    resource: {
      id: 'customer_db_full',
      type: 'database',
      sensitivity: 'CONFIDENTIAL',
      environment: 'production',
    },
    parameters: { format: 'csv', records: 100000 },
  };
  const invResultExport = engine.evaluateInvariants(exportAction, mockContext, instance);
  assert(
    !invResultExport.passed && invResultExport.violatedInvariants[0].invariantId === 'inv_sensitive_export_restriction',
    'enforces invariant: sensitive data export requires explicit compliance sign-off (§41)'
  );

  console.log(`\nResults: ${passed} passed, ${failed} failed\n`);
  if (failed > 0) {
    process.exit(1);
  }
}

runWorkflowEngineTests().catch((err) => {
  console.error(err);
  process.exit(1);
});
