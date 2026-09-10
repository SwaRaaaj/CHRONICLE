/**
 * Chronicle Adversarial Attack Suite
 * Simulates 7 sophisticated real-world AI agent attack vectors and validates
 * Chronicle's multi-layered defense-in-depth security guarantees.
 */

import assert from 'node:assert';
import { ChronicleControlPlane } from '../../apps/control-plane/src/index.ts';
import { MockEnterpriseToolsService } from '../../apps/mock-enterprise-tools/src/index.ts';
import { canonicalHash } from '@chronicle/crypto-primitives';
import type { ActionRequest } from '@chronicle/core-types';

let totalAttacks = 0;
let blockedAttacks = 0;

async function runScenario(
  number: number,
  title: string,
  scenarioFn: () => Promise<{ blocked: boolean; defenseMechanism: string; evidence: string }>
) {
  totalAttacks++;
  console.log(`\n\x1b[1m\x1b[33m[ATTACK VECTOR ${number}] ${title}\x1b[0m`);
  try {
    const result = await scenarioFn();
    if (result.blocked) {
      blockedAttacks++;
      console.log(`  \x1b[32m✔ DEFENSE SUCCESSFUL: Attack neutralised\x1b[0m`);
      console.log(`  \x1b[36m  Mechanism:\x1b[0m ${result.defenseMechanism}`);
      console.log(`  \x1b[90m  Evidence:  ${result.evidence}\x1b[0m`);
    } else {
      console.log(`  \x1b[31m✖ CRITICAL FAILURE: Attack succeeded\x1b[0m`);
    }
  } catch (err: unknown) {
    console.error(`  \x1b[31m✖ ERROR IN SCENARIO:\x1b[0m ${(err as Error).message}`);
    throw err;
  }
}

async function runAttackSuite() {
  console.log('\n\x1b[1m\x1b[35m================================================================');
  console.log('       CHRONICLE ADVERSARIAL ATTACK SIMULATION SUITE');
  console.log('================================================================\x1b[0m');

  const cp = new ChronicleControlPlane();
  const toolsService = new MockEnterpriseToolsService(cp.keyPair.publicKey);

  // -------------------------------------------------------------
  // ATTACK 1: Parameter Tampering / TOCTOU Attack
  // -------------------------------------------------------------
  await runScenario(
    1,
    'Parameter Tampering / TOCTOU (Time-of-Check to Time-of-Use)',
    async () => {
      // 1. Agent asks Chronicle for a legitimate $50 refund
      const legitimateParams = { chargeId: 'ch_44192', amount: 50 };
      const req: ActionRequest = {
        actionId: 'act_toctou_probe',
        tenantId: 'tenant_acme',
        sessionId: 'sess_toctou',
        taskId: 'task_customer_refunds',
        agentId: 'agent_finance_refund',
        delegationId: 'del_finance_refund_root',
        actionType: 'stripe_refund',
        tool: 'stripe_refund',
        resource: { id: 'ch_44192', type: 'charge', sensitivity: 'HIGH', environment: 'production' },
        parameters: legitimateParams,
        parametersHash: canonicalHash(legitimateParams),
        timestamp: new Date().toISOString()
      };

      const decision = await cp.authorizeAction(req);
      assert.strictEqual(decision.decision, 'ALLOW');
      assert(decision.grant, 'Grant must be issued for legitimate request');

      // 2. Compromised agent modifies the payload to $50,000 before sending to enterprise tools
      const tamperedParams = { chargeId: 'ch_44192', amount: 50000 };
      const execResult = toolsService.execute('stripe_refund', tamperedParams, decision.grant);

      assert.strictEqual(execResult.success, false);
      assert.strictEqual(execResult.code, 'PARAMETERS_TAMPERED: hash mismatch');

      return {
        blocked: true,
        defenseMechanism: 'Canonical Parameter Hash Cryptographic Binding',
        evidence: `Enterprise tool rejected execution: ${execResult.error}`
      };
    }
  );

  // -------------------------------------------------------------
  // ATTACK 2: Expired Grant Replay Attack
  // -------------------------------------------------------------
  await runScenario(
    2,
    'Expired Authorization Grant Replay Attack',
    async () => {
      // Create a grant that expired 10 seconds ago
      const now = Math.floor(Date.now() / 1000);
      const params = { chargeId: 'ch_expired', amount: 100 };
      const expiredGrant = {
        grantId: 'grant_expired_1',
        actionId: 'act_expired_1',
        tenantId: 'tenant_acme',
        agentId: 'agent_finance_refund',
        actionType: 'stripe_refund',
        tool: 'stripe_refund',
        resourceId: 'ch_expired',
        parametersHash: canonicalHash(params),
        delegationId: 'del_finance_refund_root',
        nonce: 'nonce123',
        notBefore: now - 100,
        expiresAt: now - 10, // Expired!
        signature: 'dummy_sig'
      };

      const execResult = toolsService.execute('stripe_refund', params, expiredGrant);
      assert.strictEqual(execResult.success, false);
      assert.strictEqual(execResult.code, 'GRANT_EXPIRED');

      return {
        blocked: true,
        defenseMechanism: 'Ephemeral Grant TTL Enforcement',
        evidence: `Tool rejected replayed grant: ${execResult.error}`
      };
    }
  );

  // -------------------------------------------------------------
  // ATTACK 3: Prompt Injection / Declared Intent Drift Attack
  // -------------------------------------------------------------
  await runScenario(
    3,
    'Prompt Injection & Declared Intent Drift Attack',
    async () => {
      // Task intent: Support agent only expected to do search_customers & read_customer_pii
      // Adversarial prompt instructs agent to call send_wire_transfer
      const injectedAction: ActionRequest = {
        actionId: 'act_drift_attempt',
        tenantId: 'tenant_acme',
        sessionId: 'sess_drift',
        taskId: 'task_support_inquiries',
        agentId: 'agent_support_general',
        delegationId: 'del_support_general_root',
        actionType: 'send_wire_transfer',
        tool: 'send_wire_transfer',
        resource: { id: 'wire_attacker', type: 'wire', sensitivity: 'CRITICAL', environment: 'production' },
        parameters: { destinationAccount: 'ACME_EVIL_OFFSHORE', amount: 10000 },
        parametersHash: canonicalHash({ destinationAccount: 'ACME_EVIL_OFFSHORE', amount: 10000 }),
        timestamp: new Date().toISOString()
      };

      const decision = await cp.authorizeAction(injectedAction);
      assert.strictEqual(decision.decision, 'DENY');
      assert.strictEqual(decision.reasonCodes[0], 'POLICY_DENY');

      return {
        blocked: true,
        defenseMechanism: 'Delegation Scope & Intent Drift Enforcement',
        evidence: `Control plane rejected action: ${decision.explanation}`
      };
    }
  );

  // -------------------------------------------------------------
  // ATTACK 4: Forbidden Cross-Tool Sequence Exfiltration
  // -------------------------------------------------------------
  await runScenario(
    4,
    'Forbidden Cross-Tool Sequence Exfiltration (PII Read -> Email Broadcast)',
    async () => {
      const sessId = 'sess_exfil_attack';

      // Step 1: Agent accesses confidential customer PII (allowed under delegation)
      const readPiiReq: ActionRequest = {
        actionId: 'act_pii_read',
        tenantId: 'tenant_acme',
        sessionId: sessId,
        taskId: 'task_support_inquiries',
        agentId: 'agent_support_general',
        delegationId: 'del_support_general_root',
        actionType: 'read_customer_pii',
        tool: 'read_customer_pii',
        resource: { id: 'cust_7721', type: 'customer', sensitivity: 'CONFIDENTIAL', environment: 'production' },
        parameters: { customerId: 'cust_7721' },
        parametersHash: canonicalHash({ customerId: 'cust_7721' }),
        timestamp: new Date().toISOString()
      };
      const readDecision = await cp.authorizeAction(readPiiReq);
      assert.strictEqual(readDecision.decision, 'ALLOW');

      // Step 2: Agent attempts to transmit exfiltrated data via external communication
      const exfilReq: ActionRequest = {
        actionId: 'act_exfil_send',
        tenantId: 'tenant_acme',
        sessionId: sessId,
        taskId: 'task_support_inquiries',
        agentId: 'agent_support_general',
        delegationId: 'del_support_general_root',
        actionType: 'send_external_email',
        tool: 'send_external_email',
        resource: { id: 'msg_exfil', type: 'email', sensitivity: 'SENSITIVE', environment: 'production' },
        parameters: { to: 'hacker@darknet.org', body: 'PII leak' },
        parametersHash: canonicalHash({ to: 'hacker@darknet.org', body: 'PII leak' }),
        timestamp: new Date().toISOString()
      };

      const exfilDecision = await cp.authorizeAction(exfilReq);
      assert.strictEqual(exfilDecision.decision, 'DENY');
      assert(
        exfilDecision.reasonCodes.includes('FORBIDDEN_SEQUENCE') ||
        exfilDecision.reasonCodes.includes('POLICY_DENY')
      );

      return {
        blocked: true,
        defenseMechanism: 'Stateful Action Sequence & Behavioral Invariant Monitoring',
        evidence: `Control plane intercepted exfiltration: ${exfilDecision.explanation}`
      };
    }
  );

  // -------------------------------------------------------------
  // ATTACK 5: Monotonic Privilege Narrowing Expansion Violation
  // -------------------------------------------------------------
  await runScenario(
    5,
    'Monotonic Privilege Narrowing Expansion Attempt (Sub-agent Escalation)',
    async () => {
      let threw = false;
      let errorMsg = '';

      try {
        // Finance agent tries to create a child delegation giving sub-agent critical wire transfer tool
        cp.delegationManager.createDelegation(
          {
            delegationId: 'del_illegal_expansion',
            tenantId: 'tenant_acme',
            parentDelegationId: 'del_finance_refund_root',
            delegatorType: 'AGENT',
            delegatorId: 'agent_finance_refund',
            delegateeId: 'agent_support_general',
            taskId: 'task_sub_escalation',
            purpose: 'Privilege expansion',
            constraints: {
              allowedTools: ['send_wire_transfer'], // Parent does NOT have send_wire_transfer!
              resourcePatterns: ['*']
            },
            notBefore: new Date().toISOString(),
            expiresAt: new Date(Date.now() + 10000).toISOString()
          },
          'invalid_key' // will fail before signing
        );
      } catch (err: unknown) {
        threw = true;
        errorMsg = (err as Error).message;
      }

      assert.strictEqual(threw, true);
      assert(errorMsg.includes('Monotonic narrowing violation'));

      return {
        blocked: true,
        defenseMechanism: 'Mathematical Monotonic Privilege Invariant Verification',
        evidence: `Delegation Engine rejected expansion: ${errorMsg}`
      };
    }
  );

  // -------------------------------------------------------------
  // ATTACK 6: Smurfing / Cumulative Limit Evasion Attack
  // -------------------------------------------------------------
  await runScenario(
    6,
    'Smurfing / Structuring Attack to Evade Approval Thresholds',
    async () => {
      const sessId = 'sess_smurf_attack';
      // del_finance_refund_root has cumulativeValueLimit: 10,000 and auto-allow threshold: 1,000
      // 11 distinct transactions of $900 = $9,900 <= $10,000 (all ALLOW)
      for (let i = 0; i < 11; i++) {
        const req: ActionRequest = {
          actionId: `act_smurf_${i}`,
          tenantId: 'tenant_acme',
          sessionId: sessId,
          taskId: 'task_customer_refunds',
          agentId: 'agent_finance_refund',
          delegationId: 'del_finance_refund_root',
          actionType: 'stripe_refund',
          tool: 'stripe_refund',
          resource: { id: `ch_${i}`, type: 'charge', sensitivity: 'HIGH', environment: 'production' },
          parameters: { chargeId: `ch_${i}`, amount: 900 },
          parametersHash: canonicalHash({ chargeId: `ch_${i}`, amount: 900 }),
          timestamp: new Date().toISOString()
        };
        const d = await cp.authorizeAction(req);
        assert.strictEqual(d.decision, 'ALLOW');
      }

      // 12th transaction: $9,900 + $900 = $10,800 > $10,000 cumulative limit -> DENY!
      const reqOverLimit: ActionRequest = {
        actionId: 'act_smurf_over',
        tenantId: 'tenant_acme',
        sessionId: sessId,
        taskId: 'task_customer_refunds',
        agentId: 'agent_finance_refund',
        delegationId: 'del_finance_refund_root',
        actionType: 'stripe_refund',
        tool: 'stripe_refund',
        resource: { id: 'ch_over', type: 'charge', sensitivity: 'HIGH', environment: 'production' },
        parameters: { chargeId: 'ch_over', amount: 900 },
        parametersHash: canonicalHash({ chargeId: 'ch_over', amount: 900 }),
        timestamp: new Date().toISOString()
      };

      const dOver = await cp.authorizeAction(reqOverLimit);
      assert.strictEqual(dOver.decision, 'DENY');
      assert(dOver.reasonCodes.includes('CUMULATIVE_LIMIT_EXCEEDED'));

      return {
        blocked: true,
        defenseMechanism: 'Rolling Window Cumulative Limit & Structuring Defense',
        evidence: `Smurfing blocked on 12th transaction: ${dOver.explanation}`
      };
    }
  );

  // -------------------------------------------------------------
  // ATTACK 7: Compromised Agent Immediate Quarantine & Lockdown
  // -------------------------------------------------------------
  await runScenario(
    7,
    'Compromised Agent Lockdown via Emergency Kill Switch',
    async () => {
      // 1. CISO or automated security monitor triggers quarantine on finance agent
      cp.policyEngine.quarantineAgent('agent_finance_refund');

      // 2. Rogue agent attempts any standard action
      const req: ActionRequest = {
        actionId: 'act_rogue_attempt',
        tenantId: 'tenant_acme',
        sessionId: 'sess_rogue',
        taskId: 'task_customer_refunds',
        agentId: 'agent_finance_refund',
        delegationId: 'del_finance_refund_root',
        actionType: 'stripe_refund',
        tool: 'stripe_refund',
        resource: { id: 'ch_rogue', type: 'charge', sensitivity: 'HIGH', environment: 'production' },
        parameters: { chargeId: 'ch_rogue', amount: 50 },
        parametersHash: canonicalHash({ chargeId: 'ch_rogue', amount: 50 }),
        timestamp: new Date().toISOString()
      };

      const decision = await cp.authorizeAction(req);
      assert.strictEqual(decision.decision, 'DENY');
      assert.strictEqual(decision.reasonCodes[0], 'AGENT_QUARANTINED');

      return {
        blocked: true,
        defenseMechanism: 'Zero-Latency Blast Radius Quarantine & Kill Switch',
        evidence: `Quarantined agent severed immediately: ${decision.explanation}`
      };
    }
  );

  console.log('\n\x1b[1m\x1b[32m================================================================');
  console.log(` ALL ${blockedAttacks}/${totalAttacks} ADVERSARIAL ATTACKS NEUTRALIZED BY CHRONICLE AACT!`);
  console.log('================================================================\x1b[0m\n');
}

runAttackSuite().catch(err => {
  console.error('\nAttack suite failed:', err);
  process.exit(1);
});
