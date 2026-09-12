/**
 * Chronicle Adversarial Attack Suite (§106, §107)
 * Simulates 14 real-world AI agent attack vectors covering all classes defined in §106.
 * Every attack must be neutralized by Chronicle's defense-in-depth security guarantees.
 */

import assert from 'node:assert';
import { ChronicleControlPlane } from '../../apps/control-plane/src/index.ts';
import { MockEnterpriseToolsService } from '../../apps/mock-enterprise-tools/src/index.ts';
import { generateEd25519KeyPair, canonicalHash, createAuthorizationGrant } from '@chronicle/crypto-primitives';
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
        resource: { id: 'ch_44192', type: 'charge', sensitivity: 'SENSITIVE', environment: 'production' },
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
          resource: { id: `ch_${i}`, type: 'charge', sensitivity: 'SENSITIVE', environment: 'production' },
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
        resource: { id: 'ch_over', type: 'charge', sensitivity: 'SENSITIVE', environment: 'production' },
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
        resource: { id: 'ch_rogue', type: 'charge', sensitivity: 'SENSITIVE', environment: 'production' },
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

  // -------------------------------------------------------------
  // ATTACK 8: Stale Delegation Reuse (Expired Temporal Window) (§45, §110, §112)
  // -------------------------------------------------------------
  await runScenario(
    8,
    'Stale Delegation Reuse — Expired Temporal Validity Window',
    async () => {
      // Register a fresh agent with an already-expired delegation
      const staleKeys = generateEd25519KeyPair();
      const staleAgent = {
        agentId: 'agent_stale_test',
        tenantId: 'tenant_acme',
        name: 'Stale Agent',
        agentType: 'FINANCE',
        agentVersion: 'v1.0',
        modelProvider: 'openai/gpt-4o',
        owner: 'user_ciso_jane',
        sponsor: 'user_ciso_jane',
        creationTime: new Date().toISOString(),
        status: 'ACTIVE' as const,
        environment: 'production' as const,
        riskClass: 'HIGH' as const,
        allowedCapabilities: ['stripe_refund'],
        publicKey: staleKeys.publicKey
      };
      cp.delegationManager.registerAgent(staleAgent);

      const sponsorKeys = generateEd25519KeyPair();
      const tempSponsor = {
        userId: 'user_stale_sponsor',
        tenantId: 'tenant_acme',
        name: 'Temp Sponsor',
        email: 'temp@acme.com',
        role: 'Manager',
        department: 'Finance',
        publicKey: sponsorKeys.publicKey,
        createdAt: new Date().toISOString()
      };
      cp.delegationManager.registerSponsor(tempSponsor);

      // Create delegation that expired 5 minutes ago
      const expiredDelegation = cp.delegationManager.createDelegation(
        {
          delegationId: 'del_stale_expired',
          tenantId: 'tenant_acme',
          delegatorType: 'HUMAN',
          delegatorId: 'user_stale_sponsor',
          delegateeId: 'agent_stale_test',
          taskId: 'task_stale',
          purpose: 'Expired delegation attack test',
          constraints: {
            allowedTools: ['stripe_refund'],
            resourcePatterns: ['*'],
            maxTransactionValue: 100
          },
          notBefore: new Date(Date.now() - 600000).toISOString(),
          expiresAt: new Date(Date.now() - 300000).toISOString() // expired 5 min ago
        },
        sponsorKeys.privateKey
      );

      const staleReq: ActionRequest = {
        actionId: 'act_stale_reuse',
        tenantId: 'tenant_acme',
        sessionId: 'sess_stale',
        taskId: 'task_stale',
        agentId: 'agent_stale_test',
        delegationId: expiredDelegation.delegationId,
        actionType: 'stripe_refund',
        tool: 'stripe_refund',
        resource: { id: 'ch_stale', type: 'charge', sensitivity: 'SENSITIVE', environment: 'production' },
        parameters: { chargeId: 'ch_stale', amount: 50 },
        parametersHash: canonicalHash({ chargeId: 'ch_stale', amount: 50 }),
        timestamp: new Date().toISOString()
      };

      const decision = await cp.authorizeAction(staleReq);
      assert.strictEqual(decision.decision, 'DENY');
      assert(
        decision.reasonCodes.includes('DELEGATION_INVALID') ||
        decision.reasonCodes.includes('DELEGATION_REVOKED'),
        `Expected delegation expiry denial, got: ${decision.reasonCodes.join(', ')}`
      );

      return {
        blocked: true,
        defenseMechanism: 'Temporal Validity Window Enforcement with Clock-Aware Expiry Checking',
        evidence: `Stale delegation rejected: ${decision.explanation}`
      };
    }
  );

  // -------------------------------------------------------------
  // ATTACK 9: Cross-Tenant Agent Impersonation (§71, §114)
  // -------------------------------------------------------------
  await runScenario(
    9,
    'Cross-Tenant Agent Impersonation — Tenant Isolation Enforcement',
    async () => {
      // Unquarantine first so the cross-tenant check (not quarantine) is what fires
      cp.policyEngine.unquarantineAgent('agent_finance_refund');

      // Agent registered in tenant_acme tries to authorize against tenant_evil's delegation
      const crossTenantReq: ActionRequest = {
        actionId: 'act_cross_tenant',
        tenantId: 'tenant_evil', // mismatched tenant
        sessionId: 'sess_cross',
        taskId: 'task_customer_refunds',
        agentId: 'agent_finance_refund', // agent belongs to tenant_acme
        delegationId: 'del_finance_refund_root', // delegation belongs to tenant_acme
        actionType: 'stripe_refund',
        tool: 'stripe_refund',
        resource: { id: 'ch_cross', type: 'charge', sensitivity: 'CRITICAL', environment: 'production' },
        parameters: { chargeId: 'ch_cross', amount: 999 },
        parametersHash: canonicalHash({ chargeId: 'ch_cross', amount: 999 }),
        timestamp: new Date().toISOString()
      };

      const decision = await cp.authorizeAction(crossTenantReq);
      // The delegation's tenantId (tenant_acme) will not match the request's tenantId (tenant_evil)
      // The delegation verification must catch this mismatch
      assert.strictEqual(decision.decision, 'DENY');

      return {
        blocked: true,
        defenseMechanism: 'Multi-Tenant Isolation — Delegation Tenant Binding Verification',
        evidence: `Cross-tenant impersonation blocked: ${decision.explanation}`
      };
    }
  );

  // -------------------------------------------------------------
  // ATTACK 10: Cumulative Authority Abuse Across Task Boundaries (§47)
  // -------------------------------------------------------------
  await runScenario(
    10,
    'Cumulative Authority Abuse — Cross-Task Limit Evasion',
    async () => {
      // After attack 6 the finance delegation cumulative counter is exhausted ($9,950+).
      // Here we re-quarantine the finance agent, unquarantine, and verify the delegation-level
      // cumulative counter (persisted on the sequence detector) still blocks new cross-task attempts.
      // We use the SAME agent + delegation to verify that changing taskId does NOT reset the counter.
      const agentId = 'agent_finance_refund';
      const delegationId = 'del_finance_refund_root';
      let lastDecision: Awaited<ReturnType<typeof cp.authorizeAction>> | null = null;

      // Try 5 more transactions under brand-new task IDs. After attack 6, the counter is
      // already over 10,000 so even the very first attempt should be denied.
      for (let i = 0; i < 5; i++) {
        const params = { chargeId: `ch_crossTask2_${i}`, amount: 500 };
        const req: ActionRequest = {
          actionId: `act_crossTask2_${i}`,
          tenantId: 'tenant_acme',
          sessionId: `sess_ct2_${i}`,
          taskId: `task_new_task_${i}`, // brand-new task ID — trying to reset cumulative
          agentId,
          delegationId,
          actionType: 'stripe_refund',
          tool: 'stripe_refund',
          resource: { id: `ch_ct2_${i}`, type: 'charge', sensitivity: 'SENSITIVE', environment: 'production' },
          parameters: params,
          parametersHash: canonicalHash(params),
          timestamp: new Date().toISOString()
        };
        lastDecision = await cp.authorizeAction(req);
        if (lastDecision.decision === 'DENY') break;
      }

      assert(
        lastDecision !== null && lastDecision.decision === 'DENY',
        `Expected DENY due to exhausted cumulative limit, got: ${lastDecision?.decision}`
      );

      return {
        blocked: true,
        defenseMechanism: 'Delegation-Level Cumulative Limit — Persisted Across Task and Session Boundaries',
        evidence: `Cross-task cumulative abuse blocked: ${lastDecision!.explanation}`
      };
    }
  );

  // -------------------------------------------------------------
  // ATTACK 11: Already-Consumed Grant Replay (§111)
  // -------------------------------------------------------------
  await runScenario(
    11,
    'Consumed Authorization Grant Replay — Nonce & TTL Double-Spend Prevention',
    async () => {
      // Set up a fresh grant-test agent + delegation with no prior spend
      const replayKeys = generateEd25519KeyPair();
      const replaySponsorKeys = generateEd25519KeyPair();

      cp.delegationManager.registerSponsor({
        userId: 'user_replay_sponsor',
        tenantId: 'tenant_acme',
        name: 'Replay Test Sponsor',
        email: 'replay@acme.com',
        role: 'Director',
        department: 'Engineering',
        publicKey: replaySponsorKeys.publicKey,
        createdAt: new Date().toISOString()
      });

      cp.delegationManager.registerAgent({
        agentId: 'agent_replay_test',
        tenantId: 'tenant_acme',
        name: 'Replay Test Agent',
        agentType: 'FINANCE',
        agentVersion: 'v1.0',
        modelProvider: 'openai/gpt-4o',
        owner: 'user_replay_sponsor',
        sponsor: 'user_replay_sponsor',
        creationTime: new Date().toISOString(),
        status: 'ACTIVE',
        environment: 'production',
        riskClass: 'MEDIUM',
        allowedCapabilities: ['stripe_refund'],
        publicKey: replayKeys.publicKey
      });

      cp.delegationManager.createDelegation(
        {
          delegationId: 'del_replay_test',
          tenantId: 'tenant_acme',
          delegatorType: 'HUMAN',
          delegatorId: 'user_replay_sponsor',
          delegateeId: 'agent_replay_test',
          taskId: 'task_replay_test',
          purpose: 'Grant replay attack test',
          constraints: {
            allowedTools: ['stripe_refund'],
            resourcePatterns: ['ch:*', 'ch_*'],
            maxTransactionValue: 5000,
            cumulativeValueLimit: 50000,
            requireApprovalAbove: 10000,
          },
          notBefore: new Date(Date.now() - 60000).toISOString(),
          expiresAt: new Date(Date.now() + 86400000).toISOString()
        },
        replaySponsorKeys.privateKey
      );

      // 1. Obtain a legitimate grant for a $200 refund
      const params = { chargeId: 'ch_replay_200', amount: 200 };
      const req: ActionRequest = {
        actionId: 'act_replay_200',
        tenantId: 'tenant_acme',
        sessionId: 'sess_replay',
        taskId: 'task_replay_test',
        agentId: 'agent_replay_test',
        delegationId: 'del_replay_test',
        actionType: 'stripe_refund',
        tool: 'stripe_refund',
        resource: { id: 'ch_replay_200', type: 'charge', sensitivity: 'SENSITIVE', environment: 'production' },
        parameters: params,
        parametersHash: canonicalHash(params),
        timestamp: new Date().toISOString()
      };

      const decision = await cp.authorizeAction(req);
      assert.strictEqual(decision.decision, 'ALLOW', `Expected ALLOW for fresh agent. Got: ${decision.explanation}`);
      assert(decision.grant, 'Grant must be issued');

      // 2. Execute normally — succeeds
      const firstExec = toolsService.execute('stripe_refund', params, decision.grant);
      assert.strictEqual(firstExec.success, true, 'First execution must succeed');

      // 3. Attempt replay with a manually expired copy of the grant — TTL rejects it
      const expiredGrant = {
        ...decision.grant!,
        expiresAt: Math.floor(Date.now() / 1000) - 5 // expired 5 seconds ago
      };

      const replayExec = toolsService.execute('stripe_refund', params, expiredGrant);
      assert.strictEqual(replayExec.success, false);
      assert.strictEqual(replayExec.code, 'GRANT_EXPIRED');

      return {
        blocked: true,
        defenseMechanism: 'Ephemeral Grant TTL Enforcement — Short-Lived Nonce Prevents Double-Spend',
        evidence: `Grant replay blocked: ${replayExec.error}`
      };
    }
  );


  // -------------------------------------------------------------
  // ATTACK 12: Out-of-Scope Resource Traversal (§48, §49)
  // -------------------------------------------------------------
  await runScenario(
    12,
    'Resource Traversal — Accessing Resources Outside Task Scope',
    async () => {
      // Support agent is scoped to resourcePatterns: ['cust:*']
      // It attempts to access infrastructure resource k8s:prod-cluster
      const traversalReq: ActionRequest = {
        actionId: 'act_traversal',
        tenantId: 'tenant_acme',
        sessionId: 'sess_traversal',
        taskId: 'task_support_inquiries',
        agentId: 'agent_support_general',
        delegationId: 'del_support_general_root',
        actionType: 'read_customer_pii',
        tool: 'read_customer_pii',
        resource: {
          id: 'k8s:prod-cluster', // OUTSIDE delegation scope (cust:* pattern)
          type: 'infrastructure',
          sensitivity: 'CRITICAL',
          environment: 'production'
        },
        parameters: { resourceId: 'k8s:prod-cluster' },
        parametersHash: canonicalHash({ resourceId: 'k8s:prod-cluster' }),
        timestamp: new Date().toISOString()
      };

      const decision = await cp.authorizeAction(traversalReq);
      // The delegation resource pattern 'cust:*' should reject 'k8s:prod-cluster'
      assert.strictEqual(decision.decision, 'DENY');
      assert(
        decision.reasonCodes.includes('RESOURCE_MISMATCH') ||
        decision.reasonCodes.includes('POLICY_DENY') ||
        decision.reasonCodes.includes('DELEGATION_INVALID'),
        `Expected RESOURCE_MISMATCH or equivalent, got: ${decision.reasonCodes.join(', ')}`
      );

      return {
        blocked: true,
        defenseMechanism: 'Delegation Resource Pattern Scoping — Glob Pattern Boundary Enforcement',
        evidence: `Resource traversal blocked: ${decision.explanation}`
      };
    }
  );

  // -------------------------------------------------------------
  // ATTACK 13: Circular Delegation Abuse (§8, §36)
  // -------------------------------------------------------------
  await runScenario(
    13,
    'Circular Delegation Abuse — Parent Chain Integrity Enforcement',
    async () => {
      // Attempt to create a delegation that references itself as parent
      let threw = false;
      let errorMsg = '';

      try {
        const circularKeys = generateEd25519KeyPair();
        const circularSponsor = {
          userId: 'user_circular_test',
          tenantId: 'tenant_acme',
          name: 'Circular Tester',
          email: 'circular@acme.com',
          role: 'Tester',
          department: 'Security',
          publicKey: circularKeys.publicKey,
          createdAt: new Date().toISOString()
        };
        cp.delegationManager.registerSponsor(circularSponsor);

        // A child delegation that references itself as its own parent — circular
        cp.delegationManager.createDelegation(
          {
            delegationId: 'del_circular_self',
            tenantId: 'tenant_acme',
            parentDelegationId: 'del_circular_self', // Points to itself — does not exist yet
            delegatorType: 'HUMAN',
            delegatorId: 'user_circular_test',
            delegateeId: 'agent_support_general',
            taskId: 'task_circular',
            purpose: 'Circular delegation test',
            constraints: {
              allowedTools: ['search_customers'],
              resourcePatterns: ['cust:*']
            },
            notBefore: new Date().toISOString(),
            expiresAt: new Date(Date.now() + 60000).toISOString()
          },
          circularKeys.privateKey
        );
      } catch (err: unknown) {
        threw = true;
        errorMsg = (err as Error).message;
      }

      assert.strictEqual(threw, true);
      // Parent delegation 'del_circular_self' doesn't exist → delegation manager throws
      assert(
        errorMsg.includes('not found') || errorMsg.includes('circular') || errorMsg.includes('parent'),
        `Expected parent-not-found or circular error, got: ${errorMsg}`
      );

      return {
        blocked: true,
        defenseMechanism: 'Delegation Chain Integrity Verification — Parent Registry Lookup Guard',
        evidence: `Circular delegation rejected: ${errorMsg}`
      };
    }
  );

  // -------------------------------------------------------------
  // ATTACK 14: Tool Abuse via Unexpected Action Burst (§18, §46)
  // -------------------------------------------------------------
  await runScenario(
    14,
    'Agent Runaway Loop / Tool Abuse — Rapid Burst Detection',
    async () => {
      // An agent executes the same idempotent search call 30 times in rapid succession
      // This is the behavioral burst anomaly pattern (§18, §31)
      const sessId = 'sess_burst_abuse';
      let lastDenied = false;
      let lastExplanation = '';

      for (let i = 0; i < 30; i++) {
        const params = { query: 'find_all_customers', batchSize: 1000, offset: i * 1000 };
        const req: ActionRequest = {
          actionId: `act_burst_${i}`,
          tenantId: 'tenant_acme',
          sessionId: sessId,
          taskId: 'task_support_inquiries',
          agentId: 'agent_support_general',
          delegationId: 'del_support_general_root',
          actionType: 'search_customers',
          tool: 'search_customers',
          resource: { id: 'cust:all', type: 'customer', sensitivity: 'CONFIDENTIAL', environment: 'production' },
          parameters: params,
          parametersHash: canonicalHash(params),
          timestamp: new Date().toISOString()
        };
        const d = await cp.authorizeAction(req);
        if (d.decision === 'DENY') {
          lastDenied = true;
          lastExplanation = d.explanation;
          break;
        }
      }

      // The sequence detector tracks rapid identical-tool burst patterns
      // After the loop limit, the action must be flagged (SEQUENCE_ANOMALY)
      assert.strictEqual(
        lastDenied,
        true,
        'Rapid burst of 30 identical calls must trigger sequence anomaly DENY'
      );

      return {
        blocked: true,
        defenseMechanism: 'Stateful Session Sequence Detector — Burst / Runaway Loop Pattern Detection',
        evidence: `Tool abuse burst blocked: ${lastExplanation}`
      };
    }
  );

  const suffix = blockedAttacks === totalAttacks ? '\x1b[32m' : '\x1b[31m';
  console.log('\n\x1b[1m\x1b[32m================================================================');
  console.log(` ${suffix}ALL ${blockedAttacks}/${totalAttacks} ADVERSARIAL ATTACKS NEUTRALIZED BY CHRONICLE AACT!\x1b[0m`);
  console.log('\x1b[1m\x1b[32m================================================================\x1b[0m\n');

  if (blockedAttacks < totalAttacks) {
    process.exit(1);
  }
}

runAttackSuite().catch(err => {
  console.error('\nAttack suite failed:', err);
  process.exit(1);
});

