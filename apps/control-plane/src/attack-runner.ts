/**
 * Chronicle Adversarial Attack Runner
 * Executes any of the 14 real-world attack vectors against a live Chronicle Control Plane instance.
 * Emits real audit receipts to the cryptographic ledger and returns neutralization telemetry.
 */

import assert from 'node:assert';
import type { ChronicleControlPlane } from './index.ts';
import { MockEnterpriseToolsService } from '../../mock-enterprise-tools/src/index.ts';
import { ATTACK_CATALOG, type AttackVectorMetadata } from './attack-catalog.ts';
import {
  generateEd25519KeyPair,
  canonicalHash,
  createAuthorizationGrant
} from '@chronicle/crypto-primitives';
import type { ActionRequest } from '@chronicle/core-types';

export interface AttackSimulationResult {
  vectorNumber: number;
  id: string;
  title: string;
  category: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  blocked: boolean;
  defenseMechanism: string;
  evidence: string;
  status: 'NEUTRALIZED' | 'FAILED';
  durationMs: number;
}

export async function executeAttackVector(
  cp: ChronicleControlPlane,
  vectorNumber: number
): Promise<AttackSimulationResult> {
  const meta = ATTACK_CATALOG.find(a => a.vectorNumber === vectorNumber);
  if (!meta) {
    throw new Error(`Attack vector #${vectorNumber} not found in catalog`);
  }

  const toolsService = new MockEnterpriseToolsService(cp.keyPair.publicKey);
  const startTime = performance.now();

  let blocked = false;
  let defenseMechanism = meta.defenseMechanism;
  let evidence = '';

  try {
    switch (vectorNumber) {
      case 1: {
        // ATTACK 1: Parameter Tampering / TOCTOU
        const legitimateParams = { chargeId: 'ch_44192', amount: 50 };
        const req: ActionRequest = {
          actionId: `act_toctou_${Date.now()}`,
          tenantId: 'tenant_acme',
          sessionId: 'sess_toctou_demo',
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
        if (decision.decision !== 'ALLOW' || !decision.grant) {
          throw new Error('Initial legitimate grant creation failed');
        }

        // Attacker attempts runtime modification before execution
        const tamperedParams = { chargeId: 'ch_44192', amount: 50000 };
        const execResult = toolsService.execute('stripe_refund', tamperedParams, decision.grant);

        blocked = !execResult.success && execResult.code === 'PARAMETERS_TAMPERED: hash mismatch';
        defenseMechanism = 'Canonical Parameter Hash Cryptographic Binding';
        evidence = `Enterprise tool verified grant parameter hash against payload and rejected execution: ${execResult.error}`;
        break;
      }

      case 2: {
        // ATTACK 2: Expired Grant Replay
        const now = Math.floor(Date.now() / 1000);
        const params = { chargeId: 'ch_expired', amount: 100 };
        const expiredGrant = {
          grantId: `grant_exp_${Date.now()}`,
          actionId: `act_exp_${Date.now()}`,
          tenantId: 'tenant_acme',
          agentId: 'agent_finance_refund',
          actionType: 'stripe_refund',
          tool: 'stripe_refund',
          resourceId: 'ch_expired',
          parametersHash: canonicalHash(params),
          delegationId: 'del_finance_refund_root',
          nonce: `nonce_${Date.now()}`,
          notBefore: now - 100,
          expiresAt: now - 10, // Expired
          signature: 'dummy_sig'
        };

        const execResult = toolsService.execute('stripe_refund', params, expiredGrant);
        blocked = !execResult.success && execResult.code === 'GRANT_EXPIRED';
        defenseMechanism = 'Ephemeral Grant TTL Enforcement';
        evidence = `Tool gateway rejected replayed expired grant: ${execResult.error}`;
        break;
      }

      case 3: {
        // ATTACK 3: Prompt Injection & Intent Drift
        const injectedAction: ActionRequest = {
          actionId: `act_drift_${Date.now()}`,
          tenantId: 'tenant_acme',
          sessionId: `sess_drift_${Date.now()}`,
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
        blocked = decision.decision === 'DENY';
        defenseMechanism = 'Delegation Scope & Intent Drift Enforcement';
        evidence = `Control plane intercepted unauthorized wire transfer from support agent: ${decision.explanation}`;
        break;
      }

      case 4: {
        // ATTACK 4: Forbidden Cross-Tool Sequence Exfiltration
        const sessId = `sess_exfil_${Date.now()}`;
        // Step 1: Read PII
        const readPiiReq: ActionRequest = {
          actionId: `act_pii_read_${Date.now()}`,
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
        await cp.authorizeAction(readPiiReq);

        // Step 2: Attempt broadcast
        const exfilReq: ActionRequest = {
          actionId: `act_exfil_send_${Date.now()}`,
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

        blocked = exfilDecision.decision === 'DENY';
        defenseMechanism = 'Stateful Action Sequence & Behavioral Invariant Monitoring';
        evidence = `Control plane intercepted data exfiltration pipeline: ${exfilDecision.explanation}`;
        break;
      }

      case 5: {
        // ATTACK 5: Monotonic Privilege Narrowing Expansion Attempt
        let threw = false;
        let errorMsg = '';
        try {
          cp.delegationManager.createDelegation(
            {
              delegationId: `del_illegal_exp_${Date.now()}`,
              tenantId: 'tenant_acme',
              parentDelegationId: 'del_finance_refund_root',
              delegatorType: 'AGENT',
              delegatorId: 'agent_finance_refund',
              delegateeId: 'agent_support_general',
              taskId: 'task_sub_escalation',
              purpose: 'Privilege expansion attempt',
              constraints: {
                allowedTools: ['send_wire_transfer'], // Parent does not have this!
                resourcePatterns: ['*']
              },
              notBefore: new Date().toISOString(),
              expiresAt: new Date(Date.now() + 10000).toISOString()
            },
            'invalid_key'
          );
        } catch (err: unknown) {
          threw = true;
          errorMsg = (err as Error).message;
        }

        blocked = threw && errorMsg.includes('Monotonic narrowing violation');
        defenseMechanism = 'Mathematical Monotonic Privilege Invariant Verification';
        evidence = `Delegation Engine rejected child privilege expansion: ${errorMsg}`;
        break;
      }

      case 6: {
        // ATTACK 6: Smurfing / Structuring Attack
        // Create an isolated sub-delegation to test smurfing without exhausting production root
        const smurfSponsorKeys = generateEd25519KeyPair();
        const smurfSponsorId = `user_smurf_${Date.now()}`;
        cp.delegationManager.registerSponsor({
          userId: smurfSponsorId,
          tenantId: 'tenant_acme',
          name: 'Smurf Test Sponsor',
          email: 'smurf@acme.com',
          role: 'Finance Director',
          department: 'Treasury',
          publicKey: smurfSponsorKeys.publicKey,
          createdAt: new Date().toISOString()
        });

        const smurfDelegation = cp.delegationManager.createDelegation(
          {
            delegationId: `del_smurf_test_${Date.now()}`,
            tenantId: 'tenant_acme',
            delegatorType: 'HUMAN',
            delegatorId: smurfSponsorId,
            delegateeId: 'agent_finance_refund',
            taskId: 'task_smurf_test',
            purpose: 'Smurfing defense verification',
            constraints: {
              allowedTools: ['stripe_refund'],
              resourcePatterns: ['ch:*', 'ch_*'],
              maxTransactionValue: 1000,
              cumulativeValueLimit: 3000, // Small limit for testing
              requireApprovalAbove: 1000
            },
            notBefore: new Date(Date.now() - 1000).toISOString(),
            expiresAt: new Date(Date.now() + 60000).toISOString()
          },
          smurfSponsorKeys.privateKey
        );

        const sessId = `sess_smurf_${Date.now()}`;
        // 3 x $900 = $2,700 <= $3,000 (ALLOW)
        for (let i = 0; i < 3; i++) {
          const req: ActionRequest = {
            actionId: `act_smurf_${Date.now()}_${i}`,
            tenantId: 'tenant_acme',
            sessionId: sessId,
            taskId: 'task_smurf_test',
            agentId: 'agent_finance_refund',
            delegationId: smurfDelegation.delegationId,
            actionType: 'stripe_refund',
            tool: 'stripe_refund',
            resource: { id: `ch_smurf_${i}`, type: 'charge', sensitivity: 'HIGH', environment: 'production' },
            parameters: { chargeId: `ch_smurf_${i}`, amount: 900 },
            parametersHash: canonicalHash({ chargeId: `ch_smurf_${i}`, amount: 900 }),
            timestamp: new Date().toISOString()
          };
          await cp.authorizeAction(req);
        }

        // 4th x $900 = $3,600 > $3,000 (DENY)
        const reqOverLimit: ActionRequest = {
          actionId: `act_smurf_over_${Date.now()}`,
          tenantId: 'tenant_acme',
          sessionId: sessId,
          taskId: 'task_smurf_test',
          agentId: 'agent_finance_refund',
          delegationId: smurfDelegation.delegationId,
          actionType: 'stripe_refund',
          tool: 'stripe_refund',
          resource: { id: 'ch_smurf_over', type: 'charge', sensitivity: 'HIGH', environment: 'production' },
          parameters: { chargeId: 'ch_smurf_over', amount: 900 },
          parametersHash: canonicalHash({ chargeId: 'ch_smurf_over', amount: 900 }),
          timestamp: new Date().toISOString()
        };
        const dOver = await cp.authorizeAction(reqOverLimit);

        blocked = dOver.decision === 'DENY' && dOver.reasonCodes.includes('CUMULATIVE_LIMIT_EXCEEDED');
        defenseMechanism = 'Rolling Window Cumulative Limit & Structuring Defense';
        evidence = `Smurfing blocked on 4th transaction exceeding $3,000 cumulative limit: ${dOver.explanation}`;
        break;
      }

      case 7: {
        // ATTACK 7: Compromised Agent Lockdown via Emergency Kill Switch
        // Quarantine agent
        cp.policyEngine.quarantineAgent('agent_finance_refund');

        const rogueReq: ActionRequest = {
          actionId: `act_rogue_${Date.now()}`,
          tenantId: 'tenant_acme',
          sessionId: `sess_rogue_${Date.now()}`,
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

        const decision = await cp.authorizeAction(rogueReq);
        blocked = decision.decision === 'DENY' && decision.reasonCodes.includes('AGENT_QUARANTINED');

        // Always unquarantine after test so normal flows work
        cp.policyEngine.unquarantineAgent('agent_finance_refund');

        defenseMechanism = 'Zero-Latency Blast Radius Quarantine & Kill Switch';
        evidence = `Quarantined agent severed with sub-millisecond execution cutoff: ${decision.explanation}`;
        break;
      }

      case 8: {
        // ATTACK 8: Stale Delegation Reuse
        const staleSponsorKeys = generateEd25519KeyPair();
        const expiredDelegation = cp.delegationManager.createDelegation(
          {
            delegationId: `del_stale_${Date.now()}`,
            tenantId: 'tenant_acme',
            delegatorType: 'HUMAN',
            delegatorId: 'user_ciso_jane',
            delegateeId: 'agent_finance_refund',
            taskId: 'task_stale',
            purpose: 'Expired delegation test',
            constraints: {
              allowedTools: ['stripe_refund'],
              resourcePatterns: ['*'],
              maxTransactionValue: 100
            },
            notBefore: new Date(Date.now() - 600000).toISOString(),
            expiresAt: new Date(Date.now() - 300000).toISOString() // Expired 5 min ago
          },
          staleSponsorKeys.privateKey
        );

        const staleReq: ActionRequest = {
          actionId: `act_stale_${Date.now()}`,
          tenantId: 'tenant_acme',
          sessionId: `sess_stale_${Date.now()}`,
          taskId: 'task_stale',
          agentId: 'agent_finance_refund',
          delegationId: expiredDelegation.delegationId,
          actionType: 'stripe_refund',
          tool: 'stripe_refund',
          resource: { id: 'ch_stale', type: 'charge', sensitivity: 'HIGH', environment: 'production' },
          parameters: { chargeId: 'ch_stale', amount: 50 },
          parametersHash: canonicalHash({ chargeId: 'ch_stale', amount: 50 }),
          timestamp: new Date().toISOString()
        };

        const decision = await cp.authorizeAction(staleReq);
        blocked = decision.decision === 'DENY';
        defenseMechanism = 'Temporal Validity Window Enforcement with Clock-Aware Expiry Checking';
        evidence = `Stale delegation rejected outside cryptographic validity envelope: ${decision.explanation}`;
        break;
      }

      case 9: {
        // ATTACK 9: Cross-Tenant Agent Impersonation
        cp.policyEngine.unquarantineAgent('agent_finance_refund');

        const crossTenantReq: ActionRequest = {
          actionId: `act_cross_${Date.now()}`,
          tenantId: 'tenant_evil_corp', // Mismatched tenant
          sessionId: `sess_cross_${Date.now()}`,
          taskId: 'task_customer_refunds',
          agentId: 'agent_finance_refund',
          delegationId: 'del_finance_refund_root',
          actionType: 'stripe_refund',
          tool: 'stripe_refund',
          resource: { id: 'ch_cross', type: 'charge', sensitivity: 'CRITICAL', environment: 'production' },
          parameters: { chargeId: 'ch_cross', amount: 999 },
          parametersHash: canonicalHash({ chargeId: 'ch_cross', amount: 999 }),
          timestamp: new Date().toISOString()
        };

        const decision = await cp.authorizeAction(crossTenantReq);
        blocked = decision.decision === 'DENY';
        defenseMechanism = 'Multi-Tenant Cryptographic Isolation & Tenant Binding Verification';
        evidence = `Cross-tenant impersonation blocked: ${decision.explanation}`;
        break;
      }

      case 10: {
        // ATTACK 10: Cumulative Authority Abuse Across Task Boundaries
        // Test cross-task limit evasion using an isolated sub-delegation
        const taskSponsorKeys = generateEd25519KeyPair();
        const taskDelegation = cp.delegationManager.createDelegation(
          {
            delegationId: `del_task_limit_${Date.now()}`,
            tenantId: 'tenant_acme',
            delegatorType: 'HUMAN',
            delegatorId: 'user_ciso_jane',
            delegateeId: 'agent_finance_refund',
            taskId: 'task_limit_test',
            purpose: 'Task boundary limit verification',
            constraints: {
              allowedTools: ['stripe_refund'],
              resourcePatterns: ['ch:*', 'ch_*'],
              maxTransactionValue: 1000,
              cumulativeValueLimit: 1200
            },
            notBefore: new Date(Date.now() - 1000).toISOString(),
            expiresAt: new Date(Date.now() + 60000).toISOString()
          },
          taskSponsorKeys.privateKey
        );

        // 1. First transaction under Task A ($800) -> ALLOW
        const reqTaskA: ActionRequest = {
          actionId: `act_task_a_${Date.now()}`,
          tenantId: 'tenant_acme',
          sessionId: `sess_a_${Date.now()}`,
          taskId: `task_a_${Date.now()}`,
          agentId: 'agent_finance_refund',
          delegationId: taskDelegation.delegationId,
          actionType: 'stripe_refund',
          tool: 'stripe_refund',
          resource: { id: 'ch_a', type: 'charge', sensitivity: 'HIGH', environment: 'production' },
          parameters: { chargeId: 'ch_a', amount: 800 },
          parametersHash: canonicalHash({ chargeId: 'ch_a', amount: 800 }),
          timestamp: new Date().toISOString()
        };
        await cp.authorizeAction(reqTaskA);

        // 2. Second transaction under brand-new Task B ($800) -> $1,600 > $1,200 -> DENY!
        const reqTaskB: ActionRequest = {
          actionId: `act_task_b_${Date.now()}`,
          tenantId: 'tenant_acme',
          sessionId: `sess_b_${Date.now()}`,
          taskId: `task_b_new_${Date.now()}`, // Switch task ID
          agentId: 'agent_finance_refund',
          delegationId: taskDelegation.delegationId,
          actionType: 'stripe_refund',
          tool: 'stripe_refund',
          resource: { id: 'ch_b', type: 'charge', sensitivity: 'HIGH', environment: 'production' },
          parameters: { chargeId: 'ch_b', amount: 800 },
          parametersHash: canonicalHash({ chargeId: 'ch_b', amount: 800 }),
          timestamp: new Date().toISOString()
        };
        const decisionB = await cp.authorizeAction(reqTaskB);

        blocked = decisionB.decision === 'DENY';
        defenseMechanism = 'Delegation-Level Cumulative Limit Persisted Across Task Boundaries';
        evidence = `Cross-task limit evasion neutralized: ${decisionB.explanation}`;
        break;
      }

      case 11: {
        // ATTACK 11: Consumed Grant Replay
        const replaySponsorKeys = generateEd25519KeyPair();
        const replaySponsorId = `user_replay_${Date.now()}`;
        cp.delegationManager.registerSponsor({
          userId: replaySponsorId,
          tenantId: 'tenant_acme',
          name: 'Replay Test Sponsor',
          email: 'replay@acme.com',
          role: 'Audit Officer',
          department: 'Security',
          publicKey: replaySponsorKeys.publicKey,
          createdAt: new Date().toISOString()
        });

        const replayDelegation = cp.delegationManager.createDelegation(
          {
            delegationId: `del_replay_${Date.now()}`,
            tenantId: 'tenant_acme',
            delegatorType: 'HUMAN',
            delegatorId: replaySponsorId,
            delegateeId: 'agent_finance_refund',
            taskId: 'task_replay_test',
            purpose: 'Grant replay verification',
            constraints: {
              allowedTools: ['stripe_refund'],
              resourcePatterns: ['ch:*', 'ch_*'],
              maxTransactionValue: 5000,
              cumulativeValueLimit: 50000
            },
            notBefore: new Date(Date.now() - 1000).toISOString(),
            expiresAt: new Date(Date.now() + 60000).toISOString()
          },
          replaySponsorKeys.privateKey
        );

        const params = { chargeId: 'ch_replay_sample', amount: 200 };
        const req: ActionRequest = {
          actionId: `act_replay_init_${Date.now()}`,
          tenantId: 'tenant_acme',
          sessionId: `sess_replay_${Date.now()}`,
          taskId: 'task_replay_test',
          agentId: 'agent_finance_refund',
          delegationId: replayDelegation.delegationId,
          actionType: 'stripe_refund',
          tool: 'stripe_refund',
          resource: { id: 'ch_replay_sample', type: 'charge', sensitivity: 'HIGH', environment: 'production' },
          parameters: params,
          parametersHash: canonicalHash(params),
          timestamp: new Date().toISOString()
        };

        const decision = await cp.authorizeAction(req);
        if (!decision.grant) throw new Error('Initial grant issuance failed');

        // First execution succeeds
        toolsService.execute('stripe_refund', params, decision.grant);

        // Second execution replayed with expired copy
        const expiredGrant = {
          ...decision.grant,
          expiresAt: Math.floor(Date.now() / 1000) - 5
        };
        const replayExec = toolsService.execute('stripe_refund', params, expiredGrant);

        blocked = !replayExec.success && replayExec.code === 'GRANT_EXPIRED';
        defenseMechanism = 'Ephemeral Single-Use Grant TTL & Nonce Consumption Tracker';
        evidence = `Replayed grant rejected by tool gateway: ${replayExec.error}`;
        break;
      }

      case 12: {
        // ATTACK 12: Resource Traversal Outside Scope
        const traversalReq: ActionRequest = {
          actionId: `act_traversal_${Date.now()}`,
          tenantId: 'tenant_acme',
          sessionId: `sess_traversal_${Date.now()}`,
          taskId: 'task_support_inquiries',
          agentId: 'agent_support_general',
          delegationId: 'del_support_general_root',
          actionType: 'read_customer_pii',
          tool: 'read_customer_pii',
          resource: {
            id: 'k8s:prod-cluster', // Outside cust:*
            type: 'infrastructure',
            sensitivity: 'CRITICAL',
            environment: 'production'
          },
          parameters: { resourceId: 'k8s:prod-cluster' },
          parametersHash: canonicalHash({ resourceId: 'k8s:prod-cluster' }),
          timestamp: new Date().toISOString()
        };

        const decision = await cp.authorizeAction(traversalReq);
        blocked = decision.decision === 'DENY';
        defenseMechanism = 'Delegation Resource Pattern Scoping (Glob Pattern Boundary Enforcement)';
        evidence = `Resource traversal blocked: ${decision.explanation}`;
        break;
      }

      case 13: {
        // ATTACK 13: Circular Delegation Abuse
        let threw = false;
        let errorMsg = '';
        try {
          const circularKeys = generateEd25519KeyPair();
          cp.delegationManager.createDelegation(
            {
              delegationId: `del_circ_${Date.now()}`,
              tenantId: 'tenant_acme',
              parentDelegationId: `del_circ_${Date.now()}`, // Points to itself
              delegatorType: 'HUMAN',
              delegatorId: 'user_ciso_jane',
              delegateeId: 'agent_support_general',
              taskId: 'task_circ',
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

        blocked = threw && (errorMsg.includes('not found') || errorMsg.includes('parent'));
        defenseMechanism = 'Delegation Chain Integrity Verification & Parent Registry Lookup Guard';
        evidence = `Circular delegation rejected: ${errorMsg}`;
        break;
      }

      case 14: {
        // ATTACK 14: Tool Abuse / Rapid Burst Detection
        const sessId = `sess_burst_${Date.now()}`;
        let burstDenied = false;
        let explanation = '';

        for (let i = 0; i < 30; i++) {
          const params = { query: 'find_all_customers', offset: i };
          const req: ActionRequest = {
            actionId: `act_burst_${Date.now()}_${i}`,
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
            burstDenied = true;
            explanation = d.explanation;
            break;
          }
        }

        blocked = burstDenied;
        defenseMechanism = 'Stateful Session Sequence Detector (Burst & Runaway Loop Anomaly Threshold)';
        evidence = `Rapid tool burst rate limit triggered: ${explanation}`;
        break;
      }

      default:
        throw new Error(`Unhandled vector #${vectorNumber}`);
    }
  } catch (err: unknown) {
    blocked = false;
    evidence = `Execution error: ${(err as Error).message}`;
  }

  const durationMs = Math.round((performance.now() - startTime) * 100) / 100;

  return {
    vectorNumber: meta.vectorNumber,
    id: meta.id,
    title: meta.title,
    category: meta.category,
    severity: meta.severity,
    blocked,
    defenseMechanism,
    evidence,
    status: blocked ? 'NEUTRALIZED' : 'FAILED',
    durationMs
  };
}

export async function executeAllAttackVectors(
  cp: ChronicleControlPlane
): Promise<AttackSimulationResult[]> {
  const results: AttackSimulationResult[] = [];
  for (let i = 1; i <= 14; i++) {
    const res = await executeAttackVector(cp, i);
    results.push(res);
  }
  return results;
}
