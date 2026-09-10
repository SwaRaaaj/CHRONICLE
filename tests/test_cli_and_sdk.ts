/**
 * Test Suite: Unified CLI & Developer Client SDK (§80, §81)
 */

import { ChronicleClient } from '../packages/sdk/src/index.ts';
import { generateEd25519KeyPair, createAuthorizationGrant, canonicalHash } from '../packages/crypto-primitives/src/index.ts';
import type { AuthorizationGrant } from '../packages/core-types/src/index.ts';

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

async function runCliAndSdkTests() {
  console.log('\n=== TESTING DEVELOPER CLIENT SDK & CLI PRIMITIVES (§80, §81) ===\n');

  const { publicKey, privateKey } = generateEd25519KeyPair();

  // 1. Instantiate Chronicle Client
  const client = new ChronicleClient({
    endpoint: 'http://localhost:3000',
    tenantId: 'tenant_acme',
    controlPlanePublicKey: publicKey,
    failClosed: true,
    timeoutMs: 1000,
  });

  assert(client !== undefined, 'initializes ChronicleClient with tenant & endpoint configuration');

  // 2. Local Grant Verification (Anti-TOCTOU validation) (§24, §80)
  const legitParams = { amount: 500, chargeId: 'ch_901' };
  const legitHash = canonicalHash(legitParams);

  const validGrant: AuthorizationGrant = createAuthorizationGrant(
    'grant_sdk_test',
    'act_sdk_test',
    'tenant_acme',
    'agent_refund',
    'stripe_refund',
    'stripe_refund',
    'charge_901',
    legitHash,
    'del_root',
    privateKey,
    60 // 60s TTL
  );

  // Verify legitimate payload
  const legitCheck = client.verifyGrant(validGrant, 'stripe_refund', legitParams);
  assert(legitCheck.valid, 'client verifies valid cryptographic grant against matching parameters');

  // 3. Detect Parameter Tampering in SDK
  const tamperedParams = { amount: 50000, chargeId: 'ch_901' }; // Attacker changed $500 -> $50,000
  const tamperedCheck = client.verifyGrant(validGrant, 'stripe_refund', tamperedParams);
  assert(
    !tamperedCheck.valid && tamperedCheck.reason?.includes('PARAMETERS_TAMPERED'),
    'client detects parameter tampering and rejects execution (TOCTOU defense in SDK) (§80)'
  );

  // 4. Detect Tool Mismatch in SDK
  const mismatchCheck = client.verifyGrant(validGrant, 'send_wire_transfer', legitParams);
  assert(
    !mismatchCheck.valid && mismatchCheck.reason?.includes('tool mismatch'),
    'client rejects grant presented to unauthorized tool mismatch'
  );

  // 5. Test Fail-Closed Network Resilience (§54, §78)
  // When endpoint is offline, client must return DENY fail-closed decision
  const offlineClient = new ChronicleClient({
    endpoint: 'http://127.0.0.1:59999', // Non-existent offline port
    tenantId: 'tenant_acme',
    failClosed: true,
    timeoutMs: 200,
  });

  const fallbackDecision = await offlineClient.authorize({
    agentId: 'agent_refund',
    actionType: 'stripe_refund',
    tool: 'stripe_refund',
    resourceId: 'ch_offline',
    parameters: { amount: 100 },
  });

  assert(fallbackDecision.decision === 'DENY', 'client enforces strict FAIL-CLOSED policy when control plane unreachable (§54, §78)');
  assert(fallbackDecision.reasonCodes.includes('POLICY_DENY'), 'returns fail-closed reason code POLICY_DENY');

  // 6. Test Enhanced CLI Command Primitives (§81)
  const { ChronicleControlPlane } = await import('../apps/control-plane/src/index.ts');
  const cp = new ChronicleControlPlane();

  const status = cp.getStatus();
  assert(status.status === 'HEALTHY', 'CLI status reports HEALTHY status');
  assert(status.activeDelegations >= 1, 'CLI status reports active delegations count');
  assert(status.registeredAgents >= 1, 'CLI status reports registered agents count');
  assert(status.ledgerIntegrity.valid === true, 'CLI status reports unbroken ledger integrity');

  const attackPaths = cp.blastRadiusAnalyzer.computeAttackPaths('agent_finance_refund');
  assert(attackPaths.length > 0, 'CLI attack-path computes lateral movement paths for agent');
  assert(attackPaths.some(p => p.tool === 'stripe_refund'), 'attack path identifies reachable tool stripe_refund');

  const blastReport = cp.blastRadiusAnalyzer.calculateBlastRadius('agent_finance_refund');
  assert(blastReport !== null && blastReport.maximumFinancialExposure > 0, 'CLI blast-radius computes maximum financial exposure');

  console.log(`\nResults: ${passed} passed, ${failed} failed\n`);
  if (failed > 0) {
    process.exit(1);
  }
}

runCliAndSdkTests().catch((err) => {
  console.error(err);
  process.exit(1);
});
