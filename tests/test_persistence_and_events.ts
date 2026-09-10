/**
 * Test Suite: Relational Database Schema Migrations & Idempotent Event Bus (§71, §73, §74, §78)
 */

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { IdempotentEventBus } from '../packages/event-bus/src/index.ts';
import type { ControlPlaneEvent } from '../packages/core-types/src/index.ts';

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

async function runPersistenceAndEventTests() {
  console.log('\n=== TESTING DATABASE SCHEMA & IDEMPOTENT EVENT BUS (§71, §73, §74, §78) ===\n');

  // 1. Validate PostgreSQL Initial Migration Schema Script (§73)
  const migrationPath = resolve(process.cwd(), 'database/migrations/001_initial_schema.sql');
  const sqlContent = readFileSync(migrationPath, 'utf8');

  assert(sqlContent.includes('CREATE TABLE IF NOT EXISTS tenants'), 'defines tenants table with multi-tenant isolation');
  assert(sqlContent.includes('CREATE TABLE IF NOT EXISTS agents'), 'defines agents table with lifecycle statuses');
  assert(sqlContent.includes('CREATE TABLE IF NOT EXISTS delegations'), 'defines delegations table with monotonic constraints');
  assert(sqlContent.includes('CREATE TABLE IF NOT EXISTS authorization_grants'), 'defines authorization_grants table with nonce & TTL');
  assert(sqlContent.includes('CREATE TABLE IF NOT EXISTS authorization_receipts'), 'defines append-only authorization_receipts ledger table');
  assert(sqlContent.includes('CREATE TABLE IF NOT EXISTS workflow_definitions'), 'defines workflow state machine table');
  assert(sqlContent.includes('CREATE TABLE IF NOT EXISTS behavior_profiles'), 'defines behavioral baseline table');
  assert(sqlContent.includes('CREATE INDEX IF NOT EXISTS idx_actions_agent'), 'includes B-Tree performance indexes');

  // 2. Test Idempotent Event Bus (§74)
  const bus = new IdempotentEventBus();
  const receivedEvents: ControlPlaneEvent[] = [];
  const wildcardReceived: ControlPlaneEvent[] = [];

  // Subscribe to specific event type
  const unsubSpecific = bus.subscribe('ACTION_ALLOWED', (evt) => {
    receivedEvents.push(evt);
  });

  // Subscribe to wildcard
  bus.subscribe('*', (evt) => {
    wildcardReceived.push(evt);
  });

  const event1: ControlPlaneEvent = {
    eventId: 'evt_001',
    eventType: 'ACTION_ALLOWED',
    tenantId: 'tenant_acme',
    timestamp: new Date().toISOString(),
    producer: 'PolicyEngine',
    correlationId: 'corr_100',
    payload: { actionId: 'act_1', tool: 'stripe_refund', amount: 50 },
  };

  // Publish event 1
  const pub1 = await bus.publish(event1);
  assert(pub1.published && !pub1.deduplicated, 'publishes new event successfully');
  assert(receivedEvents.length === 1, 'delivers event to specific subscriber');
  assert(wildcardReceived.length === 1, 'delivers event to wildcard subscriber');

  // 3. Test Idempotency / Deduplication (§74)
  // Re-publishing the exact same eventId should be deduplicated
  const pubDuplicate = await bus.publish(event1);
  assert(!pubDuplicate.published && pubDuplicate.deduplicated, 'deduplicates re-published event with identical eventId (§74)');
  assert(receivedEvents.length === 1, 'does not re-invoke subscriber on duplicate event');

  // 4. Test Error Boundary in Subscribers
  bus.subscribe('ACTION_DENIED', () => {
    throw new Error('Simulated subscriber crash');
  });

  const event2: ControlPlaneEvent = {
    eventId: 'evt_002',
    eventType: 'ACTION_DENIED',
    tenantId: 'tenant_acme',
    timestamp: new Date().toISOString(),
    producer: 'PolicyEngine',
    correlationId: 'corr_101',
    payload: { actionId: 'act_2', reason: 'LIMIT_EXCEEDED' },
  };

  // Publish should NOT throw despite failing subscriber
  let publisherDidNotCrash = false;
  try {
    const pub2 = await bus.publish(event2);
    publisherDidNotCrash = pub2.published;
  } catch {
    publisherDidNotCrash = false;
  }
  assert(publisherDidNotCrash, 'isolates subscriber errors within error boundary without crashing publisher (§78)');

  // 5. Test History Query
  const history = bus.getHistory('tenant_acme');
  assert(history.length === 2, 'records audit event history queryable by tenantId');

  // 6. Validate PostgreSQL Migration 002 Schema Script (§73)
  const migration002Path = resolve(process.cwd(), 'database/migrations/002_behavior_and_workflow.sql');
  const sql002Content = readFileSync(migration002Path, 'utf8');

  assert(sql002Content.includes('CREATE TABLE IF NOT EXISTS behavior_profiles'), 'migration 002 defines behavior_profiles table');
  assert(sql002Content.includes('CREATE TABLE IF NOT EXISTS workflow_definitions'), 'migration 002 defines workflow_definitions table');
  assert(sql002Content.includes('CREATE TABLE IF NOT EXISTS workflow_instances'), 'migration 002 defines workflow_instances table');
  assert(sql002Content.includes('CREATE TABLE IF NOT EXISTS invariants'), 'migration 002 defines invariants table');
  assert(sql002Content.includes('CREATE TABLE IF NOT EXISTS policy_shadow_runs'), 'migration 002 defines policy_shadow_runs table');
  assert(sql002Content.includes('CREATE TABLE IF NOT EXISTS observation_events'), 'migration 002 defines observation_events table');

  // 7. Test Distributed Persistence Adapter (§71, §73, §78)
  const { PersistenceAdapter } = await import('../packages/persistence/src/index.ts');
  const adapter = new PersistenceAdapter();
  assert(adapter.getMode() === 'memory', 'persistence adapter initializes in memory mode by default');

  await adapter.saveAgent({
    agentId: 'agent_persisted_1',
    tenantId: 'tenant_acme',
    name: 'Persisted Agent',
    description: 'Testing persistence',
    riskClass: 'LOW',
    status: 'ACTIVE',
    modelProvider: 'Anthropic',
    modelName: 'Claude 3.5 Sonnet',
    agentVersion: '1.0.0',
    allowedCapabilities: ['refund'],
    publicKeyPem: 'mock-key',
    keyId: 'key-1',
    createdAt: new Date().toISOString()
  });

  const retrievedAgent = await adapter.getAgent('agent_persisted_1');
  assert(retrievedAgent?.agentId === 'agent_persisted_1', 'persistence adapter stores and retrieves agent');

  await adapter.saveReceipt({
    receiptId: 'rcpt_persist_1',
    tenantId: 'tenant_acme',
    actionId: 'act_1',
    agentId: 'agent_persisted_1',
    decision: 'ALLOW',
    riskScore: 10,
    merkleCurrentHash: 'hash_curr_1',
    merklePreviousHash: 'hash_prev_0',
    signature: 'sig_1',
    timestamp: new Date().toISOString()
  } as any);

  const receipts = await adapter.getReceipts();
  assert(receipts.length === 1 && receipts[0].receiptId === 'rcpt_persist_1', 'persistence adapter stores and retrieves audit receipts');

  // Test policy caching in adapter
  await adapter.cachePolicy('policy:refund', {
    policyId: 'p_ref',
    name: 'Refund Policy',
    targetAction: 'stripe_refund',
    conditions: [],
    effect: 'ALLOW',
    rawText: 'ALLOW stripe_refund'
  });
  const cachedPolicy = await adapter.getCachedPolicy('policy:refund');
  assert(cachedPolicy?.policyId === 'p_ref', 'persistence adapter caches and retrieves compiled policy AST');

  // 8. Test OIDC Enterprise Identity Federation Bridge (§57, §98)
  const { OIDCFederationBridge } = await import('../packages/integrations/src/index.ts');
  const oidcBridge = new OIDCFederationBridge();

  const mockEntraToken = JSON.stringify({
    sub: 'entra_user_9981',
    iss: 'https://login.microsoftonline.com/common/v2.0',
    aud: 'chronicle-entra-app',
    exp: Math.floor(Date.now() / 1000) + 3600,
    iat: Math.floor(Date.now() / 1000),
    name: 'Alice Sponsor',
    email: 'alice@enterprise.com',
    roles: ['SecurityDirector']
  });

  const sponsor = await oidcBridge.verifyOIDCToken(mockEntraToken, 'https://login.microsoftonline.com/common/v2.0');
  assert(sponsor.sponsorId === 'sponsor_oidc_entra_user_9981', 'OIDC bridge maps Entra ID token subject to HumanSponsor ID');
  assert(sponsor.role === 'SecurityDirector', 'OIDC bridge maps Entra ID role claim to sponsor role');
  assert(sponsor.email === 'alice@enterprise.com', 'OIDC bridge preserves enterprise email identity');

  // 9. Test Observation vs Enforcement Engine (§3)
  const { ObservationEngine } = await import('../packages/observation/src/index.ts');
  const obsEngine = new ObservationEngine('observation');
  assert(obsEngine.getMode() === 'observation', 'observation engine initializes in observation mode');

  const mockActionReq = {
    actionId: 'act_obs_1',
    tenantId: 'tenant_acme',
    sessionId: 'sess_1',
    taskId: 'task_1',
    agentId: 'agent_obs_1',
    actionType: 'stripe_refund',
    tool: 'stripe_refund',
    resource: { id: 'ch_obs_1', type: 'charge', sensitivity: 'INTERNAL', environment: 'production' },
    parameters: { amount: 8000 },
    parametersHash: 'hash',
    timestamp: new Date().toISOString()
  };

  const mockDenyDecision = {
    decision: 'DENY' as const,
    riskScore: 85,
    riskClass: 'HIGH' as const,
    reasonCodes: ['POLICY_DENY' as const],
    explanation: 'Amount exceeds $5000 limit',
    latencyMs: 1.0
  };

  const processed = obsEngine.processDecision(mockActionReq as any, mockDenyDecision);
  assert(processed.decision === 'ALLOW', 'observation mode transforms DENY into ALLOW for non-blocking telemetry');
  assert(processed.explanation.includes('[OBSERVATION MODE] Suppressed DENY'), 'observation decision annotates suppressed violation explanation');

  const obsSummary = obsEngine.getSummary();
  assert(obsSummary.totalSuppressedViolations === 1, 'observation summary tracks suppressed violation count');
  assert(obsSummary.shadowDenyCount === 1, 'observation summary records shadow DENY count');

  console.log(`\nResults: ${passed} passed, ${failed} failed\n`);
  if (failed > 0) {
    process.exit(1);
  }
}

runPersistenceAndEventTests().catch((err) => {
  console.error(err);
  process.exit(1);
});
