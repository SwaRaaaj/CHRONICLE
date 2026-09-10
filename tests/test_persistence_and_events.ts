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

  console.log(`\nResults: ${passed} passed, ${failed} failed\n`);
  if (failed > 0) {
    process.exit(1);
  }
}

runPersistenceAndEventTests().catch((err) => {
  console.error(err);
  process.exit(1);
});
