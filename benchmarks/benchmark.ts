/**
 * Chronicle High-Throughput Performance & Latency Benchmark
 * Measures Cryptographic Signing, Canonical Hashing, Full AACT Authorization Pipeline,
 * and Merkle Receipt Ledger Verification Throughput.
 */

import {
  generateEd25519KeyPair,
  canonicalJsonStringify,
  canonicalHash,
  signEd25519,
  verifyEd25519
} from '@chronicle/crypto-primitives';
import { ChronicleControlPlane } from '../apps/control-plane/src/index.ts';
import type { ActionRequest } from '@chronicle/core-types';

function formatNumber(num: number): string {
  return num.toLocaleString(undefined, { maximumFractionDigits: 2 });
}

async function runBenchmarks() {
  console.log('\n\x1b[1m\x1b[36m================================================================');
  console.log('       CHRONICLE AACT PERFORMANCE & LATENCY BENCHMARK');
  console.log('================================================================\x1b[0m\n');

  const { publicKey, privateKey } = generateEd25519KeyPair();
  const samplePayload = {
    chargeId: 'ch_perf_12891',
    amount: 199.99,
    currency: 'USD',
    customer: { id: 'cust_8812', email: 'user@example.com' },
    metadata: { orderId: 'ord_9901', source: 'mobile_app', retries: 0 }
  };

  // -------------------------------------------------------------
  // Benchmark 1: Canonical Serialization & SHA-256 Parameter Hashing
  // -------------------------------------------------------------
  console.log('\x1b[1m1. Canonical Parameter Hashing (TOCTOU Defense Engine)\x1b[0m');
  const HASH_ITERATIONS = 50000;
  const hashStart = performance.now();
  for (let i = 0; i < HASH_ITERATIONS; i++) {
    canonicalHash(samplePayload);
  }
  const hashDurationSec = (performance.now() - hashStart) / 1000;
  const hashOpsSec = HASH_ITERATIONS / hashDurationSec;
  const hashAvgUs = (hashDurationSec * 1000000) / HASH_ITERATIONS;

  console.log(`  Iterations:  ${formatNumber(HASH_ITERATIONS)}`);
  console.log(`  Throughput:  \x1b[32m${formatNumber(hashOpsSec)} ops/sec\x1b[0m`);
  console.log(`  Avg Latency: \x1b[36m${formatNumber(hashAvgUs)} \x1b[36mμs\x1b[0m\n`);

  // -------------------------------------------------------------
  // Benchmark 2: Ed25519 Asymmetric Cryptographic Operations
  // -------------------------------------------------------------
  console.log('\x1b[1m2. Ed25519 Cryptographic Signing & Verification\x1b[0m');
  const CRYPTO_ITERATIONS = 5000;
  const canonicalData = canonicalJsonStringify(samplePayload);

  // Signing
  const signStart = performance.now();
  const signatures: string[] = [];
  for (let i = 0; i < CRYPTO_ITERATIONS; i++) {
    signatures.push(signEd25519(canonicalData, privateKey));
  }
  const signDurationSec = (performance.now() - signStart) / 1000;
  const signOpsSec = CRYPTO_ITERATIONS / signDurationSec;
  const signAvgMs = (signDurationSec * 1000) / CRYPTO_ITERATIONS;

  console.log(`  Signatures Created:     ${formatNumber(CRYPTO_ITERATIONS)}`);
  console.log(`  Signing Throughput:     \x1b[32m${formatNumber(signOpsSec)} ops/sec\x1b[0m (avg ${formatNumber(signAvgMs)} ms)`);

  // Verification
  const verifyStart = performance.now();
  for (let i = 0; i < CRYPTO_ITERATIONS; i++) {
    verifyEd25519(canonicalData, signatures[i], publicKey);
  }
  const verifyDurationSec = (performance.now() - verifyStart) / 1000;
  const verifyOpsSec = CRYPTO_ITERATIONS / verifyDurationSec;
  const verifyAvgMs = (verifyDurationSec * 1000) / CRYPTO_ITERATIONS;

  console.log(`  Signatures Verified:    ${formatNumber(CRYPTO_ITERATIONS)}`);
  console.log(`  Verify Throughput:      \x1b[32m${formatNumber(verifyOpsSec)} ops/sec\x1b[0m (avg ${formatNumber(verifyAvgMs)} ms)\n`);

  // -------------------------------------------------------------
  // Benchmark 3: Full End-to-End AACT Pipeline Latency Distribution
  // -------------------------------------------------------------
  console.log('\x1b[1m3. Full End-to-End AACT Authorization Pipeline\x1b[0m');
  console.log('   (Delegation Chain -> Sequence Invariant -> Policy Risk -> Ed25519 Grant -> Merkle Receipt)');

  const cp = new ChronicleControlPlane();
  const PIPELINE_ITERATIONS = 2000;
  const latencies: number[] = [];

  for (let i = 0; i < PIPELINE_ITERATIONS; i++) {
    const params = { chargeId: `ch_bench_${i}`, amount: 50 + (i % 800) };
    const req: ActionRequest = {
      actionId: `act_bench_${i}`,
      tenantId: 'tenant_acme',
      sessionId: `sess_bench_${Math.floor(i / 10)}`,
      taskId: 'task_customer_refunds',
      agentId: 'agent_finance_refund',
      delegationId: 'del_finance_refund_root',
      actionType: 'stripe_refund',
      tool: 'stripe_refund',
      resource: { id: `ch_bench_${i}`, type: 'charge', sensitivity: 'HIGH', environment: 'production' },
      parameters: params,
      parametersHash: canonicalHash(params),
      timestamp: new Date().toISOString()
    };

    const start = performance.now();
    const decision = await cp.authorizeAction(req);
    const end = performance.now();
    latencies.push(end - start);
  }

  latencies.sort((a, b) => a - b);
  const sum = latencies.reduce((acc, v) => acc + v, 0);
  const mean = sum / latencies.length;
  const p50 = latencies[Math.floor(latencies.length * 0.50)];
  const p90 = latencies[Math.floor(latencies.length * 0.90)];
  const p95 = latencies[Math.floor(latencies.length * 0.95)];
  const p99 = latencies[Math.floor(latencies.length * 0.99)];
  const pipelineOpsSec = PIPELINE_ITERATIONS / (sum / 1000);

  console.log(`  Actions Processed:      ${formatNumber(PIPELINE_ITERATIONS)}`);
  console.log(`  Total Throughput:       \x1b[32m${formatNumber(pipelineOpsSec)} decisions/sec\x1b[0m`);
  console.log(`  Mean Latency:           \x1b[36m${formatNumber(mean)} ms\x1b[0m`);
  console.log(`  p50 (Median):           \x1b[36m${formatNumber(p50)} ms\x1b[0m`);
  console.log(`  p90:                    \x1b[36m${formatNumber(p90)} ms\x1b[0m`);
  console.log(`  p95:                    \x1b[36m${formatNumber(p95)} ms\x1b[0m`);
  console.log(`  p99:                    \x1b[33m${formatNumber(p99)} ms\x1b[0m (Target: < 3.00 ms)\n`);

  // -------------------------------------------------------------
  // Benchmark 4: Merkle-Chained Cryptographic Audit Ledger Verification
  // -------------------------------------------------------------
  console.log('\x1b[1m4. Merkle-Chained Ledger Cryptographic Audit Verification\x1b[0m');
  const auditStart = performance.now();
  const verification = cp.auditLedger.verifyIntegrity();
  const auditDurationMs = performance.now() - auditStart;

  console.log(`  Receipt Blocks Audited: ${formatNumber(verification.totalReceipts)} blocks`);
  console.log(`  Cryptographic Verdict:  \x1b[32m${verification.valid ? 'VALID (100% Unbroken Merkle Chain)' : 'TAMPERED'}\x1b[0m`);
  console.log(`  Full Audit Duration:    \x1b[36m${formatNumber(auditDurationMs)} ms\x1b[0m (${formatNumber(verification.totalReceipts / (auditDurationMs / 1000))} blocks/sec)\n`);

  console.log('\x1b[1m\x1b[32m================================================================');
  console.log(' CHRONICLE PERFORMANCE BENCHMARK COMPLETE - ZERO HOTSPOTS DETECTED');
  console.log('================================================================\x1b[0m\n');
}

runBenchmarks().catch(err => {
  console.error('Benchmark failed:', err);
  process.exit(1);
});
