/**
 * Test Suite: Statistical Behavioral Baselining & Advisory Anomaly Detection Engine (§17, §18, §31, §63, §76)
 */

import { BehaviorBaselineEngine } from '../packages/behavior-engine/src/index.ts';
import type { ActionRequest, ActionHistoryRecord } from '../packages/core-types/src/index.ts';

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

async function runBehaviorEngineTests() {
  console.log('\n=== TESTING STATISTICAL BEHAVIOR BASELINE ENGINE (§17, §18, §31, §63, §76) ===\n');

  const engine = new BehaviorBaselineEngine();

  // 1. Establish baseline for agent_support using seedProfile (§31)
  // Baseline: refund agent normally does $150 ± $25, ~10 calls/hr
  engine.seedProfile('agent_support', {
    tool: 'stripe_refund',
    meanAmount: 150,
    stdDevAmount: 25,
    meanCallsPerHour: 10,
  });

  const profile = engine.getProfile('agent_support');
  assert(profile !== undefined, 'retrieves statistical behavior profile');
  assert(profile?.toolDistributions['stripe_refund'].meanTransactionValue === 150, 'records mean transaction value ($150)');
  assert(profile?.toolDistributions['stripe_refund'].stdDevTransactionValue === 25, 'records standard deviation ($25)');

  // 2. Normal transaction ($160 -> Z = (160-150)/25 = 0.40 sigma)
  const normalAction: ActionRequest = {
    actionId: 'act_norm',
    tenantId: 'tenant_acme',
    sessionId: 'sess_1',
    taskId: 'task_1',
    agentId: 'agent_support',
    delegationId: 'del_1',
    actionType: 'refund',
    tool: 'stripe_refund',
    resource: { id: 'ch_1', type: 'charge', sensitivity: 'INTERNAL', environment: 'production' },
    parameters: { amount: 160 },
    parametersHash: 'sha256:dummy',
    timestamp: new Date().toISOString(),
  };

  const normalAssessment = engine.assessAnomaly(normalAction);
  assert(!normalAssessment.anomalyDetected, 'flags normal action within 1-sigma as non-anomalous');
  assert(normalAssessment.anomalyScore === 0, 'assigns 0 anomaly score to normal action');
  assert(normalAssessment.zScoreAmount! < 1.0, `computes accurate Z-score (${normalAssessment.zScoreAmount} < 1.0)`);

  // 3. Statistical outlier transaction ($800 -> Z = (800-150)/25 = 26.0 sigma!)
  const outlierAction: ActionRequest = {
    ...normalAction,
    parameters: { amount: 800 },
  };

  const outlierAssessment = engine.assessAnomaly(outlierAction);
  assert(outlierAssessment.anomalyDetected, 'flags extreme monetary outlier as anomalous');
  assert(outlierAssessment.zScoreAmount! > 4.0, `detects extreme Z-score outlier (${outlierAssessment.zScoreAmount} > 4.0)`);
  assert(outlierAssessment.anomalyScore >= 65, 'assigns high anomaly score (>= 65)');
  assert(
    outlierAssessment.explanation.includes('extreme statistical outlier'),
    'provides interpretable explanation with mean, stddev, and Z-score (§18)'
  );

  // 4. Novel uncharacteristic tool invocation
  const novelToolAction: ActionRequest = {
    ...normalAction,
    tool: 'customer_db_dump',
  };

  const novelAssessment = engine.assessAnomaly(novelToolAction);
  assert(novelAssessment.unusualTool, 'flags novel uncharacteristic tool invocation');
  assert(
    novelAssessment.explanation.includes("never previously invoked tool 'customer_db_dump'"),
    'explains novel tool invocation in detail'
  );

  // 5. Online learning: stream new action observations and verify rolling stats update
  for (let i = 0; i < 5; i++) {
    const hist: ActionHistoryRecord = {
      actionId: `hist_stream_${i}`,
      sessionId: 'sess_stream',
      taskId: 'task_stream',
      agentId: 'agent_support',
      actionType: 'refund',
      tool: 'stripe_refund',
      resourceId: `ch_stream_${i}`,
      parameters: { amount: 155 },
      decision: 'ALLOW',
      timestamp: new Date().toISOString(),
    };
    engine.recordObservedAction(hist);
  }

  const updatedProfile = engine.getProfile('agent_support');
  assert(updatedProfile!.sampleCount === 35, 'updates sample count incrementally via streaming observations');

  console.log(`\nResults: ${passed} passed, ${failed} failed\n`);
  if (failed > 0) {
    process.exit(1);
  }
}

runBehaviorEngineTests().catch((err) => {
  console.error(err);
  process.exit(1);
});
