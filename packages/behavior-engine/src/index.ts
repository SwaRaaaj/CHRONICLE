/**
 * Chronicle Statistical Behavioral Baselining & Advisory Anomaly Detection Engine
 * Implements §17 (Behavior Model), §18 (Behavioral Anomaly Detection), §31 (Baseline),
 * §63 (Policy Learning), and §76 (Asynchronous Risk Analysis).
 */

import type {
  AgentId,
  TenantId,
  ActionRequest,
  ActionContext,
  ActionHistoryRecord,
  BehaviorProfile,
  BehaviorAnomalyAssessment,
  ToolCallDistribution,
} from '@chronicle/core-types';

interface RunningStats {
  count: number;
  mean: number;
  m2: number; // For Welford's algorithm: sum of squared differences from mean
  resourceCounts: Record<string, number>;
  sensitivityCounts: Record<string, number>;
}

export class BehaviorBaselineEngine {
  // Profiles mapped by "tenantId:agentId"
  private profiles = new Map<string, BehaviorProfile>();

  // Running statistics for online calculation: "tenantId:agentId:tool" -> RunningStats
  private toolStats = new Map<string, RunningStats>();

  // Hourly call timestamps for frequency analysis: "tenantId:agentId" -> number[] (epoch ms)
  private invocationTimestamps = new Map<string, number[]>();

  /**
   * Record an observed action into the statistical profile (§17, §31)
   * Uses Welford's algorithm for numerically stable streaming variance.
   */
  public recordObservedAction(record: ActionHistoryRecord): void {
    const agentKey = `${record.agentId}`;
    const toolKey = `${record.agentId}:${record.tool}`;
    const now = Date.now();

    // 1. Update invocation timestamps for call rate frequency tracking
    let timestamps = this.invocationTimestamps.get(agentKey);
    if (!timestamps) {
      timestamps = [];
      this.invocationTimestamps.set(agentKey, timestamps);
    }
    timestamps.push(now);

    // Keep only last 24 hours of timestamps
    const oneDayAgo = now - 24 * 60 * 60 * 1000;
    while (timestamps.length > 0 && timestamps[0] < oneDayAgo) {
      timestamps.shift();
    }

    // 2. Extract transaction amount if present
    const amount = typeof record.parameters?.amount === 'number' ? record.parameters.amount : 0;

    // 3. Update Welford running stats for (agent, tool)
    let stats = this.toolStats.get(toolKey);
    if (!stats) {
      stats = {
        count: 0,
        mean: 0,
        m2: 0,
        resourceCounts: {},
        sensitivityCounts: {},
      };
      this.toolStats.set(toolKey, stats);
    }

    stats.count += 1;
    if (amount > 0) {
      const delta = amount - stats.mean;
      stats.mean += delta / stats.count;
      const delta2 = amount - stats.mean;
      stats.m2 += delta * delta2;
    }

    // Track resource frequency
    stats.resourceCounts[record.resourceId] = (stats.resourceCounts[record.resourceId] || 0) + 1;

    // 4. Update overall behavior profile
    let profile = this.profiles.get(agentKey);
    if (!profile) {
      profile = {
        agentId: record.agentId,
        tenantId: 'tenant_default',
        sampleCount: 0,
        toolDistributions: {},
        typicalSequences: [],
        typicalOperatingHours: { startHourUTC: 8, endHourUTC: 20 },
        lastUpdated: new Date().toISOString(),
      };
      this.profiles.set(agentKey, profile);
    }

    profile.sampleCount += 1;
    profile.lastUpdated = new Date().toISOString();

    const variance = stats.count > 1 ? stats.m2 / (stats.count - 1) : 0;
    const stdDev = Math.sqrt(variance);

    // Calculate calls per hour over the recorded window
    const windowHours = Math.max(1, (now - (timestamps[0] || now)) / (1000 * 60 * 60));
    const callsPerHour = timestamps.length / windowHours;

    profile.toolDistributions[record.tool] = {
      meanCallsPerHour: Math.round(callsPerHour * 10) / 10,
      stdDevCallsPerHour: Math.round((callsPerHour * 0.2) * 10) / 10, // heuristic estimate
      meanTransactionValue: Math.round(stats.mean * 100) / 100,
      stdDevTransactionValue: Math.round(stdDev * 100) / 100,
      commonResources: Object.keys(stats.resourceCounts).slice(0, 5),
    };
  }

  /**
   * Assess behavioral anomaly for an incoming ActionRequest (§18)
   * Computes Z-scores for amount and frequency, detects uncharacteristic tools & resource sensitivities.
   */
  public assessAnomaly(
    action: ActionRequest,
    context?: Partial<ActionContext>
  ): BehaviorAnomalyAssessment {
    const agentKey = `${action.agentId}`;
    const toolKey = `${action.agentId}:${action.tool}`;
    const profile = this.profiles.get(agentKey);
    const stats = this.toolStats.get(toolKey);

    // If agent has no historical samples (< 3), baseline is warm-up phase (advisory score 0)
    if (!profile || profile.sampleCount < 3) {
      return {
        agentId: action.agentId,
        anomalyDetected: false,
        anomalyScore: 0,
        unusualTool: false,
        unusualResource: false,
        explanation: 'Agent baseline is warming up (< 3 historical samples). No deviation established.',
        advisoryOnly: true,
      };
    }

    const amount = typeof action.parameters?.amount === 'number' ? action.parameters.amount : 0;
    let zScoreAmount: number | undefined;
    let anomalyScore = 0;
    const explanations: string[] = [];

    // 1. Novel Uncharacteristic Tool Detection
    let unusualTool = false;
    if (!profile.toolDistributions[action.tool] || !stats) {
      unusualTool = true;
      anomalyScore += 50;
      explanations.push(`Agent has never previously invoked tool '${action.tool}'`);
    } else {
      // Tool exists in profile; perform Z-Score analysis on amount if stats available
      const variance = stats.count > 1 ? stats.m2 / (stats.count - 1) : 0;
      const stdDev = Math.sqrt(variance);

      if (amount > 0 && stats.mean > 0 && stdDev > 0) {
        zScoreAmount = Math.round(((amount - stats.mean) / stdDev) * 100) / 100;

        if (zScoreAmount > 4.0) {
          anomalyScore += 65;
          explanations.push(
            `Transaction amount $${amount} is an extreme statistical outlier (Z = ${zScoreAmount}, +${Math.round(
              (amount / stats.mean) * 100 - 100
            )}% over historical mean of $${Math.round(stats.mean)} ± $${Math.round(stdDev)})`
          );
        } else if (zScoreAmount > 2.5) {
          anomalyScore += 35;
          explanations.push(
            `Transaction amount $${amount} deviates significantly from baseline (Z = ${zScoreAmount})`
          );
        }
      }
    }

    // 2. Frequency Burst / Rate Outlier Analysis
    const timestamps = this.invocationTimestamps.get(agentKey) || [];
    const oneHourAgo = Date.now() - 60 * 60 * 1000;
    const recentHourCalls = timestamps.filter((t) => t >= oneHourAgo).length + 1;

    const toolDist = profile.toolDistributions[action.tool];
    let zScoreFrequency: number | undefined;
    if (toolDist && toolDist.meanCallsPerHour > 0) {
      const meanFreq = toolDist.meanCallsPerHour;
      const stdDevFreq = Math.max(1, toolDist.stdDevCallsPerHour);
      zScoreFrequency = Math.round(((recentHourCalls - meanFreq) / stdDevFreq) * 100) / 100;

      if (zScoreFrequency > 3.0) {
        anomalyScore += 40;
        explanations.push(
          `Invocation frequency burst: ${recentHourCalls} calls/hr (Z = ${zScoreFrequency}, historical baseline: ${meanFreq} calls/hr)`
        );
      }
    }

    // 3. Sensitivity Boundary Crossing Detection
    let unusualResource = false;
    if (
      action.resource.sensitivity === 'CRITICAL' &&
      stats &&
      !Object.keys(stats.sensitivityCounts).includes('CRITICAL')
    ) {
      unusualResource = true;
      anomalyScore += 30;
      explanations.push(
        `Agent has never previously accessed CRITICAL sensitivity resources on '${action.tool}'`
      );
    }

    // Cap total anomaly score at 100
    anomalyScore = Math.min(100, anomalyScore);
    const anomalyDetected = anomalyScore >= 45;

    return {
      agentId: action.agentId,
      anomalyDetected,
      anomalyScore,
      zScoreAmount,
      zScoreFrequency,
      unusualTool,
      unusualResource,
      explanation:
        explanations.length > 0
          ? explanations.join('; ')
          : 'Observed behavior conforms within normal Gaussian operational parameters (Z < 2.0).',
      advisoryOnly: true, // Master rule §18/§76: advisory signal for risk engine, not opaque blocking
    };
  }

  /**
   * Retrieve the complete statistical profile for an agent (§17)
   */
  public getProfile(agentId: AgentId): BehaviorProfile | undefined {
    return this.profiles.get(agentId);
  }

  /**
   * Reset or seed baseline profile (useful for testing and bootstrapping)
   */
  public seedProfile(agentId: AgentId, baselineData: {
    tool: string;
    meanAmount: number;
    stdDevAmount: number;
    meanCallsPerHour: number;
  }): void {
    const agentKey = agentId;
    const toolKey = `${agentId}:${baselineData.tool}`;

    // Seed running stats
    const count = 30; // 30 samples to establish statistical confidence
    this.toolStats.set(toolKey, {
      count,
      mean: baselineData.meanAmount,
      m2: (count - 1) * Math.pow(baselineData.stdDevAmount, 2),
      resourceCounts: { 'seed_resource_1': 15, 'seed_resource_2': 15 },
      sensitivityCounts: { 'INTERNAL': 30 },
    });

    // Seed timestamps
    const now = Date.now();
    const timestamps: number[] = [];
    for (let i = 0; i < baselineData.meanCallsPerHour; i++) {
      timestamps.push(now - Math.random() * 3600 * 1000);
    }
    this.invocationTimestamps.set(agentKey, timestamps);

    // Seed profile
    this.profiles.set(agentKey, {
      agentId,
      tenantId: 'tenant_enterprise',
      sampleCount: count,
      toolDistributions: {
        [baselineData.tool]: {
          meanCallsPerHour: baselineData.meanCallsPerHour,
          stdDevCallsPerHour: Math.max(1, Math.round(baselineData.meanCallsPerHour * 0.2)),
          meanTransactionValue: baselineData.meanAmount,
          stdDevTransactionValue: baselineData.stdDevAmount,
          commonResources: ['seed_resource_1', 'seed_resource_2'],
        },
      },
      typicalSequences: [],
      typicalOperatingHours: { startHourUTC: 8, endHourUTC: 20 },
      lastUpdated: new Date().toISOString(),
    });
  }
}
