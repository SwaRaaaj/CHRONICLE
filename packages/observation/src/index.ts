/**
 * Chronicle Observation vs Enforcement Engine (§3)
 * Provides dual-mode operation:
 * - ENFORCEMENT: Synchronous deterministic blocking and step-up gating.
 * - OBSERVATION: Pass-through audit mode where violations generate telemetry and alerts without blocking execution.
 */

import type {
  ActionRequest,
  AuthorizationDecision,
  DecisionEffect,
  ReasonCode,
  AuthorizationGrant
} from '@chronicle/core-types';

export interface ObservationEvent {
  eventId: string;
  actionId: string;
  agentId: string;
  tool: string;
  resourceId: string;
  actualDecision: DecisionEffect;
  shadowDecision: DecisionEffect;
  shadowReasonCodes: ReasonCode[];
  shadowExplanation: string;
  suppressedViolation: boolean;
  timestamp: string;
}

export interface ObservationSummary {
  mode: 'enforcement' | 'observation';
  totalEvaluated: number;
  totalSuppressedViolations: number;
  shadowDenyCount: number;
  shadowHoldCount: number;
  shadowAllowCount: number;
  lastViolationTimestamp?: string;
}

export class ObservationEngine {
  private mode: 'enforcement' | 'observation';
  private events: ObservationEvent[] = [];
  private maxHistory: number = 1000;

  constructor(initialMode: 'enforcement' | 'observation' = 'enforcement') {
    this.mode = initialMode;
  }

  public getMode(): 'enforcement' | 'observation' {
    return this.mode;
  }

  public setMode(mode: 'enforcement' | 'observation'): void {
    this.mode = mode;
  }

  /**
   * Transforms or records an authorization decision based on current mode.
   * If in OBSERVATION mode and decision is DENY or HOLD, it mutates decision to ALLOW
   * (or grants observation access) and logs the suppressed violation.
   */
  public processDecision(
    request: ActionRequest,
    decision: AuthorizationDecision,
    createGrantFn?: () => AuthorizationGrant
  ): AuthorizationDecision {
    const isViolation = decision.decision === 'DENY' || decision.decision === 'HOLD';

    if (this.mode === 'observation') {
      const originalDecision = decision.decision;
      const suppressed = isViolation;

      const event: ObservationEvent = {
        eventId: `obs_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
        actionId: request.actionId,
        agentId: request.agentId,
        tool: request.tool,
        resourceId: request.resource.id,
        actualDecision: 'ALLOW',
        shadowDecision: originalDecision,
        shadowReasonCodes: [...decision.reasonCodes],
        shadowExplanation: decision.explanation,
        suppressedViolation: suppressed,
        timestamp: new Date().toISOString()
      };

      this.recordEvent(event);

      if (isViolation) {
        // Construct shadow-annotated decision
        const observedDecision: AuthorizationDecision = {
          ...decision,
          decision: 'ALLOW',
          explanation: `[OBSERVATION MODE] Suppressed ${originalDecision}: ${decision.explanation}`,
          grant: decision.grant || (createGrantFn ? createGrantFn() : undefined)
        };
        return observedDecision;
      }
    }

    return decision;
  }

  private recordEvent(event: ObservationEvent): void {
    this.events.push(event);
    if (this.events.length > this.maxHistory) {
      this.events.shift();
    }
  }

  public getEvents(limit: number = 100): ObservationEvent[] {
    return this.events.slice(-limit).reverse();
  }

  public getSummary(): ObservationSummary {
    let shadowDenyCount = 0;
    let shadowHoldCount = 0;
    let shadowAllowCount = 0;
    let totalSuppressed = 0;
    let lastViolation: string | undefined;

    for (const e of this.events) {
      if (e.shadowDecision === 'DENY') {
        shadowDenyCount++;
        totalSuppressed++;
        lastViolation = e.timestamp;
      } else if (e.shadowDecision === 'HOLD') {
        shadowHoldCount++;
        totalSuppressed++;
        lastViolation = e.timestamp;
      } else {
        shadowAllowCount++;
      }
    }

    return {
      mode: this.mode,
      totalEvaluated: this.events.length,
      totalSuppressedViolations: totalSuppressed,
      shadowDenyCount,
      shadowHoldCount,
      shadowAllowCount,
      lastViolationTimestamp: lastViolation
    };
  }

  public clearHistory(): void {
    this.events = [];
  }
}
