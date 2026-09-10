/**
 * Chronicle Idempotent Event Bus Architecture (§74)
 * Provides deduplicated asynchronous event dispatch, decoupled telemetry,
 * and reliable publish/subscribe primitives for the Control Plane.
 */

import type {
  ControlPlaneEvent,
  EventType,
  TenantId,
} from '@chronicle/core-types';

export type EventHandler = (event: ControlPlaneEvent) => Promise<void> | void;

export class IdempotentEventBus {
  // Deduplication cache: stores processed event IDs (bounded to 10,000 to prevent unbounded memory growth)
  private processedEventIds = new Set<string>();
  private processedOrder: string[] = [];
  private readonly maxDeduplicationCacheSize = 10000;

  // Subscriptions mapped by EventType or '*'
  private handlers = new Map<string, Set<EventHandler>>();

  // In-memory event audit log
  private eventHistory: ControlPlaneEvent[] = [];

  constructor() {}

  /**
   * Subscribe to specific or wildcard events (§74)
   * Returns an unsubscribe function.
   */
  public subscribe(eventType: EventType | '*', handler: EventHandler): () => void {
    let handlerSet = this.handlers.get(eventType);
    if (!handlerSet) {
      handlerSet = new Set<EventHandler>();
      this.handlers.set(eventType, handlerSet);
    }
    handlerSet.add(handler);

    return () => {
      handlerSet?.delete(handler);
    };
  }

  /**
   * Publish an event with strict idempotency / deduplication (§74)
   * If the eventId has already been processed, it is safely ignored.
   */
  public async publish(event: ControlPlaneEvent): Promise<{ published: boolean; deduplicated: boolean }> {
    // 1. Check idempotency
    if (this.processedEventIds.has(event.eventId)) {
      return { published: false, deduplicated: true };
    }

    // 2. Mark event as processed (with LRU eviction of old IDs)
    this.processedEventIds.add(event.eventId);
    this.processedOrder.push(event.eventId);
    if (this.processedOrder.length > this.maxDeduplicationCacheSize) {
      const oldestId = this.processedOrder.shift();
      if (oldestId) {
        this.processedEventIds.delete(oldestId);
      }
    }

    // 3. Commit to event log
    this.eventHistory.push(event);
    if (this.eventHistory.length > 5000) {
      this.eventHistory.shift();
    }

    // 4. Dispatch to subscribers asynchronously without throwing to caller
    const specificHandlers = this.handlers.get(event.eventType) || new Set();
    const wildcardHandlers = this.handlers.get('*') || new Set();
    const allHandlers = [...specificHandlers, ...wildcardHandlers];

    for (const handler of allHandlers) {
      try {
        const result = handler(event);
        if (result instanceof Promise) {
          await result;
        }
      } catch (err: unknown) {
        if (process.env.NODE_ENV !== 'test') {
          console.warn(
            `[IdempotentEventBus] Error in event handler for '${event.eventType}' (EventId: ${event.eventId}):`,
            err
          );
        }
      }
    }

    return { published: true, deduplicated: false };
  }

  /**
   * Query event audit history (§64, §65)
   */
  public getHistory(tenantId?: TenantId, eventType?: EventType): ControlPlaneEvent[] {
    return this.eventHistory.filter((e) => {
      if (tenantId && e.tenantId !== tenantId) return false;
      if (eventType && e.eventType !== eventType) return false;
      return true;
    });
  }

  /**
   * Clear in-memory history (primarily for tests)
   */
  public clear(): void {
    this.processedEventIds.clear();
    this.processedOrder = [];
    this.eventHistory = [];
  }
}
