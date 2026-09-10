/**
 * Chronicle Workflow State Machine & Business Invariant Engine
 * Enforces State-Aware, Event-Aware, and Invariant-Constrained Action Authorization (§41, §42, §43, §44)
 */

import type {
  WorkflowId,
  WorkflowInstanceId,
  WorkflowDefinition,
  WorkflowInstance,
  WorkflowTransition,
  BusinessInvariant,
  InvariantEvaluationResult,
  ActionRequest,
  ActionContext,
  TenantId,
  TaskId,
} from '@chronicle/core-types';

export class WorkflowEngine {
  private workflows = new Map<WorkflowId, WorkflowDefinition>();
  private instances = new Map<WorkflowInstanceId, WorkflowInstance>();
  private invariants = new Map<string, BusinessInvariant>();
  private processedRefunds = new Set<string>(); // Tracks chargeIds to prevent double refunds (§41)

  constructor() {
    this.registerDefaultInvariants();
  }

  /**
   * Register a formal workflow state machine definition (§42)
   */
  public registerWorkflow(definition: WorkflowDefinition): void {
    this.workflows.set(definition.workflowId, definition);
  }

  public getWorkflow(workflowId: WorkflowId): WorkflowDefinition | undefined {
    return this.workflows.get(workflowId);
  }

  /**
   * Create a new stateful workflow instance tied to a task (§42)
   */
  public createInstance(
    workflowId: WorkflowId,
    tenantId: TenantId,
    taskId: TaskId,
    initialContext: Record<string, unknown> = {}
  ): WorkflowInstance {
    const definition = this.workflows.get(workflowId);
    if (!definition) {
      throw new Error(`Workflow definition '${workflowId}' not found`);
    }

    const instanceId = `wf_inst_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
    const now = new Date().toISOString();

    const instance: WorkflowInstance = {
      instanceId,
      workflowId,
      tenantId,
      taskId,
      currentState: definition.initialState,
      history: [
        {
          fromState: 'NONE',
          toState: definition.initialState,
          transitionedAt: now,
          triggeredBy: 'SYSTEM_INIT',
        },
      ],
      emittedEvents: [],
      contextData: { ...initialContext },
      createdAt: now,
      updatedAt: now,
    };

    this.instances.set(instanceId, instance);
    return instance;
  }

  public getInstance(instanceId: WorkflowInstanceId): WorkflowInstance | undefined {
    return this.instances.get(instanceId);
  }

  public findInstanceByTask(taskId: TaskId): WorkflowInstance | undefined {
    for (const inst of this.instances.values()) {
      if (inst.taskId === taskId) {
        return inst;
      }
    }
    return undefined;
  }

  /**
   * Emit an external/internal event into a workflow instance (§44)
   * e.g. "fraud_check_passed", "pr_reviewed", "customer_complaint_verified"
   */
  public emitEvent(instanceId: WorkflowInstanceId, event: string): void {
    const instance = this.instances.get(instanceId);
    if (!instance) {
      throw new Error(`Workflow instance '${instanceId}' not found`);
    }

    if (!instance.emittedEvents.includes(event)) {
      instance.emittedEvents.push(event);
      instance.updatedAt = new Date().toISOString();
    }
  }

  /**
   * Transition the workflow state (§42, §43)
   */
  public transition(
    instanceId: WorkflowInstanceId,
    toState: string,
    triggeredBy: string,
    triggerEvent?: string,
    metadata?: Record<string, unknown>
  ): WorkflowInstance {
    const instance = this.instances.get(instanceId);
    if (!instance) {
      throw new Error(`Workflow instance '${instanceId}' not found`);
    }

    const definition = this.workflows.get(instance.workflowId);
    if (!definition) {
      throw new Error(`Workflow definition '${instance.workflowId}' not found`);
    }

    // Verify state exists in definition
    if (!definition.states.includes(toState)) {
      throw new Error(`State '${toState}' is not a valid state in workflow '${definition.name}'`);
    }

    // Find valid transition
    const validTransition = definition.transitions.find(
      (t) => t.fromState === instance.currentState && t.toState === toState
    );

    if (!validTransition) {
      throw new Error(
        `Invalid workflow transition from '${instance.currentState}' to '${toState}' in workflow '${definition.name}'`
      );
    }

    // If transition requires a specific event, verify it has occurred (§44)
    if (validTransition.triggerEvent && !instance.emittedEvents.includes(validTransition.triggerEvent)) {
      if (triggerEvent !== validTransition.triggerEvent) {
        throw new Error(
          `Cannot transition to '${toState}': required prerequisite event '${validTransition.triggerEvent}' has not occurred`
        );
      }
      instance.emittedEvents.push(triggerEvent);
    }

    const now = new Date().toISOString();
    instance.history.push({
      fromState: instance.currentState,
      toState,
      transitionedAt: now,
      triggeredBy,
      event: triggerEvent || validTransition.triggerEvent,
      metadata,
    });

    instance.currentState = toState;
    instance.updatedAt = now;
    return instance;
  }

  /**
   * State-Aware Authorization Check (§43)
   * Verifies if the requested tool is allowed in the current workflow state
   */
  public checkActionAllowed(
    action: ActionRequest,
    instance: WorkflowInstance
  ): { allowed: boolean; reason?: string } {
    const definition = this.workflows.get(instance.workflowId);
    if (!definition) {
      return { allowed: true };
    }

    const requiredStates = definition.actionStateRequirements[action.tool];
    if (!requiredStates || requiredStates.length === 0) {
      // No specific state requirement defined for this tool
      return { allowed: true };
    }

    if (!requiredStates.includes(instance.currentState)) {
      return {
        allowed: false,
        reason: `Action '${action.tool}' requires workflow state [${requiredStates.join(
          ', '
        )}], but current state is '${instance.currentState}'`,
      };
    }

    return { allowed: true };
  }

  /**
   * Register a custom Business Invariant (§41)
   */
  public registerInvariant(invariant: BusinessInvariant): void {
    this.invariants.set(invariant.invariantId, invariant);
  }

  /**
   * Evaluate all registered Business Invariants against an ActionRequest (§41)
   */
  public evaluateInvariants(
    action: ActionRequest,
    context: ActionContext,
    instance?: WorkflowInstance
  ): InvariantEvaluationResult {
    const violatedInvariants: { invariantId: string; name: string; reason: string }[] = [];

    for (const invariant of this.invariants.values()) {
      if (invariant.targetActionType === action.tool || invariant.targetActionType === '*') {
        const result = invariant.evaluate(action, context, instance);
        if (!result.valid) {
          violatedInvariants.push({
            invariantId: invariant.invariantId,
            name: invariant.name,
            reason: result.reason || 'Invariant evaluation failed',
          });
        }
      }
    }

    // Record successful refund to prevent double-refund invariant (§41)
    if (violatedInvariants.length === 0 && (action.tool === 'stripe_refund' || action.tool === 'refund')) {
      const chargeId = (action.parameters?.chargeId || action.parameters?.orderId || action.resource.id) as string;
      if (chargeId) {
        this.processedRefunds.add(chargeId);
      }
    }

    return {
      passed: violatedInvariants.length === 0,
      violatedInvariants,
    };
  }

  /**
   * Built-in standard enterprise invariants (§41)
   */
  private registerDefaultInvariants(): void {
    // Invariant 1: Refund cannot exceed original payment amount
    this.registerInvariant({
      invariantId: 'inv_refund_not_exceed_original',
      tenantId: 'global',
      name: 'Refund Not Exceed Original Payment',
      description: 'Refund amount must be less than or equal to the original payment amount (§41)',
      targetActionType: 'stripe_refund',
      evaluate: (action) => {
        const amount = Number(action.parameters?.amount ?? 0);
        const originalAmount = Number(action.parameters?.originalAmount ?? 5000); // Default simulated ceiling

        if (originalAmount > 0 && amount > originalAmount) {
          return {
            valid: false,
            reason: `Refund amount ($${amount}) exceeds original payment amount ($${originalAmount})`,
          };
        }
        return { valid: true };
      },
    });

    // Invariant 2: Double refund prevention
    this.registerInvariant({
      invariantId: 'inv_double_refund_prevention',
      tenantId: 'global',
      name: 'Double Refund Prevention',
      description: 'A transaction or charge cannot be refunded more than once (§41)',
      targetActionType: 'stripe_refund',
      evaluate: (action) => {
        const chargeId = (action.parameters?.chargeId || action.parameters?.orderId || action.resource.id) as string;
        if (chargeId && this.processedRefunds.has(chargeId)) {
          return {
            valid: false,
            reason: `Charge '${chargeId}' has already been refunded. Duplicate refunds are strictly prohibited.`,
          };
        }
        return { valid: true };
      },
    });

    // Invariant 3: Production deployment requires approved PR
    this.registerInvariant({
      invariantId: 'inv_prod_deploy_requires_pr',
      tenantId: 'global',
      name: 'Production Deploy Requires Approved PR',
      description: 'Production infrastructure deployments require a verified PR approval event (§41)',
      targetActionType: 'deploy_production',
      evaluate: (action, context, instance) => {
        if (action.resource.environment === 'production') {
          const hasPrApproval = instance?.emittedEvents.includes('pr_approved') ||
            action.parameters?.prApproved === true;
          if (!hasPrApproval) {
            return {
              valid: false,
              reason: `Production deployment of '${action.resource.id}' requires an approved pull request event ('pr_approved')`,
            };
          }
        }
        return { valid: true };
      },
    });

    // Invariant 4: Sensitive customer data export restriction
    this.registerInvariant({
      invariantId: 'inv_sensitive_export_restriction',
      tenantId: 'global',
      name: 'Sensitive Data Export Restriction',
      description: 'Sensitive or confidential customer data cannot be exported without compliance sign-off (§41)',
      targetActionType: 'customer_bulk_export',
      evaluate: (action) => {
        if (action.resource.sensitivity === 'CONFIDENTIAL' || action.resource.sensitivity === 'CRITICAL') {
          const complianceApproved = action.parameters?.complianceSignOff === true;
          if (!complianceApproved) {
            return {
              valid: false,
              reason: `Exporting resource with sensitivity '${action.resource.sensitivity}' requires explicit compliance sign-off`,
            };
          }
        }
        return { valid: true };
      },
    });
  }
}
