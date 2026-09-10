/**
 * Chronicle Core Types
 * First-class domain representations for Behavior-Aware, Sequence-Aware,
 * Transaction-Level Autonomous Action Control.
 */

// 1. Entity Identifiers & Enums
export type TenantId = string;
export type AgentId = string;
export type UserId = string; // Human Sponsor
export type DelegationId = string;
export type ActionId = string;
export type TaskId = string;
export type SessionId = string;
export type GrantId = string;
export type ReceiptId = string;
export type ApprovalId = string;
export type PolicyId = string;

export type RiskClass = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type AgentStatus = 'REGISTERED' | 'ACTIVE' | 'SUSPENDED' | 'QUARANTINED' | 'REVOKED' | 'DECOMMISSIONED';
export type ResourceSensitivity = 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'SENSITIVE' | 'CRITICAL';

export type DecisionEffect = 'ALLOW' | 'DENY' | 'HOLD' | 'ESCALATE' | 'CONSTRAIN';

export type ReasonCode =
  | 'POLICY_PERMIT'
  | 'POLICY_DENY'
  | 'LIMIT_EXCEEDED'
  | 'CUMULATIVE_LIMIT_EXCEEDED'
  | 'INTENT_DRIFT'
  | 'SEQUENCE_ANOMALY'
  | 'FORBIDDEN_SEQUENCE'
  | 'MISSING_PREREQUISITE_SEQUENCE'
  | 'DELEGATION_INVALID'
  | 'DELEGATION_REVOKED'
  | 'DELEGATION_LIMIT_EXCEEDED'
  | 'MONOTONIC_NARROWING_VIOLATION'
  | 'RESOURCE_MISMATCH'
  | 'RESOURCE_OWNER_MISMATCH'
  | 'WORKFLOW_STATE_INVALID'
  | 'MISSING_REQUIRED_APPROVAL'
  | 'AGENT_QUARANTINED'
  | 'TOOL_LOCKED_DOWN'
  | 'RISK_THRESHOLD_EXCEEDED'
  | 'INVARIANT_VIOLATION'
  | 'CLOCK_SKEW_ERROR'
  | 'REPLAY_DETECTED';

// 2. Human & Agent Identity Model
export interface HumanSponsor {
  userId: UserId;
  tenantId: TenantId;
  name: string;
  email: string;
  role: string;
  department: string;
  publicKey: string;
  createdAt: string;
}

export interface AgentIdentity {
  agentId: AgentId;
  tenantId: TenantId;
  name: string;
  agentType: string;
  agentVersion: string;
  modelProvider: string; // e.g. "anthropic/claude-3.5-sonnet", "openai/gpt-4o"
  owner: UserId; // Human Owner
  sponsor: UserId; // Active Human Sponsor
  parentAgentId?: AgentId;
  creationTime: string;
  expirationTime?: string;
  status: AgentStatus;
  environment: 'development' | 'staging' | 'production';
  riskClass: RiskClass;
  allowedCapabilities: string[];
  publicKey: string;
}

// 3. Delegation Model & Constraints
export interface DelegationConstraints {
  allowedTools: string[];
  resourcePatterns: string[]; // Glob patterns e.g. ["order:nord_*"]
  maxTransactionValue?: number;
  cumulativeValueLimit?: number;
  currency?: string;
  temporalValiditySeconds?: number;
  maxActionCount?: number;
  allowedActionTypes?: string[];
  requireApprovalAbove?: number;
  enforceWorkflows?: string[];
}

export interface DelegationEnvelope {
  delegationId: DelegationId;
  tenantId: TenantId;
  parentDelegationId?: DelegationId;
  delegatorType: 'HUMAN' | 'AGENT';
  delegatorId: string;
  delegateeId: AgentId;
  taskId: TaskId;
  purpose: string;
  constraints: DelegationConstraints;
  notBefore: string;
  expiresAt: string;
  revoked: boolean;
  revokedAt?: string;
  revokedReason?: string;
  signature: string; // Ed25519 signature
  createdAt: string;
}

export interface DelegationChain {
  chain: DelegationEnvelope[];
  rootSponsor: HumanSponsor;
  activeAgent: AgentIdentity;
  isValid: boolean;
  rejectionReason?: string;
}

// 4. Task & Declared Intent Model
export interface TaskIntent {
  taskId: TaskId;
  tenantId: TenantId;
  sponsorId: UserId;
  declaredPurpose: string;
  intendedCapabilities: string[];
  expectedTools: string[];
  targetCustomerId?: string;
  targetResourceId?: string;
  maxAllowedValue?: number;
  workflowState: string;
  createdAt: string;
}

// 5. Action Model
export interface ResourceDescriptor {
  id: string;
  type: string;
  ownerId?: string;
  sensitivity: ResourceSensitivity;
  environment: string;
}

export interface ActionRequest {
  actionId: ActionId;
  tenantId: TenantId;
  sessionId: SessionId;
  taskId: TaskId;
  agentId: AgentId;
  delegationId: DelegationId;
  actionType: string;
  tool: string;
  resource: ResourceDescriptor;
  parameters: Record<string, unknown>;
  parametersHash: string; // SHA-256 canonical representation
  timestamp: string;
  idempotencyKey?: string;
}

// 6. Context Model
export interface ActionContext {
  task: TaskIntent;
  delegation: DelegationEnvelope;
  sponsor: HumanSponsor;
  agent: AgentIdentity;
  workflowState: string;
  environment: string;
  externalSignals?: Record<string, unknown>;
  currentTime: string;
}

// 7. Sequence Model
export interface ActionHistoryRecord {
  actionId: ActionId;
  sessionId: SessionId;
  taskId: TaskId;
  agentId: AgentId;
  delegationId?: string; // Optional for backward compatibility; required for cross-task cumulative tracking
  actionType: string;
  tool: string;
  resourceId: string;
  parameters: Record<string, unknown>;
  decision: DecisionEffect;
  timestamp: string;
}

export interface SequenceSummary {
  sessionId: SessionId;
  taskId: TaskId;
  recentActions: string[]; // e.g. ["crm_read", "billing_read", "stripe_refund"]
  cumulativeAmounts: Record<string, number>; // e.g. { "stripe_refund": 4500 }
  actionCounts: Record<string, number>;
  firstActionTime: string;
  lastActionTime: string;
}

// 8. Cryptographic Grants & Receipts
export interface AuthorizationGrant {
  grantId: GrantId;
  actionId: ActionId;
  tenantId: TenantId;
  agentId: AgentId;
  actionType: string;
  tool: string;
  resourceId: string;
  parametersHash: string;
  delegationId: DelegationId;
  nonce: string;
  notBefore: number; // Unix epoch seconds
  expiresAt: number; // Unix epoch seconds (short TTL, e.g. 60s)
  signature: string; // Ed25519 signature of control plane
}

export interface AuthorizationReceipt {
  receiptId: ReceiptId;
  actionId: ActionId;
  grantId?: GrantId;
  tenantId: TenantId;
  agentId: AgentId;
  sponsorId: UserId;
  decision: DecisionEffect;
  actionType: string;
  resourceId: string;
  policyVersion: string;
  riskScore: number;
  reasonCodes: ReasonCode[];
  explanation: string;
  parametersHash: string;
  previousReceiptHash: string; // Hash-chaining Merkle structure
  receiptHash: string;
  timestamp: string;
  signature: string; // Ed25519 signature
}

// 9. Authorization Decision
export interface AuthorizationDecision {
  actionId: ActionId;
  decision: DecisionEffect;
  reasonCodes: ReasonCode[];
  explanation: string;
  policyVersion: string;
  riskScore: number;
  riskClass: RiskClass;
  grant?: AuthorizationGrant;
  approvalId?: ApprovalId;
  requiredApprovalRole?: string;
  receipt?: AuthorizationReceipt;
  evaluatedAt: string;
  latencyMs: number;
}

// 10. Human Approvals (Step-Up)
export interface ApprovalRequest {
  approvalId: ApprovalId;
  tenantId: TenantId;
  actionId: ActionId;
  agentId: AgentId;
  taskId: TaskId;
  actionType: string;
  resource: ResourceDescriptor;
  parameters: Record<string, unknown>;
  riskScore: number;
  requiredRole: string;
  explanation: string;
  status: 'PENDING' | 'APPROVED' | 'REJECTED' | 'EXPIRED';
  createdAt: string;
  expiresAt: string;
  decidedBy?: UserId;
  decidedAt?: string;
  decisionNotes?: string;
  oneTimeGrant?: AuthorizationGrant;
}

// 11. Security Analytics & Blast Radius
export interface BlastRadiusReport {
  agentId: AgentId;
  calculatedAt: string;
  agentStatus: AgentStatus;
  riskClass: RiskClass;
  directCapabilities: string[];
  reachableTools: {
    tool: string;
    risk: RiskClass;
    maxExposure?: number;
  }[];
  reachableResources: {
    resourceType: string;
    sensitivity: ResourceSensitivity;
    countEstimate: number;
  }[];
  reachableAgents: AgentId[];
  maximumFinancialExposure: number;
  privilegeEscalationPaths: {
    description: string;
    severity: RiskClass;
    hops: string[];
  }[];
  killSwitchActive: boolean;
}

export interface ProvenanceNode {
  id: string;
  type: 'HUMAN' | 'DELEGATION' | 'TASK' | 'AGENT' | 'POLICY' | 'ACTION' | 'RESOURCE' | 'GRANT' | 'RECEIPT';
  label: string;
  metadata: Record<string, unknown>;
}

export interface ProvenanceEdge {
  from: string;
  to: string;
  relation: string; // e.g. "SPONSORED", "DELEGATED_TO", "EVALUATED_BY", "TARGETED"
}

export interface ProvenanceGraph {
  actionId: ActionId;
  nodes: ProvenanceNode[];
  edges: ProvenanceEdge[];
  decision: DecisionEffect;
  explanation: string;
  receiptVerified: boolean;
}

// 12. Counterfactual Policy Simulation
export interface PolicySimulationRequest {
  tenantId: TenantId;
  proposedPolicyContent: string;
  targetActionType?: string;
  sampleSize?: number;
}

export interface PolicySimulationResult {
  simulationId: string;
  totalEvaluated: number;
  unchangedCount: number;
  newlyAllowedCount: number;
  newlyDeniedCount: number;
  newlyHeldCount: number;
  affectedAgents: string[];
  highRiskNewlyAllowed: {
    actionId: string;
    actionType: string;
    agentId: string;
    amount?: number;
    resourceId: string;
  }[];
  summaryText: string;
}

// 13. Workflow State Machine Model (§42, §43, §44)
export type WorkflowId = string;
export type WorkflowInstanceId = string;

export interface WorkflowTransition {
  fromState: string;
  toState: string;
  triggerEvent?: string;
  requiredRole?: string;
  requiredApprovals?: number;
  allowedActions?: string[];
}

export interface WorkflowDefinition {
  workflowId: WorkflowId;
  tenantId: TenantId;
  name: string;
  description: string;
  initialState: string;
  terminalStates: string[];
  states: string[];
  transitions: WorkflowTransition[];
  actionStateRequirements: Record<string, string[]>; // e.g. { "stripe_refund": ["APPROVED", "EXECUTION_READY"] }
}

export interface WorkflowInstance {
  instanceId: WorkflowInstanceId;
  workflowId: WorkflowId;
  tenantId: TenantId;
  taskId: TaskId;
  currentState: string;
  history: {
    fromState: string;
    toState: string;
    transitionedAt: string;
    triggeredBy: string;
    event?: string;
    metadata?: Record<string, unknown>;
  }[];
  emittedEvents: string[]; // e.g. ["fraud_check_passed", "pr_reviewed"]
  contextData: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
}

// 14. Business Invariants Model (§41)
export type InvariantId = string;

export interface BusinessInvariant {
  invariantId: InvariantId;
  tenantId: TenantId;
  name: string;
  description: string;
  targetActionType: string;
  evaluate: (action: ActionRequest, context: ActionContext, state?: WorkflowInstance) => {
    valid: boolean;
    reason?: string;
  };
}

export interface InvariantEvaluationResult {
  passed: boolean;
  violatedInvariants: {
    invariantId: InvariantId;
    name: string;
    reason: string;
  }[];
}

// 15. Declarative Policy DSL & AST Model (§22, §50, §51)
export interface PolicyCondition {
  field: string;
  operator: '==' | '!=' | '<=' | '>=' | '<' | '>' | 'IN' | 'NOT_IN' | 'CONTAINS';
  value: unknown;
  connector?: 'AND' | 'OR';
  negated?: boolean;
}

export interface PolicyAST {
  policyId: string;
  name: string;
  targetAction: string;
  conditions: PolicyCondition[];
  requireApprovalAbove?: number;
  effect: DecisionEffect;
  rawText: string;
}

export interface PolicyTestCase {
  testId: string;
  name: string;
  policyId: string;
  mockAction: ActionRequest;
  mockContext: ActionContext;
  expectedDecision: DecisionEffect;
  expectedReasonCode?: ReasonCode;
}

export interface PolicyTestReport {
  totalTests: number;
  passed: number;
  failed: number;
  results: {
    testId: string;
    name: string;
    passed: boolean;
    actualDecision: DecisionEffect;
    expectedDecision: DecisionEffect;
    error?: string;
  }[];
}

// 16. Statistical Behavioral Profiling Model (§17, §18, §31, §63)
export interface ToolCallDistribution {
  meanCallsPerHour: number;
  stdDevCallsPerHour: number;
  meanTransactionValue: number;
  stdDevTransactionValue: number;
  commonResources: string[];
}

export interface BehaviorProfile {
  agentId: AgentId;
  tenantId: TenantId;
  sampleCount: number;
  toolDistributions: Record<string, ToolCallDistribution>;
  typicalSequences: string[][]; // e.g. [["search_customers", "stripe_refund"]]
  typicalOperatingHours: {
    startHourUTC: number;
    endHourUTC: number;
  };
  lastUpdated: string;
}

export interface BehaviorAnomalyAssessment {
  agentId: AgentId;
  anomalyDetected: boolean;
  anomalyScore: number; // 0 - 100
  zScoreAmount?: number;
  zScoreFrequency?: number;
  unusualTool: boolean;
  unusualResource: boolean;
  explanation: string;
  advisoryOnly: boolean; // Advisory signal: does NOT directly block if false
}

// 17. Event Architecture Model (§74)
export type EventType =
  | 'AGENT_REGISTERED'
  | 'DELEGATION_CREATED'
  | 'ACTION_REQUESTED'
  | 'ACTION_ALLOWED'
  | 'ACTION_DENIED'
  | 'ACTION_HELD'
  | 'APPROVAL_REQUESTED'
  | 'APPROVAL_GRANTED'
  | 'APPROVAL_REJECTED'
  | 'DELEGATION_REVOKED'
  | 'AGENT_QUARANTINED'
  | 'BEHAVIOR_ANOMALY'
  | 'POLICY_CHANGED'
  | 'WORKFLOW_TRANSITIONED';

export interface ControlPlaneEvent {
  eventId: string;
  eventType: EventType;
  tenantId: TenantId;
  timestamp: string;
  producer: string;
  correlationId: string;
  payload: Record<string, unknown>;
}

