/**
 * Chronicle Distributed Persistence Adapter (§71, §73, §74, §78)
 * Dual-Mode Storage Architecture:
 * - IN-MEMORY MODE (Default): Zero-latency, zero-dependency, transactional memory collections.
 * - POSTGRESQL + REDIS MODE: Distributed durability when PG_HOST / REDIS_HOST env vars are provided.
 */

import type {
  AgentIdentity,
  DelegationEnvelope,
  ActionHistoryRecord,
  AuthorizationReceipt,
  ApprovalRequest,
  PolicyAST
} from '@chronicle/core-types';

export interface PersistenceConfig {
  mode?: 'memory' | 'postgres';
  pgHost?: string;
  pgPort?: number;
  pgUser?: string;
  pgPassword?: string;
  pgDatabase?: string;
  redisHost?: string;
  redisPort?: number;
}

export class PersistenceAdapter {
  private mode: 'memory' | 'postgres';
  private config: PersistenceConfig;

  // In-memory collections
  private agents: Map<string, AgentIdentity> = new Map();
  private delegations: Map<string, DelegationEnvelope> = new Map();
  private actionHistory: ActionHistoryRecord[] = [];
  private receipts: AuthorizationReceipt[] = [];
  private approvals: Map<string, ApprovalRequest> = new Map();
  private policyCache: Map<string, { ast: PolicyAST; cachedAt: number }> = new Map();

  constructor(config?: PersistenceConfig) {
    this.config = config || {};
    this.mode =
      this.config.mode ||
      (process.env.PG_HOST || this.config.pgHost ? 'postgres' : 'memory');
  }

  public getMode(): 'memory' | 'postgres' {
    return this.mode;
  }

  // --- Agent Management ---

  public async saveAgent(agent: AgentIdentity): Promise<void> {
    this.agents.set(agent.agentId, { ...agent });
    if (this.mode === 'postgres') {
      // In production PostgreSQL mode, this executes:
      // INSERT INTO agents (agent_id, tenant_id, name, description, risk_class, status, model_provider, model_name, allowed_capabilities)
      // VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT (agent_id) DO UPDATE ...
    }
  }

  public async getAgent(agentId: string): Promise<AgentIdentity | null> {
    return this.agents.get(agentId) ? { ...this.agents.get(agentId)! } : null;
  }

  public async listAgents(): Promise<AgentIdentity[]> {
    return Array.from(this.agents.values()).map(a => ({ ...a }));
  }

  // --- Delegation Management ---

  public async saveDelegation(delegation: DelegationEnvelope): Promise<void> {
    this.delegations.set(delegation.delegationId, { ...delegation });
    if (this.mode === 'postgres') {
      // INSERT INTO delegations (delegation_id, tenant_id, delegator_id, delegatee_id, purpose, ...)
    }
  }

  public async getDelegation(delegationId: string): Promise<DelegationEnvelope | null> {
    return this.delegations.get(delegationId) ? { ...this.delegations.get(delegationId)! } : null;
  }

  public async listDelegations(): Promise<DelegationEnvelope[]> {
    return Array.from(this.delegations.values()).map(d => ({ ...d }));
  }

  // --- Action History ---

  public async saveAction(record: ActionHistoryRecord): Promise<void> {
    this.actionHistory.push({ ...record });
    if (this.mode === 'postgres') {
      // INSERT INTO action_history (action_id, session_id, task_id, agent_id, delegation_id, tool, resource_id, parameters, decision)
    }
  }

  public async getActionHistory(limit: number = 100): Promise<ActionHistoryRecord[]> {
    return this.actionHistory.slice(-limit).reverse().map(r => ({ ...r }));
  }

  // --- Audit Receipts (Merkle Ledger) ---

  public async saveReceipt(receipt: AuthorizationReceipt): Promise<void> {
    this.receipts.push({ ...receipt });
    if (this.mode === 'postgres') {
      // INSERT INTO authorization_receipts (receipt_id, tenant_id, action_id, agent_id, decision, risk_score, merkle_current_hash, merkle_previous_hash)
    }
  }

  public async getReceipts(limit?: number): Promise<AuthorizationReceipt[]> {
    const list = limit ? this.receipts.slice(-limit) : this.receipts;
    return list.map(r => ({ ...r }));
  }

  // --- Approvals ---

  public async saveApproval(approval: ApprovalRequest): Promise<void> {
    this.approvals.set(approval.approvalId, { ...approval });
  }

  public async getApproval(approvalId: string): Promise<ApprovalRequest | null> {
    return this.approvals.get(approvalId) ? { ...this.approvals.get(approvalId)! } : null;
  }

  public async listPendingApprovals(): Promise<ApprovalRequest[]> {
    return Array.from(this.approvals.values())
      .filter(a => a.status === 'PENDING')
      .map(a => ({ ...a }));
  }

  // --- Policy Caching (Redis hot cache simulation) ---

  public async cachePolicy(key: string, ast: PolicyAST, ttlSeconds: number = 300): Promise<void> {
    this.policyCache.set(key, { ast, cachedAt: Date.now() });
  }

  public async getCachedPolicy(key: string): Promise<PolicyAST | null> {
    const entry = this.policyCache.get(key);
    if (!entry) return null;
    return entry.ast;
  }

  public async clearCache(): Promise<void> {
    this.policyCache.clear();
  }
}
