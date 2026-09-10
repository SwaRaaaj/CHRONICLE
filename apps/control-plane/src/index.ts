import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import type {
  ActionRequest,
  AuthorizationDecision,
  ApprovalRequest,
  HumanSponsor,
  AgentIdentity,
  DelegationEnvelope,
  PolicySimulationRequest,
  BlastRadiusReport,
  ProvenanceGraph,
  AuthorizationReceipt
} from '@chronicle/core-types';
import {
  generateEd25519KeyPair,
  createAuthorizationGrant,
  canonicalHash
} from '@chronicle/crypto-primitives';
import type { KeyPair } from '@chronicle/crypto-primitives';
import { DelegationManager } from '@chronicle/delegation-manager';
import { SequenceDetector } from '@chronicle/sequence-detector';
import { PolicyEngine } from '@chronicle/policy-engine';
import { AuditLedger } from '@chronicle/audit-ledger';
import { BlastRadiusAnalyzer } from '@chronicle/blast-radius';
import { parsePolicyDSL } from '@chronicle/policy-dsl';
import { ATTACK_CATALOG } from './attack-catalog.ts';
import { executeAttackVector, executeAllAttackVectors } from './attack-runner.ts';
import { ENTERPRISE_TOOL_CATALOG } from '../../mock-enterprise-tools/src/index.ts';

export class ChronicleControlPlane {
  public keyPair: KeyPair;
  public delegationManager: DelegationManager;
  public sequenceDetector: SequenceDetector;
  public policyEngine: PolicyEngine;
  public auditLedger: AuditLedger;
  public blastRadiusAnalyzer: BlastRadiusAnalyzer;

  private approvals: Map<string, ApprovalRequest> = new Map();
  private totalActionsProcessed: number = 0;
  private startTime: number = Date.now();
  /** Enforcement vs Observation mode (§3) */
  private mode: 'enforcement' | 'observation' = 'enforcement';
  /** In-memory action history for API queries */
  private actionHistory: Array<{
    actionId: string; agentId: string; tenantId: string; sessionId: string; taskId: string;
    actionType: string; tool: string; resourceId: string; decision: string;
    riskScore: number; riskClass: string; explanation: string; timestamp: string;
  }> = [];

  constructor() {
    // Generate Master Control Plane Ed25519 Keypair
    this.keyPair = generateEd25519KeyPair();

    this.delegationManager = new DelegationManager();
    this.sequenceDetector = new SequenceDetector();
    this.policyEngine = new PolicyEngine(
      this.delegationManager,
      this.sequenceDetector,
      this.keyPair.privateKey
    );
    this.auditLedger = new AuditLedger(this.keyPair.privateKey, this.keyPair.publicKey);
    this.blastRadiusAnalyzer = new BlastRadiusAnalyzer(this.delegationManager);

    this.seedDefaultEnvironment();
  }

  /**
   * Seed enterprise human sponsors, agents, and default delegation envelopes.
   */
  public seedDefaultEnvironment(): void {
    const sponsorKeys = generateEd25519KeyPair();
    const defaultSponsor: HumanSponsor = {
      userId: 'user_ciso_jane',
      tenantId: 'tenant_acme',
      name: 'Jane Doe (CISO)',
      email: 'jane.ciso@acmecorp.com',
      role: 'CISO',
      department: 'Security & Trust',
      publicKey: sponsorKeys.publicKey,
      createdAt: new Date().toISOString()
    };
    this.delegationManager.registerSponsor(defaultSponsor);

    // 1. Finance Agent
    const financeAgentKeys = generateEd25519KeyPair();
    const financeAgent: AgentIdentity = {
      agentId: 'agent_finance_refund',
      tenantId: 'tenant_acme',
      name: 'Finance Refund Agent',
      agentType: 'FINANCIAL_OPS',
      agentVersion: 'v2.1',
      modelProvider: 'anthropic/claude-3.5-sonnet',
      owner: defaultSponsor.userId,
      sponsor: defaultSponsor.userId,
      creationTime: new Date().toISOString(),
      status: 'ACTIVE',
      environment: 'production',
      riskClass: 'HIGH',
      allowedCapabilities: ['stripe_refund', 'search_customers'],
      publicKey: financeAgentKeys.publicKey
    };
    this.delegationManager.registerAgent(financeAgent);

    // Issue Delegation for Finance Agent: Max transaction $1,000, cumulative $10,000
    this.delegationManager.createDelegation(
      {
        delegationId: 'del_finance_refund_root',
        tenantId: 'tenant_acme',
        delegatorType: 'HUMAN',
        delegatorId: defaultSponsor.userId,
        delegateeId: financeAgent.agentId,
        taskId: 'task_customer_refunds',
        purpose: 'Execute authorized customer refunds up to policy limit',
        constraints: {
          allowedTools: ['stripe_refund', 'search_customers'],
          resourcePatterns: ['ch:*', 'ch_*', 'charge:*', 'charge_*', 'cust:*', 'cust_*'],
          maxTransactionValue: 5000,
          cumulativeValueLimit: 10000,
          requireApprovalAbove: 1000,
          temporalValiditySeconds: 86400
        },
        notBefore: new Date(Date.now() - 60000).toISOString(),
        expiresAt: new Date(Date.now() + 86400000).toISOString()
      },
      sponsorKeys.privateKey
    );


    // 2. Customer Support Agent
    const supportAgentKeys = generateEd25519KeyPair();
    const supportAgent: AgentIdentity = {
      agentId: 'agent_support_general',
      tenantId: 'tenant_acme',
      name: 'Customer Support Agent',
      agentType: 'TIER_1_SUPPORT',
      agentVersion: 'v1.0',
      modelProvider: 'openai/gpt-4o',
      owner: defaultSponsor.userId,
      sponsor: defaultSponsor.userId,
      creationTime: new Date().toISOString(),
      status: 'ACTIVE',
      environment: 'production',
      riskClass: 'MEDIUM',
      allowedCapabilities: ['search_customers', 'read_customer_pii', 'update_customer_record'],
      publicKey: supportAgentKeys.publicKey
    };
    this.delegationManager.registerAgent(supportAgent);

    this.delegationManager.createDelegation(
      {
        delegationId: 'del_support_general_root',
        tenantId: 'tenant_acme',
        delegatorType: 'HUMAN',
        delegatorId: defaultSponsor.userId,
        delegateeId: supportAgent.agentId,
        taskId: 'task_support_inquiries',
        purpose: 'Resolve customer support queries',
        constraints: {
          allowedTools: ['search_customers', 'read_customer_pii', 'update_customer_record'],
          resourcePatterns: ['cust:*', 'cust_*'],
          temporalValiditySeconds: 86400
        },
        notBefore: new Date(Date.now() - 60000).toISOString(),
        expiresAt: new Date(Date.now() + 86400000).toISOString()
      },
      sponsorKeys.privateKey
    );


    // 3. DevOps Infrastructure Agent
    const devopsAgentKeys = generateEd25519KeyPair();
    const devopsAgent: AgentIdentity = {
      agentId: 'agent_infra_devops',
      tenantId: 'tenant_acme',
      name: 'DevOps Automated Agent',
      agentType: 'INFRASTRUCTURE',
      agentVersion: 'v3.0',
      modelProvider: 'anthropic/claude-3.5-sonnet',
      owner: defaultSponsor.userId,
      sponsor: defaultSponsor.userId,
      creationTime: new Date().toISOString(),
      status: 'ACTIVE',
      environment: 'production',
      riskClass: 'CRITICAL',
      allowedCapabilities: ['deploy_container', 'modify_security_group', 'query_production_database'],
      publicKey: devopsAgentKeys.publicKey
    };
    this.delegationManager.registerAgent(devopsAgent);

    this.delegationManager.createDelegation(
      {
        delegationId: 'del_devops_infra_root',
        tenantId: 'tenant_acme',
        delegatorType: 'HUMAN',
        delegatorId: defaultSponsor.userId,
        delegateeId: devopsAgent.agentId,
        taskId: 'task_infra_maintenance',
        purpose: 'Maintain production cloud infrastructure',
        constraints: {
          allowedTools: ['deploy_container', 'modify_security_group', 'query_production_database'],
          resourcePatterns: ['k8s:*', 'sg:*', 'db:*'],
          temporalValiditySeconds: 86400
        },
        notBefore: new Date(Date.now() - 60000).toISOString(),
        expiresAt: new Date(Date.now() + 86400000).toISOString()
      },
      sponsorKeys.privateKey
    );
  }

  /**
   * Main Authorization Pipeline:
   * Evaluate request -> Generate receipt -> Record in audit ledger & sequence detector.
   */
  public async authorizeAction(request: ActionRequest): Promise<AuthorizationDecision> {
    this.totalActionsProcessed++;

    // 1. Evaluate with Policy Engine
    const decision = await this.policyEngine.evaluate(request);

    // 2. If HOLD, create Step-Up Approval record
    if (decision.decision === 'HOLD' && decision.approvalId) {
      const approval: ApprovalRequest = {
        approvalId: decision.approvalId,
        tenantId: request.tenantId,
        actionId: request.actionId,
        agentId: request.agentId,
        taskId: request.taskId,
        actionType: request.actionType,
        resource: request.resource,
        parameters: request.parameters,
        riskScore: decision.riskScore,
        requiredRole: decision.requiredApprovalRole || 'FINANCE_SPONSOR',
        explanation: decision.explanation,
        status: 'PENDING',
        createdAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 1800000).toISOString() // 30 minutes
      };
      this.approvals.set(approval.approvalId, approval);
    }

    // 3. Record in Merkle-chained Cryptographic Audit Ledger
    const receipt = this.auditLedger.recordDecision(
      request,
      decision,
      'user_ciso_jane' // Sponsor ID
    );
    decision.receipt = receipt;

    // 4. Record action in Sequence Detector history (with delegationId for global cumulative tracking)
    this.sequenceDetector.recordAction({
      actionId: request.actionId,
      sessionId: request.sessionId,
      taskId: request.taskId,
      agentId: request.agentId,
      delegationId: request.delegationId,
      actionType: request.actionType,
      tool: request.tool,
      resourceId: request.resource.id,
      parameters: request.parameters,
      decision: decision.decision,
      timestamp: request.timestamp
    });

    // 5. Record in action history for API queries
    this.actionHistory.push({
      actionId: request.actionId,
      agentId: request.agentId,
      tenantId: request.tenantId,
      sessionId: request.sessionId,
      taskId: request.taskId,
      actionType: request.actionType,
      tool: request.tool,
      resourceId: request.resource.id,
      decision: this.mode === 'observation' ? 'OBSERVED' : decision.decision,
      riskScore: decision.riskScore,
      riskClass: decision.riskClass,
      explanation: decision.explanation,
      timestamp: request.timestamp
    });

    // 6. In observation mode: override blocking decisions to ALLOW but tag as OBSERVED
    if (this.mode === 'observation' && (decision.decision === 'DENY' || decision.decision === 'HOLD')) {
      return {
        ...decision,
        decision: 'ALLOW' as const,
        reasonCodes: ['POLICY_PERMIT'],
        explanation: `[OBSERVATION MODE] Would have been ${decision.decision}: ${decision.explanation}`,
        observationNote: `Original decision: ${decision.decision}. System is in observation mode — no enforcement.`
      };
    }

    return decision;
  }

  /**
   * Human Step-Up Approval Decision Handler:
   * Human sponsor approves or rejects an action on HOLD.
   */
  public decideApproval(
    approvalId: string,
    approved: boolean,
    decidedBy: string,
    notes?: string
  ): { approval: ApprovalRequest; grant?: unknown } | null {
    const approval = this.approvals.get(approvalId);
    if (!approval) return null;

    approval.status = approved ? 'APPROVED' : 'REJECTED';
    approval.decidedBy = decidedBy;
    approval.decidedAt = new Date().toISOString();
    approval.decisionNotes = notes;

    if (approved) {
      // Issue one-time grant for the held action
      const grantId = 'grant_appr_' + Math.random().toString(36).substring(2, 10);
      const paramsHash = canonicalHash(approval.parameters);
      const grant = createAuthorizationGrant(
        grantId,
        approval.actionId,
        approval.tenantId,
        approval.agentId,
        approval.actionType,
        approval.actionType,
        approval.resource.id,
        paramsHash,
        'del_finance_refund_root',
        this.keyPair.privateKey,
        300 // 5 minutes TTL
      );
      approval.oneTimeGrant = grant;
      return { approval, grant };
    }

    return { approval };
  }

  public getPendingApprovals(): ApprovalRequest[] {
    return Array.from(this.approvals.values()).filter(a => a.status === 'PENDING');
  }

  public getMode(): 'enforcement' | 'observation' { return this.mode; }
  public setMode(mode: 'enforcement' | 'observation'): void { this.mode = mode; }

  public getStatus(): {
    status: string;
    mode: string;
    uptimeSeconds: number;
    totalActions: number;
    killSwitchActive: boolean;
    publicKey: string;
    activeDelegations: number;
    registeredAgents: number;
    pendingApprovals: number;
    auditReceiptsCount: number;
    ledgerIntegrity: { valid: boolean; totalReceipts: number };
  } {
    const integrity = this.auditLedger.verifyIntegrity();
    return {
      status: 'HEALTHY',
      mode: this.mode,
      uptimeSeconds: Math.floor((Date.now() - this.startTime) / 1000),
      totalActions: this.totalActionsProcessed,
      killSwitchActive: false,
      publicKey: this.keyPair.publicKey,
      activeDelegations: this.delegationManager.listDelegations().filter(d => !d.revoked).length,
      registeredAgents: this.delegationManager.listAgents().length,
      pendingApprovals: this.getPendingApprovals().length,
      auditReceiptsCount: this.auditLedger.getReceipts().length,
      ledgerIntegrity: { valid: integrity.valid, totalReceipts: integrity.totalReceipts }
    };
  }

  /**
   * Create Node HTTP Server to serve API and Dashboard UI.
   */
  public createHttpServer(port: number = 3000): http.Server {
    const server = http.createServer(async (req, res) => {
      const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);

      // CORS
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

      if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
      }

      // 1. Dashboard UI
      if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
        const htmlPath = path.resolve('apps/control-plane/public/index.html');
        if (fs.existsSync(htmlPath)) {
          const html = fs.readFileSync(htmlPath, 'utf8');
          res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
          res.end(html);
          return;
        }
      }

      // 2. Health & Status
      if (req.method === 'GET' && url.pathname === '/api/v1/status') {
        const status = this.getStatus();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(status));
        return;
      }

      // 3. Main Authorization API
      if (req.method === 'POST' && url.pathname === '/api/v1/authorize') {
        let body = '';
        req.on('data', c => { body += c; });
        req.on('end', async () => {
          try {
            const actionRequest: ActionRequest = JSON.parse(body);
            const decision = await this.authorizeAction(actionRequest);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(decision, null, 2));
          } catch (err: unknown) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: (err as Error).message }));
          }
        });
        return;
      }

      // 4. Approvals List
      if (req.method === 'GET' && url.pathname === '/api/v1/approvals') {
        const pending = this.getPendingApprovals();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(pending));
        return;
      }

      // 5. Decide Approval
      if (req.method === 'POST' && url.pathname.startsWith('/api/v1/approvals/') && url.pathname.endsWith('/decide')) {
        const parts = url.pathname.split('/');
        const approvalId = parts[parts.length - 2];
        let body = '';
        req.on('data', c => { body += c; });
        req.on('end', () => {
          try {
            const { approved, sponsorId, notes } = JSON.parse(body);
            const result = this.decideApproval(approvalId, approved, sponsorId, notes);
            if (!result) {
              res.writeHead(404, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ error: 'Approval not found' }));
              return;
            }
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(result));
          } catch (err: unknown) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: (err as Error).message }));
          }
        });
        return;
      }

      // 6. Audit Receipts
      if (req.method === 'GET' && url.pathname === '/api/v1/audit/receipts') {
        const receipts = this.auditLedger.getReceipts();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(receipts));
        return;
      }

      // 7. Audit Integrity Verification
      if (req.method === 'GET' && url.pathname === '/api/v1/audit/verify') {
        const verification = this.auditLedger.verifyIntegrity();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(verification));
        return;
      }

      // 8. Blast Radius Report
      if (req.method === 'GET' && url.pathname.startsWith('/api/v1/analytics/blast-radius/')) {
        const agentId = url.pathname.split('/').pop()!;
        const report = this.blastRadiusAnalyzer.calculateBlastRadius(agentId);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(report));
        return;
      }

      // 9. Provenance DAG
      if (req.method === 'GET' && url.pathname.startsWith('/api/v1/analytics/provenance/')) {
        const actionId = url.pathname.split('/').pop()!;
        const graph = this.auditLedger.buildProvenanceGraph(actionId);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(graph));
        return;
      }

      // 10. Policy Simulator
      if (req.method === 'POST' && url.pathname === '/api/v1/policies/simulate') {
        let body = '';
        req.on('data', c => { body += c; });
        req.on('end', () => {
          try {
            const simReq: PolicySimulationRequest = JSON.parse(body);
            // Convert receipts to action history records for simulation
            const history = this.auditLedger.getReceipts().map(r => ({
              actionId: r.actionId,
              sessionId: 'sess_sim',
              taskId: 'task_sim',
              agentId: r.agentId,
              actionType: r.actionType,
              tool: r.actionType,
              resourceId: r.resourceId,
              parameters: { amount: r.riskScore * 15 },
              decision: r.decision,
              timestamp: r.timestamp
            }));

            const result = this.policyEngine.simulatePolicy(simReq, history);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(result));
          } catch (err: unknown) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: (err as Error).message }));
          }
        });
        return;
      }

      // 11. Emergency Kill Switch / Quarantine
      if (req.method === 'POST' && url.pathname === '/api/v1/kill-switch') {
        let body = '';
        req.on('data', c => { body += c; });
        req.on('end', () => {
          try {
            const { active, agentId } = JSON.parse(body);
            if (agentId) {
              if (active) this.policyEngine.quarantineAgent(agentId);
              else this.policyEngine.unquarantineAgent(agentId);
              res.writeHead(200, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ agentId, quarantined: active }));
              return;
            }
            this.policyEngine.setKillSwitch(!!active);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ active: !!active, message: active ? 'GLOBAL LOCKDOWN ENGAGED' : 'OPERATIONAL' }));
          } catch (err: unknown) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: (err as Error).message }));
          }
        });
        return;
      }

      // 12. Kill Switch / Quarantine (alternate route)
      if (req.method === 'POST' && url.pathname === '/api/v1/kill-switch/quarantine') {
        let body = '';
        req.on('data', c => { body += c; });
        req.on('end', () => {
          try {
            const { agentId, quarantine } = JSON.parse(body);
            if (quarantine) this.policyEngine.quarantineAgent(agentId);
            else this.policyEngine.unquarantineAgent(agentId);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ agentId, quarantined: quarantine }));
          } catch (err: unknown) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: (err as Error).message }));
          }
        });
        return;
      }

      // === Phase 8–12 New Endpoints ===

      // 13. Enforcement / Observation mode toggle (§3)
      if (req.method === 'POST' && url.pathname === '/api/v1/mode') {
        let body = '';
        req.on('data', c => { body += c; });
        req.on('end', () => {
          try {
            const { mode } = JSON.parse(body) as { mode: 'enforcement' | 'observation' };
            if (mode !== 'enforcement' && mode !== 'observation') {
              res.writeHead(400, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ error: 'mode must be enforcement or observation' }));
              return;
            }
            this.setMode(mode);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ mode, message: `Control plane switched to ${mode.toUpperCase()} mode` }));
          } catch (err: unknown) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: (err as Error).message }));
          }
        });
        return;
      }

      if (req.method === 'GET' && url.pathname === '/api/v1/mode') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ mode: this.getMode() }));
        return;
      }

      // 14. Agent Registry — List all agents (§79)
      if (req.method === 'GET' && url.pathname === '/api/v1/agents') {
        const agents = this.delegationManager.listAgents();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(agents));
        return;
      }

      // 15. Agent Detail (§79)
      if (req.method === 'GET' && url.pathname.match(/^\/api\/v1\/agents\/[^/]+$/)) {
        const agentId = url.pathname.split('/').pop()!;
        const agent = this.delegationManager.getAgent(agentId);
        if (!agent) {
          res.writeHead(404, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: `Agent '${agentId}' not found` }));
          return;
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(agent));
        return;
      }

      // 16. Register Agent (§79)
      if (req.method === 'POST' && url.pathname === '/api/v1/agents') {
        let body = '';
        req.on('data', c => { body += c; });
        req.on('end', () => {
          try {
            const agent = JSON.parse(body);
            this.delegationManager.registerAgent(agent);
            res.writeHead(201, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ registered: true, agentId: agent.agentId }));
          } catch (err: unknown) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: (err as Error).message }));
          }
        });
        return;
      }

      // 17. Agent Capabilities (§79)
      if (req.method === 'GET' && url.pathname.match(/^\/api\/v1\/agents\/[^/]+\/capabilities$/)) {
        const parts = url.pathname.split('/');
        const agentId = parts[parts.length - 2];
        const agent = this.delegationManager.getAgent(agentId);
        if (!agent) {
          res.writeHead(404, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: `Agent '${agentId}' not found` }));
          return;
        }
        const delegations = this.delegationManager.listDelegations().filter(d => d.delegateeId === agentId && !d.revoked);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          agentId,
          allowedCapabilities: agent.allowedCapabilities,
          delegations: delegations.map(d => ({
            delegationId: d.delegationId, purpose: d.purpose,
            constraints: d.constraints, expiresAt: d.expiresAt
          }))
        }));
        return;
      }

      // 18. Delegation List (§79)
      if (req.method === 'GET' && url.pathname === '/api/v1/delegations') {
        const delegations = this.delegationManager.listDelegations();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(delegations));
        return;
      }

      // 19. Revoke Delegation (§79)
      if (req.method === 'POST' && url.pathname.match(/^\/api\/v1\/delegations\/[^/]+\/revoke$/)) {
        const parts = url.pathname.split('/');
        const delegationId = parts[parts.length - 2];
        let body = '';
        req.on('data', c => { body += c; });
        req.on('end', () => {
          try {
            const { reason } = JSON.parse(body) as { reason: string };
            const result = this.delegationManager.revokeDelegation(delegationId, reason || 'API revocation');
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ delegationId, revokedCount: result.revokedCount }));
          } catch (err: unknown) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: (err as Error).message }));
          }
        });
        return;
      }

      // 20. Action History List (§79)
      if (req.method === 'GET' && url.pathname === '/api/v1/actions') {
        const limit = parseInt(url.searchParams.get('limit') || '100');
        const agentFilter = url.searchParams.get('agentId');
        let history = [...this.actionHistory].reverse(); // newest first
        if (agentFilter) history = history.filter(h => h.agentId === agentFilter);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(history.slice(0, limit)));
        return;
      }

      // 21. Action Detail (§79)
      if (req.method === 'GET' && url.pathname.match(/^\/api\/v1\/actions\/[^/]+$/) && !url.pathname.endsWith('/provenance')) {
        const actionId = url.pathname.split('/').pop()!;
        const action = this.actionHistory.find(h => h.actionId === actionId);
        if (!action) {
          res.writeHead(404, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: `Action '${actionId}' not found` }));
          return;
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(action));
        return;
      }

      // 22. Action Provenance Graph (§79) — alias of analytics route
      if (req.method === 'GET' && url.pathname.match(/^\/api\/v1\/actions\/[^/]+\/provenance$/)) {
        const parts = url.pathname.split('/');
        const actionId = parts[parts.length - 2];
        const graph = this.auditLedger.buildProvenanceGraph(actionId);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(graph));
        return;
      }

      // 23. Simulate Agent Compromise Blast Radius (§79)
      if (req.method === 'POST' && url.pathname === '/api/v1/simulate/agent') {
        let body = '';
        req.on('data', c => { body += c; });
        req.on('end', () => {
          try {
            const { agentId } = JSON.parse(body);
            const report = this.blastRadiusAnalyzer.calculateBlastRadius(agentId);
            const attackPaths = this.blastRadiusAnalyzer.computeAttackPaths(agentId);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ blastRadius: report, attackPaths }));
          } catch (err: unknown) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: (err as Error).message }));
          }
        });
        return;
      }

      // 24. Attack Path Analysis (§79)
      if (req.method === 'POST' && url.pathname === '/api/v1/simulate/attack-path') {
        let body = '';
        req.on('data', c => { body += c; });
        req.on('end', () => {
          try {
            const { agentId } = JSON.parse(body);
            const attackPaths = this.blastRadiusAnalyzer.computeAttackPaths(agentId);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ agentId, attackPaths }));
          } catch (err: unknown) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: (err as Error).message }));
          }
        });
        return;
      }

      // 25. Shadow Policy Comparator (§79)
      if (req.method === 'POST' && url.pathname === '/api/v1/policies/shadow') {
        let body = '';
        req.on('data', c => { body += c; });
        req.on('end', () => {
          try {
            const { currentPolicy, proposedPolicy } = JSON.parse(body);
            const history = this.actionHistory.map(h => ({
              actionId: h.actionId, agentId: h.agentId, actionType: h.actionType,
              sessionId: h.sessionId, taskId: h.taskId, tool: h.tool,
              resourceId: h.resourceId,
              parameters: { amount: h.riskScore * 10 },
              decision: h.decision as 'ALLOW' | 'DENY' | 'HOLD',
              timestamp: h.timestamp
            }));
            const currentResult = this.policyEngine.simulatePolicy({ proposedPolicyContent: JSON.stringify(currentPolicy || {}) }, history);
            const proposedResult = this.policyEngine.simulatePolicy({ proposedPolicyContent: JSON.stringify(proposedPolicy || {}) }, history);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              current: currentResult,
              proposed: proposedResult,
              divergence: {
                newlyAllowed: proposedResult.newlyAllowedCount - currentResult.newlyAllowedCount,
                newlyDenied: proposedResult.newlyDeniedCount - currentResult.newlyDeniedCount,
                newlyHeld: proposedResult.newlyHeldCount - currentResult.newlyHeldCount
              }
            }));
          } catch (err: unknown) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: (err as Error).message }));
          }
        });
        return;
      }

      // 26. Behavioral Profile (§79)
      if (req.method === 'GET' && url.pathname.match(/^\/api\/v1\/behavior\/[^/]+$/)) {
        const agentId = url.pathname.split('/').pop()!;
        const behaviorEngine = this.policyEngine.getBehaviorEngine();
        const profile = behaviorEngine.getProfile(agentId);
        const agentActions = this.actionHistory.filter(h => h.agentId === agentId);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          agentId,
          profile: profile || null,
          recentActions: agentActions.slice(-20),
          totalActions: agentActions.length,
          anomalyStatus: profile ? 'PROFILED' : 'INSUFFICIENT_DATA'
        }));
        return;
      }

      // 27. Security Incidents List (§79)
      if (req.method === 'GET' && url.pathname === '/api/v1/incidents') {
        const incidents = this.actionHistory
          .filter(h => h.decision === 'DENY' && h.riskScore >= 80)
          .slice(-50)
          .reverse()
          .map(h => ({
            incidentId: `inc_${h.actionId}`,
            agentId: h.agentId,
            tool: h.tool,
            riskScore: h.riskScore,
            riskClass: h.riskClass,
            decision: h.decision,
            explanation: h.explanation,
            timestamp: h.timestamp
          }));
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(incidents));
        return;
      }

      // 28. Adversarial Attack Catalog (§106, §107)
      if (req.method === 'GET' && url.pathname === '/api/v1/attacks') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(ATTACK_CATALOG));
        return;
      }

      // 29. Simulate Adversarial Attack Vector (§106, §107)
      if (req.method === 'POST' && url.pathname === '/api/v1/simulate/attack') {
        let body = '';
        req.on('data', c => { body += c; });
        req.on('end', async () => {
          try {
            const payload = body ? JSON.parse(body) : {};
            const { vectorNumber } = payload;
            if (vectorNumber === 'all' || vectorNumber === undefined) {
              const results = await executeAllAttackVectors(this);
              const totalNeutralized = results.filter(r => r.blocked).length;
              res.writeHead(200, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({
                success: true,
                totalExecuted: results.length,
                totalNeutralized,
                allNeutralized: totalNeutralized === results.length,
                results
              }));
              return;
            }

            const num = Number(vectorNumber);
            if (isNaN(num) || num < 1 || num > 14) {
              res.writeHead(400, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ error: 'Vector number must be an integer between 1 and 14 or "all"' }));
              return;
            }

            const result = await executeAttackVector(this, num);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              success: true,
              result,
              results: [result],
              totalExecuted: 1,
              totalNeutralized: result.blocked ? 1 : 0,
              allNeutralized: result.blocked
            }));
          } catch (err: unknown) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: (err as Error).message }));
          }
        });
        return;
      }

      // 30. Enterprise Tool Catalog (§80, §106)
      if (req.method === 'GET' && url.pathname === '/api/v1/tools') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(ENTERPRISE_TOOL_CATALOG));
        return;
      }

      // 31. Policy DSL Compiler & Validator (§22, §50, §51)
      if (req.method === 'POST' && url.pathname === '/api/v1/policies/compile') {
        let body = '';
        req.on('data', c => { body += c; });
        req.on('end', () => {
          try {
            const { dsl } = JSON.parse(body);
            if (!dsl || typeof dsl !== 'string') {
              res.writeHead(400, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ error: 'Missing or invalid "dsl" field' }));
              return;
            }
            const ast = parsePolicyDSL(dsl);
            const responseData = JSON.stringify({
              valid: true,
              policyName: ast.name || ast.policyId,
              targetAction: ast.targetAction,
              ast,
              compiledAt: new Date().toISOString()
            });
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(responseData);
          } catch (err: unknown) {
            if (!res.headersSent) {
              res.writeHead(400, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ valid: false, error: (err as Error).message }));
            }
          }
        });
        return;
      }

      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Endpoint not found' }));
    });

    return server;
  }
}

// Standalone runner
if (process.argv[1]?.endsWith('control-plane/src/index.ts')) {
  const controlPlane = new ChronicleControlPlane();
  const server = controlPlane.createHttpServer(3000);
  server.listen(3000, () => {
    console.log('[Chronicle Control Plane] Online at http://localhost:3000');
    console.log('[Chronicle Control Plane] Dashboard available at http://localhost:3000/');
  });
}
