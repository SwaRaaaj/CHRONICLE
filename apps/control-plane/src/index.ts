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

    // Issue Delegation for Finance Agent: Max transaction $1,000, cumulative $5,000
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
          resourcePatterns: ['charge:*', 'cust:*'],
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
          resourcePatterns: ['cust:*'],
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

    // 4. Record action in Sequence Detector history
    this.sequenceDetector.recordAction({
      actionId: request.actionId,
      sessionId: request.sessionId,
      taskId: request.taskId,
      agentId: request.agentId,
      actionType: request.actionType,
      tool: request.tool,
      resourceId: request.resource.id,
      parameters: request.parameters,
      decision: decision.decision,
      timestamp: request.timestamp
    });

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

  public getStatus(): {
    status: string;
    uptimeSeconds: number;
    totalActions: number;
    killSwitchActive: boolean;
    publicKey: string;
  } {
    return {
      status: 'HEALTHY',
      uptimeSeconds: Math.floor((Date.now() - this.startTime) / 1000),
      totalActions: this.totalActionsProcessed,
      killSwitchActive: false, // will reflect policy engine
      publicKey: this.keyPair.publicKey
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
