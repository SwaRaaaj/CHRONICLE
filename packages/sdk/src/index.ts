/**
 * Chronicle Developer Client SDK (§80)
 * Official TypeScript SDK for autonomous agent developers, enterprise gateways,
 * and downstream tool verification.
 */

import type {
  ActionRequest,
  AuthorizationDecision,
  AuthorizationGrant,
  BlastRadiusReport,
  ProvenanceGraph,
  DecisionEffect,
  TenantId,
  AgentId,
} from '@chronicle/core-types';
import {
  canonicalHash,
  verifyAuthorizationGrant,
} from '@chronicle/crypto-primitives';

export interface ChronicleClientConfig {
  endpoint: string; // e.g. "http://localhost:3000"
  tenantId: TenantId;
  controlPlanePublicKey?: string; // For offline local grant verification
  failClosed?: boolean; // Default true (§54)
  timeoutMs?: number;
}

export interface AuthorizeActionParams {
  agentId: AgentId;
  delegationId?: string;
  taskId?: string;
  sessionId?: string;
  actionType: string;
  tool: string;
  resourceId: string;
  resourceSensitivity?: 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'SENSITIVE' | 'CRITICAL';
  resourceEnvironment?: string;
  parameters: Record<string, unknown>;
}

export class ChronicleClient {
  private endpoint: string;
  private tenantId: TenantId;
  private controlPlanePublicKey?: string;
  private failClosed: boolean;
  private timeoutMs: number;

  constructor(config: ChronicleClientConfig) {
    this.endpoint = config.endpoint.replace(/\/$/, '');
    this.tenantId = config.tenantId;
    this.controlPlanePublicKey = config.controlPlanePublicKey;
    this.failClosed = config.failClosed ?? true;
    this.timeoutMs = config.timeoutMs ?? 5000;
  }

  /**
   * Request transaction-level runtime authorization from Chronicle (§11, §80)
   */
  public async authorize(params: AuthorizeActionParams): Promise<AuthorizationDecision> {
    const actionId = `act_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
    const parametersHash = canonicalHash(params.parameters);

    const requestPayload: ActionRequest = {
      actionId,
      tenantId: this.tenantId,
      sessionId: params.sessionId || `sess_${this.tenantId}`,
      taskId: params.taskId || `task_${params.agentId}`,
      agentId: params.agentId,
      delegationId: params.delegationId || `del_${params.agentId}_root`,
      actionType: params.actionType,
      tool: params.tool,
      resource: {
        id: params.resourceId,
        type: params.tool.split('_')[0] || 'resource',
        sensitivity: params.resourceSensitivity || 'CONFIDENTIAL',
        environment: params.resourceEnvironment || 'production',
      },
      parameters: params.parameters,
      parametersHash,
      timestamp: new Date().toISOString(),
    };

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), this.timeoutMs);

      const response = await fetch(`${this.endpoint}/api/v1/authorize`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Chronicle-Tenant': this.tenantId,
        },
        body: JSON.stringify(requestPayload),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        throw new Error(`Chronicle Control Plane returned HTTP ${response.status}: ${await response.text()}`);
      }

      const decision: AuthorizationDecision = await response.json();
      return decision;
    } catch (err: unknown) {
      if (this.failClosed) {
        // Strict Fail-Closed default posture (§54, §78)
        return {
          actionId,
          decision: 'DENY',
          reasonCodes: ['POLICY_DENY'],
          explanation: `Chronicle Control Plane unreachable (${(err as Error).message}). Failed closed according to zero-trust policy.`,
          policyVersion: 'fail-closed-fallback',
          riskScore: 100,
          riskClass: 'CRITICAL',
          evaluatedAt: new Date().toISOString(),
          latencyMs: 0,
        };
      }
      throw err;
    }
  }

  /**
   * Local verification of an AuthorizationGrant against payload and public key (§24, §111)
   * Eliminates TOCTOU parameter tampering at the enterprise tool boundary.
   */
  public verifyGrant(
    grant: AuthorizationGrant,
    expectedTool: string,
    receivedParameters: Record<string, unknown>,
    publicKey?: string
  ): { valid: boolean; reason?: string } {
    const key = publicKey || this.controlPlanePublicKey;
    if (!key) {
      return { valid: false, reason: 'Control Plane public key not provided for grant verification' };
    }

    // 1. Tool match check
    if (grant.tool !== expectedTool) {
      return { valid: false, reason: `Grant tool mismatch: expected '${expectedTool}', grant contains '${grant.tool}'` };
    }

    // 2. Cryptographic signature and parameter hash match (Anti-TOCTOU)
    return verifyAuthorizationGrant(grant, expectedTool, receivedParameters, key);
  }

  /**
   * Query an agent's compromise blast radius (§38, §84, §85)
   */
  public async getAgentBlastRadius(agentId: AgentId): Promise<BlastRadiusReport> {
    const response = await fetch(`${this.endpoint}/api/v1/analytics/blast-radius/${agentId}`, {
      headers: { 'X-Chronicle-Tenant': this.tenantId },
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch blast radius: HTTP ${response.status}`);
    }

    return response.json();
  }

  /**
   * Query the complete cryptographic provenance graph for an action (§26, §87)
   */
  public async getProvenanceGraph(actionId: string): Promise<ProvenanceGraph> {
    const response = await fetch(`${this.endpoint}/api/v1/audit/provenance/${actionId}`, {
      headers: { 'X-Chronicle-Tenant': this.tenantId },
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch provenance graph: HTTP ${response.status}`);
    }

    return response.json();
  }

  /**
   * Emergency Quarantine an agent (§32, §33)
   */
  public async quarantineAgent(agentId: AgentId, quarantine: boolean = true): Promise<void> {
    const response = await fetch(`${this.endpoint}/api/v1/kill-switch/quarantine`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Chronicle-Tenant': this.tenantId },
      body: JSON.stringify({ agentId, quarantine }),
    });

    if (!response.ok) {
      throw new Error(`Failed to quarantine agent: HTTP ${response.status}`);
    }
  }
}
