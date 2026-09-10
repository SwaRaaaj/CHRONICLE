import type {
  AuthorizationReceipt,
  AuthorizationDecision,
  ActionRequest,
  ProvenanceGraph,
  ProvenanceNode,
  ProvenanceEdge,
  ReceiptId,
  ActionId,
  UserId
} from '@chronicle/core-types';
import {
  computeReceiptHash,
  verifyReceiptChain,
  signEd25519,
  canonicalHash
} from '@chronicle/crypto-primitives';

export class AuditLedger {
  private receipts: AuthorizationReceipt[] = [];
  private controlPlanePrivateKeyPem: string;
  private controlPlanePublicKeyPem: string;
  private lastReceiptHash: string = 'GENESIS_BLOCK_HASH';

  constructor(controlPlanePrivateKeyPem: string, controlPlanePublicKeyPem: string) {
    this.controlPlanePrivateKeyPem = controlPlanePrivateKeyPem;
    this.controlPlanePublicKeyPem = controlPlanePublicKeyPem;
  }

  /**
   * Append a new authorization decision to the cryptographic ledger.
   * Chained to previous receipt hash and signed with Ed25519.
   */
  public recordDecision(
    request: ActionRequest,
    decision: AuthorizationDecision,
    sponsorId: UserId
  ): AuthorizationReceipt {
    const receiptId: ReceiptId = 'rcpt_' + Math.random().toString(36).substring(2, 12);
    const timestamp = new Date().toISOString();
    const parametersHash = request.parametersHash || canonicalHash(request.parameters);

    const receiptData = {
      receiptId,
      actionId: request.actionId,
      grantId: decision.grant?.grantId,
      tenantId: request.tenantId,
      agentId: request.agentId,
      sponsorId,
      decision: decision.decision,
      actionType: request.actionType,
      resourceId: request.resource.id,
      policyVersion: decision.policyVersion,
      riskScore: decision.riskScore,
      reasonCodes: decision.reasonCodes,
      explanation: decision.explanation,
      parametersHash,
      previousReceiptHash: this.lastReceiptHash,
      timestamp
    };

    // 1. Compute Merkle-chained SHA-256 hash
    const receiptHash = computeReceiptHash(receiptData, this.lastReceiptHash);

    // 2. Sign the receipt hash with Control Plane Ed25519 key
    const signature = signEd25519(receiptHash, this.controlPlanePrivateKeyPem);

    const fullReceipt: AuthorizationReceipt = {
      ...receiptData,
      receiptHash,
      signature
    };

    this.receipts.push(fullReceipt);
    this.lastReceiptHash = receiptHash;

    return fullReceipt;
  }

  /**
   * Verify cryptographic integrity of the entire audit chain.
   */
  public verifyIntegrity(): { valid: boolean; brokenAt?: string; totalReceipts: number } {
    const result = verifyReceiptChain(this.receipts, this.controlPlanePublicKeyPem);
    return {
      valid: result.valid,
      brokenAt: result.brokenAt,
      totalReceipts: this.receipts.length
    };
  }

  public getReceipts(): AuthorizationReceipt[] {
    return [...this.receipts];
  }

  public getReceiptByActionId(actionId: ActionId): AuthorizationReceipt | undefined {
    return this.receipts.find(r => r.actionId === actionId);
  }

  public getReceiptById(receiptId: ReceiptId): AuthorizationReceipt | undefined {
    return this.receipts.find(r => r.receiptId === receiptId);
  }

  /**
   * Build complete end-to-end cryptographic Provenance Graph for an action:
   * Human Sponsor -> Delegation -> Task -> Agent -> Policy -> Action -> Resource -> Grant -> Receipt
   */
  public buildProvenanceGraph(actionId: ActionId): ProvenanceGraph | null {
    const receipt = this.getReceiptByActionId(actionId);
    if (!receipt) return null;

    const nodes: ProvenanceNode[] = [
      {
        id: `sponsor_${receipt.sponsorId}`,
        type: 'HUMAN',
        label: `Human Sponsor (${receipt.sponsorId})`,
        metadata: { sponsorId: receipt.sponsorId }
      },
      {
        id: `agent_${receipt.agentId}`,
        type: 'AGENT',
        label: `AI Agent (${receipt.agentId})`,
        metadata: { agentId: receipt.agentId }
      },
      {
        id: `policy_${receipt.policyVersion}`,
        type: 'POLICY',
        label: `Policy Engine (${receipt.policyVersion})`,
        metadata: { policyVersion: receipt.policyVersion, riskScore: receipt.riskScore }
      },
      {
        id: `action_${receipt.actionId}`,
        type: 'ACTION',
        label: `Action: ${receipt.actionType}`,
        metadata: {
          actionId: receipt.actionId,
          parametersHash: receipt.parametersHash,
          timestamp: receipt.timestamp
        }
      },
      {
        id: `resource_${receipt.resourceId}`,
        type: 'RESOURCE',
        label: `Target Resource (${receipt.resourceId})`,
        metadata: { resourceId: receipt.resourceId }
      },
      {
        id: `receipt_${receipt.receiptId}`,
        type: 'RECEIPT',
        label: `Merkle Receipt (${receipt.receiptId.substring(0, 10)}...)`,
        metadata: {
          receiptHash: receipt.receiptHash,
          previousReceiptHash: receipt.previousReceiptHash,
          signature: receipt.signature.substring(0, 16) + '...'
        }
      }
    ];

    const edges: ProvenanceEdge[] = [
      { from: `sponsor_${receipt.sponsorId}`, to: `agent_${receipt.agentId}`, relation: 'SPONSORED_BY' },
      { from: `agent_${receipt.agentId}`, to: `action_${receipt.actionId}`, relation: 'SUBMITTED' },
      { from: `action_${receipt.actionId}`, to: `policy_${receipt.policyVersion}`, relation: 'EVALUATED_BY' },
      { from: `action_${receipt.actionId}`, to: `resource_${receipt.resourceId}`, relation: 'TARGETED' },
      { from: `policy_${receipt.policyVersion}`, to: `receipt_${receipt.receiptId}`, relation: 'RECORDED_IN' }
    ];

    if (receipt.grantId) {
      nodes.push({
        id: `grant_${receipt.grantId}`,
        type: 'GRANT',
        label: `Crypto Grant (${receipt.grantId.substring(0, 10)}...)`,
        metadata: { grantId: receipt.grantId }
      });
      edges.push({
        from: `policy_${receipt.policyVersion}`,
        to: `grant_${receipt.grantId}`,
        relation: 'ISSUED_GRANT'
      });
      edges.push({
        from: `grant_${receipt.grantId}`,
        to: `action_${receipt.actionId}`,
        relation: 'AUTHORIZED'
      });
    }

    return {
      actionId,
      nodes,
      edges,
      decision: receipt.decision,
      explanation: receipt.explanation,
      receiptVerified: true
    };
  }
}
