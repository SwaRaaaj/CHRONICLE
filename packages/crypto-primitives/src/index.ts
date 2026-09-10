import crypto from 'node:crypto';
import type { AuthorizationGrant, AuthorizationReceipt } from '@chronicle/core-types';

export interface KeyPair {
  publicKey: string; // PEM format
  privateKey: string; // PEM format
}

/**
 * Generate an asymmetric Ed25519 keypair for control-plane or agent signing.
 */
export function generateEd25519KeyPair(): KeyPair {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
  return { publicKey, privateKey };
}

/**
 * Deterministically serialize any JavaScript value to canonical JSON.
 * Recursively sorts all object keys to guarantee identical byte output regardless of insertion order.
 */
export function canonicalJsonStringify(val: unknown): string {
  if (val === null || typeof val !== 'object') {
    return JSON.stringify(val);
  }

  if (Array.isArray(val)) {
    return '[' + val.map(canonicalJsonStringify).join(',') + ']';
  }

  const keys = Object.keys(val as Record<string, unknown>).sort();
  const pairs = keys.map(k => {
    const v = (val as Record<string, unknown>)[k];
    return JSON.stringify(k) + ':' + canonicalJsonStringify(v);
  });
  return '{' + pairs.join(',') + '}';
}

/**
 * Compute canonical SHA-256 hash of arbitrary structured parameters.
 * Used for non-repudiable parameter binding to eliminate TOCTOU attacks.
 */
export function canonicalHash(val: unknown): string {
  const canonical = canonicalJsonStringify(val);
  return 'sha256:' + crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');
}

/**
 * Sign arbitrary data with Ed25519 private key. Returns hex signature.
 */
export function signEd25519(data: string, privateKeyPem: string): string {
  const signature = crypto.sign(null, Buffer.from(data, 'utf8'), privateKeyPem);
  return signature.toString('hex');
}

/**
 * Verify Ed25519 signature against data and public key.
 */
export function verifyEd25519(data: string, signatureHex: string, publicKeyPem: string): boolean {
  try {
    const signature = Buffer.from(signatureHex, 'hex');
    return crypto.verify(null, Buffer.from(data, 'utf8'), publicKeyPem, signature);
  } catch {
    return false;
  }
}

/**
 * Generate a cryptographically signed single-use Authorization Grant.
 * Bound to exact parameters hash, nonce, and short TTL (default 60 seconds).
 */
export function createAuthorizationGrant(
  grantId: string,
  actionId: string,
  tenantId: string,
  agentId: string,
  actionType: string,
  tool: string,
  resourceId: string,
  parametersHash: string,
  delegationId: string,
  privateKeyPem: string,
  ttlSeconds: number = 60
): AuthorizationGrant {
  const now = Math.floor(Date.now() / 1000);
  const nonce = crypto.randomBytes(16).toString('hex');

  const payloadToSign = [
    grantId,
    actionId,
    tenantId,
    agentId,
    actionType,
    tool,
    resourceId,
    parametersHash,
    delegationId,
    nonce,
    now,
    now + ttlSeconds
  ].join('|');

  const signature = signEd25519(payloadToSign, privateKeyPem);

  return {
    grantId,
    actionId,
    tenantId,
    agentId,
    actionType,
    tool,
    resourceId,
    parametersHash,
    delegationId,
    nonce,
    notBefore: now,
    expiresAt: now + ttlSeconds,
    signature
  };
}

/**
 * Verify that an Authorization Grant is valid, has not expired, matches the tool and parameters,
 * and is signed by the control plane's public key.
 */
export function verifyAuthorizationGrant(
  grant: AuthorizationGrant,
  expectedTool: string,
  actualParameters: unknown,
  controlPlanePublicKeyPem: string
): { valid: boolean; reason?: string } {
  const now = Math.floor(Date.now() / 1000);

  // 1. Clock checks
  if (now > grant.expiresAt) {
    return { valid: false, reason: 'GRANT_EXPIRED' };
  }
  if (now < grant.notBefore - 5) { // 5s clock skew allowance
    return { valid: false, reason: 'GRANT_NOT_YET_VALID' };
  }

  // 2. Tool binding check
  if (grant.tool !== expectedTool) {
    return { valid: false, reason: `TOOL_MISMATCH: expected ${expectedTool}, got ${grant.tool}` };
  }

  // 3. Exact parameter hash binding (prevent TOCTOU parameter tampering)
  const actualHash = canonicalHash(actualParameters);
  if (grant.parametersHash !== actualHash) {
    return { valid: false, reason: `PARAMETERS_TAMPERED: hash mismatch` };
  }

  // 4. Ed25519 Cryptographic Signature Check
  const payloadToSign = [
    grant.grantId,
    grant.actionId,
    grant.tenantId,
    grant.agentId,
    grant.actionType,
    grant.tool,
    grant.resourceId,
    grant.parametersHash,
    grant.delegationId,
    grant.nonce,
    grant.notBefore,
    grant.expiresAt
  ].join('|');

  const signatureValid = verifyEd25519(payloadToSign, grant.signature, controlPlanePublicKeyPem);
  if (!signatureValid) {
    return { valid: false, reason: 'INVALID_SIGNATURE' };
  }

  return { valid: true };
}

/**
 * Compute Merkle-chained hash for a tamper-evident Authorization Receipt.
 */
export function computeReceiptHash(
  receiptData: Omit<AuthorizationReceipt, 'receiptHash' | 'signature'>,
  previousReceiptHash: string
): string {
  const content = [
    previousReceiptHash,
    receiptData.receiptId,
    receiptData.actionId,
    receiptData.tenantId,
    receiptData.agentId,
    receiptData.sponsorId,
    receiptData.decision,
    receiptData.actionType,
    receiptData.resourceId,
    receiptData.policyVersion,
    receiptData.riskScore,
    receiptData.reasonCodes.join(','),
    receiptData.parametersHash,
    receiptData.timestamp
  ].join('|');

  return 'sha256:' + crypto.createHash('sha256').update(content, 'utf8').digest('hex');
}

/**
 * Verify integrity of a chain of authorization receipts.
 * Returns true if the entire sequence forms an unbroken cryptographic ledger.
 */
export function verifyReceiptChain(
  receipts: AuthorizationReceipt[],
  controlPlanePublicKeyPem: string
): { valid: boolean; brokenAt?: string } {
  let prevHash = 'GENESIS_BLOCK_HASH';

  for (let i = 0; i < receipts.length; i++) {
    const r = receipts[i];

    // Verify link to previous receipt
    if (r.previousReceiptHash !== prevHash) {
      return { valid: false, brokenAt: `Receipt ${r.receiptId} previousHash mismatch` };
    }

    // Verify computed hash
    const expectedHash = computeReceiptHash(r, prevHash);
    if (r.receiptHash !== expectedHash) {
      return { valid: false, brokenAt: `Receipt ${r.receiptId} hash tampered` };
    }

    // Verify signature
    const sigValid = verifyEd25519(r.receiptHash, r.signature, controlPlanePublicKeyPem);
    if (!sigValid) {
      return { valid: false, brokenAt: `Receipt ${r.receiptId} signature invalid` };
    }

    prevHash = r.receiptHash;
  }

  return { valid: true };
}
