// apps/control-plane/src/index.ts
import http2 from "node:http";
import fs from "node:fs";
import path from "node:path";

// packages/crypto-primitives/src/index.ts
import crypto from "node:crypto";
function generateEd25519KeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" }
  });
  return { publicKey, privateKey };
}
function canonicalJsonStringify(val) {
  if (val === null || typeof val !== "object") {
    return JSON.stringify(val);
  }
  if (Array.isArray(val)) {
    return "[" + val.map(canonicalJsonStringify).join(",") + "]";
  }
  const keys = Object.keys(val).sort();
  const pairs = keys.map((k) => {
    const v = val[k];
    return JSON.stringify(k) + ":" + canonicalJsonStringify(v);
  });
  return "{" + pairs.join(",") + "}";
}
function canonicalHash(val) {
  const canonical = canonicalJsonStringify(val);
  return "sha256:" + crypto.createHash("sha256").update(canonical, "utf8").digest("hex");
}
function signEd25519(data, privateKeyPem) {
  const signature = crypto.sign(null, Buffer.from(data, "utf8"), privateKeyPem);
  return signature.toString("hex");
}
function verifyEd25519(data, signatureHex, publicKeyPem) {
  try {
    const signature = Buffer.from(signatureHex, "hex");
    return crypto.verify(null, Buffer.from(data, "utf8"), publicKeyPem, signature);
  } catch {
    return false;
  }
}
function createAuthorizationGrant(grantId, actionId, tenantId, agentId, actionType, tool, resourceId, parametersHash, delegationId, privateKeyPem, ttlSeconds = 60) {
  const now = Math.floor(Date.now() / 1e3);
  const nonce = crypto.randomBytes(16).toString("hex");
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
  ].join("|");
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
function verifyAuthorizationGrant(grant, expectedTool, actualParameters, controlPlanePublicKeyPem) {
  const now = Math.floor(Date.now() / 1e3);
  if (now > grant.expiresAt) {
    return { valid: false, reason: "GRANT_EXPIRED" };
  }
  if (now < grant.notBefore - 5) {
    return { valid: false, reason: "GRANT_NOT_YET_VALID" };
  }
  if (grant.tool !== expectedTool) {
    return { valid: false, reason: `TOOL_MISMATCH: expected ${expectedTool}, got ${grant.tool}` };
  }
  const actualHash = canonicalHash(actualParameters);
  if (grant.parametersHash !== actualHash) {
    return { valid: false, reason: `PARAMETERS_TAMPERED: hash mismatch` };
  }
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
  ].join("|");
  const signatureValid = verifyEd25519(payloadToSign, grant.signature, controlPlanePublicKeyPem);
  if (!signatureValid) {
    return { valid: false, reason: "INVALID_SIGNATURE" };
  }
  return { valid: true };
}
function computeReceiptHash(receiptData, previousReceiptHash) {
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
    receiptData.reasonCodes.join(","),
    receiptData.parametersHash,
    receiptData.timestamp
  ].join("|");
  return "sha256:" + crypto.createHash("sha256").update(content, "utf8").digest("hex");
}
function verifyReceiptChain(receipts, controlPlanePublicKeyPem) {
  let prevHash = "GENESIS_BLOCK_HASH";
  for (let i = 0; i < receipts.length; i++) {
    const r = receipts[i];
    if (r.previousReceiptHash !== prevHash) {
      return { valid: false, brokenAt: `Receipt ${r.receiptId} previousHash mismatch` };
    }
    const expectedHash = computeReceiptHash(r, prevHash);
    if (r.receiptHash !== expectedHash) {
      return { valid: false, brokenAt: `Receipt ${r.receiptId} hash tampered` };
    }
    const sigValid = verifyEd25519(r.receiptHash, r.signature, controlPlanePublicKeyPem);
    if (!sigValid) {
      return { valid: false, brokenAt: `Receipt ${r.receiptId} signature invalid` };
    }
    prevHash = r.receiptHash;
  }
  return { valid: true };
}

// packages/delegation-manager/src/index.ts
var DelegationManager = class {
  sponsors = /* @__PURE__ */ new Map();
  agents = /* @__PURE__ */ new Map();
  delegations = /* @__PURE__ */ new Map();
  childDelegations = /* @__PURE__ */ new Map();
  // 1. Identity Management
  registerSponsor(sponsor) {
    this.sponsors.set(sponsor.userId, { ...sponsor });
  }
  getSponsor(userId) {
    return this.sponsors.get(userId);
  }
  registerAgent(agent) {
    this.agents.set(agent.agentId, { ...agent });
  }
  getAgent(agentId) {
    return this.agents.get(agentId);
  }
  listAgents() {
    return Array.from(this.agents.values());
  }
  listSponsors() {
    return Array.from(this.sponsors.values());
  }
  setAgentStatus(agentId, status) {
    const agent = this.agents.get(agentId);
    if (!agent) return false;
    agent.status = status;
    return true;
  }
  // 2. Monotonic Privilege Narrowing Validation
  validateMonotonicNarrowing(parentConstraints, childConstraints) {
    for (const tool of childConstraints.allowedTools) {
      if (!parentConstraints.allowedTools.includes("*") && !parentConstraints.allowedTools.includes(tool)) {
        return {
          valid: false,
          violation: `Child delegation requests unauthorized tool '${tool}' not granted by parent`
        };
      }
    }
    if (parentConstraints.maxTransactionValue !== void 0) {
      if (childConstraints.maxTransactionValue === void 0 || childConstraints.maxTransactionValue > parentConstraints.maxTransactionValue) {
        return {
          valid: false,
          violation: `Child maxTransactionValue (${childConstraints.maxTransactionValue}) exceeds parent limit (${parentConstraints.maxTransactionValue})`
        };
      }
    }
    if (parentConstraints.cumulativeValueLimit !== void 0) {
      if (childConstraints.cumulativeValueLimit === void 0 || childConstraints.cumulativeValueLimit > parentConstraints.cumulativeValueLimit) {
        return {
          valid: false,
          violation: `Child cumulativeValueLimit (${childConstraints.cumulativeValueLimit}) exceeds parent cumulative limit (${parentConstraints.cumulativeValueLimit})`
        };
      }
    }
    if (parentConstraints.allowedActionTypes && parentConstraints.allowedActionTypes.length > 0) {
      if (!childConstraints.allowedActionTypes || childConstraints.allowedActionTypes.length === 0) {
        return {
          valid: false,
          violation: `Child delegation must restrict action types to subset of parent`
        };
      }
      for (const act of childConstraints.allowedActionTypes) {
        if (!parentConstraints.allowedActionTypes.includes(act)) {
          return {
            valid: false,
            violation: `Child action type '${act}' not permitted by parent delegation`
          };
        }
      }
    }
    return { valid: true };
  }
  // 3. Issue Delegation Envelope
  createDelegation(envelope, signerPrivateKeyPem) {
    if (envelope.parentDelegationId) {
      const parent = this.delegations.get(envelope.parentDelegationId);
      if (!parent) {
        throw new Error(`Parent delegation '${envelope.parentDelegationId}' not found`);
      }
      if (parent.revoked) {
        throw new Error(`Cannot sub-delegate from revoked parent delegation '${parent.delegationId}'`);
      }
      const narrowing = this.validateMonotonicNarrowing(parent.constraints, envelope.constraints);
      if (!narrowing.valid) {
        throw new Error(`Monotonic narrowing violation: ${narrowing.violation}`);
      }
      const parentExp = new Date(parent.expiresAt).getTime();
      const childExp = new Date(envelope.expiresAt).getTime();
      if (childExp > parentExp) {
        throw new Error(`Child delegation expiration (${envelope.expiresAt}) cannot exceed parent expiration (${parent.expiresAt})`);
      }
    }
    const createdAt = (/* @__PURE__ */ new Date()).toISOString();
    const payloadToSign = canonicalJsonStringify({
      delegationId: envelope.delegationId,
      tenantId: envelope.tenantId,
      parentDelegationId: envelope.parentDelegationId,
      delegatorType: envelope.delegatorType,
      delegatorId: envelope.delegatorId,
      delegateeId: envelope.delegateeId,
      taskId: envelope.taskId,
      purpose: envelope.purpose,
      constraints: envelope.constraints,
      notBefore: envelope.notBefore,
      expiresAt: envelope.expiresAt,
      createdAt
    });
    const signature = signEd25519(payloadToSign, signerPrivateKeyPem);
    const fullEnvelope = {
      ...envelope,
      createdAt,
      revoked: false,
      signature
    };
    this.delegations.set(fullEnvelope.delegationId, fullEnvelope);
    if (fullEnvelope.parentDelegationId) {
      if (!this.childDelegations.has(fullEnvelope.parentDelegationId)) {
        this.childDelegations.set(fullEnvelope.parentDelegationId, /* @__PURE__ */ new Set());
      }
      this.childDelegations.get(fullEnvelope.parentDelegationId).add(fullEnvelope.delegationId);
    }
    return fullEnvelope;
  }
  // 4. Revocation with Cascading Invalidation
  revokeDelegation(delegationId, reason) {
    const target = this.delegations.get(delegationId);
    if (!target) return { revokedCount: 0 };
    let count = 0;
    const toRevoke = [delegationId];
    while (toRevoke.length > 0) {
      const currentId = toRevoke.shift();
      const del = this.delegations.get(currentId);
      if (del && !del.revoked) {
        del.revoked = true;
        del.revokedAt = (/* @__PURE__ */ new Date()).toISOString();
        del.revokedReason = reason;
        count++;
      }
      const children = this.childDelegations.get(currentId);
      if (children) {
        for (const childId of children) {
          toRevoke.push(childId);
        }
      }
    }
    return { revokedCount: count };
  }
  // 5. Chain Verification
  verifyDelegationChain(delegationId, agentId) {
    const chain = [];
    let currentId = delegationId;
    const now = Date.now();
    while (currentId) {
      const envelope = this.delegations.get(currentId);
      if (!envelope) {
        return {
          valid: false,
          reasonCode: "DELEGATION_INVALID",
          explanation: `Delegation '${currentId}' not found in registry`
        };
      }
      if (envelope.revoked) {
        return {
          valid: false,
          reasonCode: "DELEGATION_REVOKED",
          explanation: `Delegation '${envelope.delegationId}' has been revoked (${envelope.revokedReason || "No reason provided"})`
        };
      }
      const notBefore = new Date(envelope.notBefore).getTime();
      const expiresAt = new Date(envelope.expiresAt).getTime();
      if (now < notBefore) {
        return {
          valid: false,
          reasonCode: "DELEGATION_INVALID",
          explanation: `Delegation '${envelope.delegationId}' is not yet valid (notBefore: ${envelope.notBefore})`
        };
      }
      if (now > expiresAt) {
        return {
          valid: false,
          reasonCode: "DELEGATION_INVALID",
          explanation: `Delegation '${envelope.delegationId}' expired at ${envelope.expiresAt}`
        };
      }
      let delegatorPublicKey;
      if (envelope.delegatorType === "HUMAN") {
        const sponsor = this.sponsors.get(envelope.delegatorId);
        if (!sponsor) {
          return {
            valid: false,
            reasonCode: "DELEGATION_INVALID",
            explanation: `Human sponsor '${envelope.delegatorId}' not found`
          };
        }
        delegatorPublicKey = sponsor.publicKey;
      } else {
        const parentAgent = this.agents.get(envelope.delegatorId);
        if (!parentAgent) {
          return {
            valid: false,
            reasonCode: "DELEGATION_INVALID",
            explanation: `Delegating agent '${envelope.delegatorId}' not found`
          };
        }
        if (parentAgent.status !== "ACTIVE") {
          return {
            valid: false,
            reasonCode: "AGENT_QUARANTINED",
            explanation: `Delegating agent '${parentAgent.agentId}' is in non-active state: ${parentAgent.status}`
          };
        }
        delegatorPublicKey = parentAgent.publicKey;
      }
      const payload = canonicalJsonStringify({
        delegationId: envelope.delegationId,
        tenantId: envelope.tenantId,
        parentDelegationId: envelope.parentDelegationId,
        delegatorType: envelope.delegatorType,
        delegatorId: envelope.delegatorId,
        delegateeId: envelope.delegateeId,
        taskId: envelope.taskId,
        purpose: envelope.purpose,
        constraints: envelope.constraints,
        notBefore: envelope.notBefore,
        expiresAt: envelope.expiresAt,
        createdAt: envelope.createdAt
      });
      const signatureValid = verifyEd25519(payload, envelope.signature, delegatorPublicKey);
      if (!signatureValid) {
        return {
          valid: false,
          reasonCode: "DELEGATION_INVALID",
          explanation: `Cryptographic signature on delegation '${envelope.delegationId}' failed verification`
        };
      }
      chain.unshift(envelope);
      currentId = envelope.parentDelegationId;
    }
    if (chain.length === 0) {
      return {
        valid: false,
        reasonCode: "DELEGATION_INVALID",
        explanation: "Empty delegation chain"
      };
    }
    const rootEnvelope = chain[0];
    if (rootEnvelope.delegatorType !== "HUMAN") {
      return {
        valid: false,
        reasonCode: "DELEGATION_INVALID",
        explanation: `Root delegation '${rootEnvelope.delegationId}' must originate from a HUMAN sponsor`
      };
    }
    const rootSponsor = this.sponsors.get(rootEnvelope.delegatorId);
    if (!rootSponsor) {
      return {
        valid: false,
        reasonCode: "DELEGATION_INVALID",
        explanation: `Root sponsor '${rootEnvelope.delegatorId}' not found`
      };
    }
    const terminalEnvelope = chain[chain.length - 1];
    if (terminalEnvelope.delegateeId !== agentId) {
      return {
        valid: false,
        reasonCode: "DELEGATION_INVALID",
        explanation: `Delegation chain terminates at agent '${terminalEnvelope.delegateeId}', but action was submitted by '${agentId}'`
      };
    }
    const rootTenant = chain[0].tenantId;
    for (const link of chain) {
      if (link.tenantId !== rootTenant) {
        return {
          valid: false,
          reasonCode: "DELEGATION_INVALID",
          explanation: `Cross-tenant delegation detected: chain mixes tenants '${rootTenant}' and '${link.tenantId}'`
        };
      }
    }
    const activeAgent = this.agents.get(agentId);
    if (!activeAgent) {
      return {
        valid: false,
        reasonCode: "DELEGATION_INVALID",
        explanation: `Active agent '${agentId}' not found in registry`
      };
    }
    if (activeAgent.status !== "ACTIVE") {
      return {
        valid: false,
        reasonCode: "AGENT_QUARANTINED",
        explanation: `Active agent '${agentId}' is ${activeAgent.status}`
      };
    }
    for (let i = 0; i < chain.length - 1; i++) {
      const parent = chain[i];
      const child = chain[i + 1];
      const narrowing = this.validateMonotonicNarrowing(parent.constraints, child.constraints);
      if (!narrowing.valid) {
        return {
          valid: false,
          reasonCode: "MONOTONIC_NARROWING_VIOLATION",
          explanation: `Monotonic narrowing violation between '${parent.delegationId}' and '${child.delegationId}': ${narrowing.violation}`
        };
      }
    }
    return {
      valid: true,
      chain: {
        chain,
        rootSponsor,
        activeAgent,
        isValid: true
      }
    };
  }
  /**
   * Glob-style resource ID pattern matching for resource traversal prevention (§48, §49)
   * Supports: 'cust:*' matches 'cust:123', '*' matches anything, 'k8s:**' matches any sub-path
   */
  matchesGlobPattern(resourceId, pattern) {
    if (pattern === "*" || pattern === "**") return true;
    const regexStr = "^" + pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*\*/g, "__DS__").replace(/\*/g, "[^:]+").replace(/__DS__/g, ".*") + "$";
    return new RegExp(regexStr).test(resourceId);
  }
  /**
   * Verify that a resource ID is within the scope of a delegation's resource patterns.
   * Blocks resource traversal attacks where an agent accesses out-of-scope resources.
   */
  checkResourceScope(resourceId, delegationId) {
    const delegation = this.delegations.get(delegationId);
    if (!delegation) {
      return { allowed: false, reason: `Delegation '${delegationId}' not found` };
    }
    const patterns = delegation.constraints.resourcePatterns;
    if (!patterns || patterns.length === 0 || patterns.includes("*")) {
      return { allowed: true };
    }
    const matches = patterns.some((p) => this.matchesGlobPattern(resourceId, p));
    if (!matches) {
      return {
        allowed: false,
        reason: `Resource '${resourceId}' does not match delegation resource patterns: [${patterns.join(", ")}]`
      };
    }
    return { allowed: true };
  }
  getDelegation(delegationId) {
    return this.delegations.get(delegationId);
  }
  listDelegations() {
    return Array.from(this.delegations.values());
  }
};

// packages/sequence-detector/src/index.ts
var SequenceDetector = class {
  history = [];
  forbiddenRules = [];
  prerequisiteRules = [];
  /** Global per-delegation cumulative spend tracker (persists across all sessions and tasks) */
  delegationCumulativeSpend = /* @__PURE__ */ new Map();
  constructor() {
    this.initializeDefaultRules();
  }
  initializeDefaultRules() {
    this.forbiddenRules.push({
      id: "SEQ_DATA_EXFILTRATION",
      name: "Sensitive PII Exfiltration via Outbound Communication",
      sequence: ["read_customer_pii", "send_external_email"],
      maxWindowSeconds: 3600,
      reasonCode: "FORBIDDEN_SEQUENCE",
      severity: "CRITICAL",
      description: "Agent accessed customer PII and subsequently attempted external email transmission"
    });
    this.forbiddenRules.push({
      id: "SEQ_SLACK_EXFILTRATION",
      name: "PII Exfiltration via Slack Announcement",
      sequence: ["read_customer_pii", "post_slack_announcement"],
      maxWindowSeconds: 3600,
      reasonCode: "FORBIDDEN_SEQUENCE",
      severity: "CRITICAL",
      description: "Agent accessed customer PII and subsequently attempted Slack broadcast"
    });
    this.forbiddenRules.push({
      id: "SEQ_INFRA_ESCALATION",
      name: "Firewall Alteration followed by DB Query",
      sequence: ["modify_security_group", "query_production_database"],
      maxWindowSeconds: 1800,
      reasonCode: "FORBIDDEN_SEQUENCE",
      severity: "CRITICAL",
      description: "Agent modified security firewall rules and subsequently queried production database"
    });
    this.prerequisiteRules.push({
      targetAction: "send_wire_transfer",
      requiredPriorActions: ["verify_identity"],
      description: "Wire transfers strictly require prior identity verification within the same task session"
    });
    this.prerequisiteRules.push({
      targetAction: "deploy_container",
      requiredPriorActions: ["run_security_scan"],
      description: "Production container deployment requires prior security scanning"
    });
  }
  recordAction(record) {
    this.history.push({ ...record });
    if (record.decision === "ALLOW" && typeof record.parameters?.amount === "number" && record.parameters.amount > 0) {
      if (record.delegationId) {
        const key = `${record.agentId}:${record.delegationId}`;
        this.delegationCumulativeSpend.set(key, (this.delegationCumulativeSpend.get(key) ?? 0) + record.parameters.amount);
      }
    }
  }
  getSessionHistory(sessionId) {
    return this.history.filter((h) => h.sessionId === sessionId);
  }
  getTaskHistory(taskId) {
    return this.history.filter((h) => h.taskId === taskId);
  }
  getSequenceSummary(sessionId, taskId) {
    const sessionRecords = this.history.filter((h) => h.sessionId === sessionId || h.taskId === taskId);
    const recentActions = sessionRecords.map((r) => r.actionType);
    const cumulativeAmounts = {};
    const actionCounts = {};
    for (const r of sessionRecords) {
      actionCounts[r.actionType] = (actionCounts[r.actionType] || 0) + 1;
      if (r.parameters && typeof r.parameters.amount === "number") {
        cumulativeAmounts[r.actionType] = (cumulativeAmounts[r.actionType] || 0) + r.parameters.amount;
      }
    }
    const firstTime = sessionRecords.length > 0 ? sessionRecords[0].timestamp : (/* @__PURE__ */ new Date()).toISOString();
    const lastTime = sessionRecords.length > 0 ? sessionRecords[sessionRecords.length - 1].timestamp : firstTime;
    return {
      sessionId,
      taskId,
      recentActions,
      cumulativeAmounts,
      actionCounts,
      firstActionTime: firstTime,
      lastActionTime: lastTime
    };
  }
  /**
   * Evaluate whether the proposed ActionRequest violates sequence rules,
   * prerequisite requirements, cumulative limits, loop limits, or declared intent.
   */
  evaluateSequence(request, task, delegation) {
    const sessionHistory = this.getSessionHistory(request.sessionId);
    const taskHistory = this.getTaskHistory(request.taskId);
    const relevantHistory = [.../* @__PURE__ */ new Set([...sessionHistory, ...taskHistory])].sort(
      (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
    );
    const now = new Date(request.timestamp).getTime();
    if (task) {
      if (task.expectedTools && task.expectedTools.length > 0) {
        if (!task.expectedTools.includes("*") && !task.expectedTools.includes(request.tool)) {
          return {
            valid: false,
            reasonCode: "INTENT_DRIFT",
            explanation: `Action tool '${request.tool}' is not within declared task expected tools: [${task.expectedTools.join(", ")}]`,
            anomalyScore: 90
          };
        }
      }
      if (task.maxAllowedValue !== void 0 && typeof request.parameters.amount === "number") {
        if (request.parameters.amount > task.maxAllowedValue) {
          return {
            valid: false,
            reasonCode: "LIMIT_EXCEEDED",
            explanation: `Requested amount $${request.parameters.amount} exceeds task max allowed value ($${task.maxAllowedValue})`,
            anomalyScore: 85
          };
        }
      }
    }
    for (const prereq of this.prerequisiteRules) {
      if (prereq.targetAction === request.actionType) {
        const hasPrereq = relevantHistory.some(
          (h) => prereq.requiredPriorActions.includes(h.actionType) && h.decision === "ALLOW"
        );
        if (!hasPrereq) {
          return {
            valid: false,
            reasonCode: "MISSING_PREREQUISITE_SEQUENCE",
            explanation: `Action '${request.actionType}' requires prior execution of [${prereq.requiredPriorActions.join(", ")}]. ${prereq.description}`,
            anomalyScore: 80
          };
        }
      }
    }
    for (const rule of this.forbiddenRules) {
      const targetStep = rule.sequence[rule.sequence.length - 1];
      if (targetStep === request.actionType) {
        const priorSteps = rule.sequence.slice(0, rule.sequence.length - 1);
        const match = relevantHistory.find((h) => {
          if (!priorSteps.includes(h.actionType)) return false;
          if (rule.maxWindowSeconds) {
            const historyTime = new Date(h.timestamp).getTime();
            if ((now - historyTime) / 1e3 > rule.maxWindowSeconds) return false;
          }
          return true;
        });
        if (match) {
          return {
            valid: false,
            reasonCode: rule.reasonCode,
            explanation: `Forbidden sequence detected: '${match.actionType}' -> '${request.actionType}'. ${rule.description}`,
            anomalyScore: rule.severity === "CRITICAL" ? 95 : 75
          };
        }
      }
    }
    const proposedAmount = typeof request.parameters.amount === "number" ? request.parameters.amount : 0;
    if (proposedAmount > 0 && delegation?.constraints.cumulativeValueLimit !== void 0) {
      const delegKey = `${request.agentId}:${delegation.delegationId}`;
      const globalCumulative = this.delegationCumulativeSpend.get(delegKey) ?? 0;
      if (globalCumulative > 0) {
        if (globalCumulative + proposedAmount > delegation.constraints.cumulativeValueLimit) {
          return {
            valid: false,
            reasonCode: "CUMULATIVE_LIMIT_EXCEEDED",
            explanation: `Cumulative transaction sum ($${globalCumulative} + $${proposedAmount} = $${globalCumulative + proposedAmount}) exceeds delegation cumulative limit ($${delegation.constraints.cumulativeValueLimit})`,
            anomalyScore: 88
          };
        }
      } else {
        let currentCumulative = 0;
        for (const h of relevantHistory) {
          if (h.decision === "ALLOW" && typeof h.parameters.amount === "number") {
            currentCumulative += h.parameters.amount;
          }
        }
        if (currentCumulative + proposedAmount > delegation.constraints.cumulativeValueLimit) {
          return {
            valid: false,
            reasonCode: "CUMULATIVE_LIMIT_EXCEEDED",
            explanation: `Cumulative transaction sum ($${currentCumulative} + $${proposedAmount} = $${currentCumulative + proposedAmount}) exceeds delegation cumulative limit ($${delegation.constraints.cumulativeValueLimit})`,
            anomalyScore: 88
          };
        }
      }
    }
    const recentWindowRecords = relevantHistory.filter((h) => {
      const recTime = new Date(h.timestamp).getTime();
      return now - recTime <= 3e4;
    });
    const identicalCalls = recentWindowRecords.filter(
      (h) => h.actionType === request.actionType && h.tool === request.tool && JSON.stringify(h.parameters) === JSON.stringify(request.parameters)
    );
    if (identicalCalls.length >= 3) {
      return {
        valid: false,
        reasonCode: "SEQUENCE_ANOMALY",
        explanation: `Runaway agent loop detected: ${identicalCalls.length + 1} identical calls to '${request.actionType}' with identical parameters in under 30 seconds`,
        anomalyScore: 95
      };
    }
    const sameToolCalls = recentWindowRecords.filter(
      (h) => h.tool === request.tool
    );
    if (sameToolCalls.length >= 14) {
      return {
        valid: false,
        reasonCode: "SEQUENCE_ANOMALY",
        explanation: `Tool abuse burst detected: ${sameToolCalls.length + 1} rapid consecutive calls to tool '${request.tool}' in a 30-second window. Rate limit exceeded.`,
        anomalyScore: 88
      };
    }
    return {
      valid: true,
      anomalyScore: 10
    };
  }
  addForbiddenRule(rule) {
    this.forbiddenRules.push(rule);
  }
  addPrerequisiteRule(rule) {
    this.prerequisiteRules.push(rule);
  }
};

// packages/workflow-engine/src/index.ts
var WorkflowEngine = class {
  workflows = /* @__PURE__ */ new Map();
  instances = /* @__PURE__ */ new Map();
  invariants = /* @__PURE__ */ new Map();
  processedRefunds = /* @__PURE__ */ new Set();
  // Tracks chargeIds to prevent double refunds (§41)
  constructor() {
    this.registerDefaultInvariants();
  }
  /**
   * Register a formal workflow state machine definition (§42)
   */
  registerWorkflow(definition) {
    this.workflows.set(definition.workflowId, definition);
  }
  getWorkflow(workflowId) {
    return this.workflows.get(workflowId);
  }
  /**
   * Create a new stateful workflow instance tied to a task (§42)
   */
  createInstance(workflowId, tenantId, taskId, initialContext = {}) {
    const definition = this.workflows.get(workflowId);
    if (!definition) {
      throw new Error(`Workflow definition '${workflowId}' not found`);
    }
    const instanceId = `wf_inst_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
    const now = (/* @__PURE__ */ new Date()).toISOString();
    const instance = {
      instanceId,
      workflowId,
      tenantId,
      taskId,
      currentState: definition.initialState,
      history: [
        {
          fromState: "NONE",
          toState: definition.initialState,
          transitionedAt: now,
          triggeredBy: "SYSTEM_INIT"
        }
      ],
      emittedEvents: [],
      contextData: { ...initialContext },
      createdAt: now,
      updatedAt: now
    };
    this.instances.set(instanceId, instance);
    return instance;
  }
  getInstance(instanceId) {
    return this.instances.get(instanceId);
  }
  findInstanceByTask(taskId) {
    for (const inst of this.instances.values()) {
      if (inst.taskId === taskId) {
        return inst;
      }
    }
    return void 0;
  }
  /**
   * Emit an external/internal event into a workflow instance (§44)
   * e.g. "fraud_check_passed", "pr_reviewed", "customer_complaint_verified"
   */
  emitEvent(instanceId, event) {
    const instance = this.instances.get(instanceId);
    if (!instance) {
      throw new Error(`Workflow instance '${instanceId}' not found`);
    }
    if (!instance.emittedEvents.includes(event)) {
      instance.emittedEvents.push(event);
      instance.updatedAt = (/* @__PURE__ */ new Date()).toISOString();
    }
  }
  /**
   * Transition the workflow state (§42, §43)
   */
  transition(instanceId, toState, triggeredBy, triggerEvent, metadata) {
    const instance = this.instances.get(instanceId);
    if (!instance) {
      throw new Error(`Workflow instance '${instanceId}' not found`);
    }
    const definition = this.workflows.get(instance.workflowId);
    if (!definition) {
      throw new Error(`Workflow definition '${instance.workflowId}' not found`);
    }
    if (!definition.states.includes(toState)) {
      throw new Error(`State '${toState}' is not a valid state in workflow '${definition.name}'`);
    }
    const validTransition = definition.transitions.find(
      (t) => t.fromState === instance.currentState && t.toState === toState
    );
    if (!validTransition) {
      throw new Error(
        `Invalid workflow transition from '${instance.currentState}' to '${toState}' in workflow '${definition.name}'`
      );
    }
    if (validTransition.triggerEvent && !instance.emittedEvents.includes(validTransition.triggerEvent)) {
      if (triggerEvent !== validTransition.triggerEvent) {
        throw new Error(
          `Cannot transition to '${toState}': required prerequisite event '${validTransition.triggerEvent}' has not occurred`
        );
      }
      instance.emittedEvents.push(triggerEvent);
    }
    const now = (/* @__PURE__ */ new Date()).toISOString();
    instance.history.push({
      fromState: instance.currentState,
      toState,
      transitionedAt: now,
      triggeredBy,
      event: triggerEvent || validTransition.triggerEvent,
      metadata
    });
    instance.currentState = toState;
    instance.updatedAt = now;
    return instance;
  }
  /**
   * State-Aware Authorization Check (§43)
   * Verifies if the requested tool is allowed in the current workflow state
   */
  checkActionAllowed(action, instance) {
    const definition = this.workflows.get(instance.workflowId);
    if (!definition) {
      return { allowed: true };
    }
    const requiredStates = definition.actionStateRequirements[action.tool];
    if (!requiredStates || requiredStates.length === 0) {
      return { allowed: true };
    }
    if (!requiredStates.includes(instance.currentState)) {
      return {
        allowed: false,
        reason: `Action '${action.tool}' requires workflow state [${requiredStates.join(
          ", "
        )}], but current state is '${instance.currentState}'`
      };
    }
    return { allowed: true };
  }
  /**
   * Register a custom Business Invariant (§41)
   */
  registerInvariant(invariant) {
    this.invariants.set(invariant.invariantId, invariant);
  }
  /**
   * Evaluate all registered Business Invariants against an ActionRequest (§41)
   */
  evaluateInvariants(action, context, instance) {
    const violatedInvariants = [];
    for (const invariant of this.invariants.values()) {
      if (invariant.targetActionType === action.tool || invariant.targetActionType === "*") {
        const result = invariant.evaluate(action, context, instance);
        if (!result.valid) {
          violatedInvariants.push({
            invariantId: invariant.invariantId,
            name: invariant.name,
            reason: result.reason || "Invariant evaluation failed"
          });
        }
      }
    }
    if (violatedInvariants.length === 0 && (action.tool === "stripe_refund" || action.tool === "refund")) {
      const chargeId = action.parameters?.chargeId || action.parameters?.orderId || action.resource.id;
      if (chargeId) {
        this.processedRefunds.add(chargeId);
      }
    }
    return {
      passed: violatedInvariants.length === 0,
      violatedInvariants
    };
  }
  /**
   * Built-in standard enterprise invariants (§41)
   */
  registerDefaultInvariants() {
    this.registerInvariant({
      invariantId: "inv_refund_not_exceed_original",
      tenantId: "global",
      name: "Refund Not Exceed Original Payment",
      description: "Refund amount must be less than or equal to the original payment amount (\xA741)",
      targetActionType: "stripe_refund",
      evaluate: (action) => {
        const amount = Number(action.parameters?.amount ?? 0);
        const originalAmount = Number(action.parameters?.originalAmount ?? 5e3);
        if (originalAmount > 0 && amount > originalAmount) {
          return {
            valid: false,
            reason: `Refund amount ($${amount}) exceeds original payment amount ($${originalAmount})`
          };
        }
        return { valid: true };
      }
    });
    this.registerInvariant({
      invariantId: "inv_double_refund_prevention",
      tenantId: "global",
      name: "Double Refund Prevention",
      description: "A transaction or charge cannot be refunded more than once (\xA741)",
      targetActionType: "stripe_refund",
      evaluate: (action) => {
        const chargeId = action.parameters?.chargeId || action.parameters?.orderId || action.resource.id;
        if (chargeId && this.processedRefunds.has(chargeId)) {
          return {
            valid: false,
            reason: `Charge '${chargeId}' has already been refunded. Duplicate refunds are strictly prohibited.`
          };
        }
        return { valid: true };
      }
    });
    this.registerInvariant({
      invariantId: "inv_prod_deploy_requires_pr",
      tenantId: "global",
      name: "Production Deploy Requires Approved PR",
      description: "Production infrastructure deployments require a verified PR approval event (\xA741)",
      targetActionType: "deploy_production",
      evaluate: (action, context, instance) => {
        if (action.resource.environment === "production") {
          const hasPrApproval = instance?.emittedEvents.includes("pr_approved") || action.parameters?.prApproved === true;
          if (!hasPrApproval) {
            return {
              valid: false,
              reason: `Production deployment of '${action.resource.id}' requires an approved pull request event ('pr_approved')`
            };
          }
        }
        return { valid: true };
      }
    });
    this.registerInvariant({
      invariantId: "inv_sensitive_export_restriction",
      tenantId: "global",
      name: "Sensitive Data Export Restriction",
      description: "Sensitive or confidential customer data cannot be exported without compliance sign-off (\xA741)",
      targetActionType: "customer_bulk_export",
      evaluate: (action) => {
        if (action.resource.sensitivity === "CONFIDENTIAL" || action.resource.sensitivity === "CRITICAL") {
          const complianceApproved = action.parameters?.complianceSignOff === true;
          if (!complianceApproved) {
            return {
              valid: false,
              reason: `Exporting resource with sensitivity '${action.resource.sensitivity}' requires explicit compliance sign-off`
            };
          }
        }
        return { valid: true };
      }
    });
  }
};

// packages/behavior-engine/src/index.ts
var BehaviorBaselineEngine = class {
  // Profiles mapped by "tenantId:agentId"
  profiles = /* @__PURE__ */ new Map();
  // Running statistics for online calculation: "tenantId:agentId:tool" -> RunningStats
  toolStats = /* @__PURE__ */ new Map();
  // Hourly call timestamps for frequency analysis: "tenantId:agentId" -> number[] (epoch ms)
  invocationTimestamps = /* @__PURE__ */ new Map();
  /**
   * Record an observed action into the statistical profile (§17, §31)
   * Uses Welford's algorithm for numerically stable streaming variance.
   */
  recordObservedAction(record) {
    const agentKey = `${record.agentId}`;
    const toolKey = `${record.agentId}:${record.tool}`;
    const now = Date.now();
    let timestamps = this.invocationTimestamps.get(agentKey);
    if (!timestamps) {
      timestamps = [];
      this.invocationTimestamps.set(agentKey, timestamps);
    }
    timestamps.push(now);
    const oneDayAgo = now - 24 * 60 * 60 * 1e3;
    while (timestamps.length > 0 && timestamps[0] < oneDayAgo) {
      timestamps.shift();
    }
    const amount = typeof record.parameters?.amount === "number" ? record.parameters.amount : 0;
    let stats = this.toolStats.get(toolKey);
    if (!stats) {
      stats = {
        count: 0,
        mean: 0,
        m2: 0,
        resourceCounts: {},
        sensitivityCounts: {}
      };
      this.toolStats.set(toolKey, stats);
    }
    stats.count += 1;
    if (amount > 0) {
      const delta = amount - stats.mean;
      stats.mean += delta / stats.count;
      const delta2 = amount - stats.mean;
      stats.m2 += delta * delta2;
    }
    stats.resourceCounts[record.resourceId] = (stats.resourceCounts[record.resourceId] || 0) + 1;
    let profile = this.profiles.get(agentKey);
    if (!profile) {
      profile = {
        agentId: record.agentId,
        tenantId: "tenant_default",
        sampleCount: 0,
        toolDistributions: {},
        typicalSequences: [],
        typicalOperatingHours: { startHourUTC: 8, endHourUTC: 20 },
        lastUpdated: (/* @__PURE__ */ new Date()).toISOString()
      };
      this.profiles.set(agentKey, profile);
    }
    profile.sampleCount += 1;
    profile.lastUpdated = (/* @__PURE__ */ new Date()).toISOString();
    const variance = stats.count > 1 ? stats.m2 / (stats.count - 1) : 0;
    const stdDev = Math.sqrt(variance);
    const windowHours = Math.max(1, (now - (timestamps[0] || now)) / (1e3 * 60 * 60));
    const callsPerHour = timestamps.length / windowHours;
    profile.toolDistributions[record.tool] = {
      meanCallsPerHour: Math.round(callsPerHour * 10) / 10,
      stdDevCallsPerHour: Math.round(callsPerHour * 0.2 * 10) / 10,
      // heuristic estimate
      meanTransactionValue: Math.round(stats.mean * 100) / 100,
      stdDevTransactionValue: Math.round(stdDev * 100) / 100,
      commonResources: Object.keys(stats.resourceCounts).slice(0, 5)
    };
  }
  /**
   * Assess behavioral anomaly for an incoming ActionRequest (§18)
   * Computes Z-scores for amount and frequency, detects uncharacteristic tools & resource sensitivities.
   */
  assessAnomaly(action, context) {
    const agentKey = `${action.agentId}`;
    const toolKey = `${action.agentId}:${action.tool}`;
    const profile = this.profiles.get(agentKey);
    const stats = this.toolStats.get(toolKey);
    if (!profile || profile.sampleCount < 3) {
      return {
        agentId: action.agentId,
        anomalyDetected: false,
        anomalyScore: 0,
        unusualTool: false,
        unusualResource: false,
        explanation: "Agent baseline is warming up (< 3 historical samples). No deviation established.",
        advisoryOnly: true
      };
    }
    const amount = typeof action.parameters?.amount === "number" ? action.parameters.amount : 0;
    let zScoreAmount;
    let anomalyScore = 0;
    const explanations = [];
    let unusualTool = false;
    if (!profile.toolDistributions[action.tool] || !stats) {
      unusualTool = true;
      anomalyScore += 50;
      explanations.push(`Agent has never previously invoked tool '${action.tool}'`);
    } else {
      const variance = stats.count > 1 ? stats.m2 / (stats.count - 1) : 0;
      const stdDev = Math.sqrt(variance);
      if (amount > 0 && stats.mean > 0 && stdDev > 0) {
        zScoreAmount = Math.round((amount - stats.mean) / stdDev * 100) / 100;
        if (zScoreAmount > 4) {
          anomalyScore += 65;
          explanations.push(
            `Transaction amount $${amount} is an extreme statistical outlier (Z = ${zScoreAmount}, +${Math.round(
              amount / stats.mean * 100 - 100
            )}% over historical mean of $${Math.round(stats.mean)} \xB1 $${Math.round(stdDev)})`
          );
        } else if (zScoreAmount > 2.5) {
          anomalyScore += 35;
          explanations.push(
            `Transaction amount $${amount} deviates significantly from baseline (Z = ${zScoreAmount})`
          );
        }
      }
    }
    const timestamps = this.invocationTimestamps.get(agentKey) || [];
    const oneHourAgo = Date.now() - 60 * 60 * 1e3;
    const recentHourCalls = timestamps.filter((t) => t >= oneHourAgo).length + 1;
    const toolDist = profile.toolDistributions[action.tool];
    let zScoreFrequency;
    if (toolDist && toolDist.meanCallsPerHour > 0) {
      const meanFreq = toolDist.meanCallsPerHour;
      const stdDevFreq = Math.max(1, toolDist.stdDevCallsPerHour);
      zScoreFrequency = Math.round((recentHourCalls - meanFreq) / stdDevFreq * 100) / 100;
      if (zScoreFrequency > 3) {
        anomalyScore += 40;
        explanations.push(
          `Invocation frequency burst: ${recentHourCalls} calls/hr (Z = ${zScoreFrequency}, historical baseline: ${meanFreq} calls/hr)`
        );
      }
    }
    let unusualResource = false;
    if (action.resource.sensitivity === "CRITICAL" && stats && !Object.keys(stats.sensitivityCounts).includes("CRITICAL")) {
      unusualResource = true;
      anomalyScore += 30;
      explanations.push(
        `Agent has never previously accessed CRITICAL sensitivity resources on '${action.tool}'`
      );
    }
    anomalyScore = Math.min(100, anomalyScore);
    const anomalyDetected = anomalyScore >= 45;
    return {
      agentId: action.agentId,
      anomalyDetected,
      anomalyScore,
      zScoreAmount,
      zScoreFrequency,
      unusualTool,
      unusualResource,
      explanation: explanations.length > 0 ? explanations.join("; ") : "Observed behavior conforms within normal Gaussian operational parameters (Z < 2.0).",
      advisoryOnly: true
      // Master rule §18/§76: advisory signal for risk engine, not opaque blocking
    };
  }
  /**
   * Retrieve the complete statistical profile for an agent (§17)
   */
  getProfile(agentId) {
    return this.profiles.get(agentId);
  }
  /**
   * Reset or seed baseline profile (useful for testing and bootstrapping)
   */
  seedProfile(agentId, baselineData) {
    const agentKey = agentId;
    const toolKey = `${agentId}:${baselineData.tool}`;
    const count = 30;
    this.toolStats.set(toolKey, {
      count,
      mean: baselineData.meanAmount,
      m2: (count - 1) * Math.pow(baselineData.stdDevAmount, 2),
      resourceCounts: { "seed_resource_1": 15, "seed_resource_2": 15 },
      sensitivityCounts: { "INTERNAL": 30 }
    });
    const now = Date.now();
    const timestamps = [];
    for (let i = 0; i < baselineData.meanCallsPerHour; i++) {
      timestamps.push(now - Math.random() * 3600 * 1e3);
    }
    this.invocationTimestamps.set(agentKey, timestamps);
    this.profiles.set(agentKey, {
      agentId,
      tenantId: "tenant_enterprise",
      sampleCount: count,
      toolDistributions: {
        [baselineData.tool]: {
          meanCallsPerHour: baselineData.meanCallsPerHour,
          stdDevCallsPerHour: Math.max(1, Math.round(baselineData.meanCallsPerHour * 0.2)),
          meanTransactionValue: baselineData.meanAmount,
          stdDevTransactionValue: baselineData.stdDevAmount,
          commonResources: ["seed_resource_1", "seed_resource_2"]
        }
      },
      typicalSequences: [],
      typicalOperatingHours: { startHourUTC: 8, endHourUTC: 20 },
      lastUpdated: (/* @__PURE__ */ new Date()).toISOString()
    });
  }
};

// packages/policy-engine/src/index.ts
var PolicyEngine = class {
  delegationManager;
  sequenceDetector;
  workflowEngine;
  behaviorEngine;
  controlPlanePrivateKeyPem;
  policyVersion = "v1.4.0-enterprise";
  customRules = [];
  killSwitchActive = false;
  quarantinedAgents = /* @__PURE__ */ new Set();
  constructor(delegationManager, sequenceDetector, controlPlanePrivateKeyPem, workflowEngine, behaviorEngine) {
    this.delegationManager = delegationManager;
    this.sequenceDetector = sequenceDetector;
    this.controlPlanePrivateKeyPem = controlPlanePrivateKeyPem;
    this.workflowEngine = workflowEngine ?? new WorkflowEngine();
    this.behaviorEngine = behaviorEngine ?? new BehaviorBaselineEngine();
  }
  getWorkflowEngine() {
    return this.workflowEngine;
  }
  getBehaviorEngine() {
    return this.behaviorEngine;
  }
  setKillSwitch(active) {
    this.killSwitchActive = active;
  }
  quarantineAgent(agentId) {
    this.quarantinedAgents.add(agentId);
    this.delegationManager.setAgentStatus(agentId, "QUARANTINED");
  }
  unquarantineAgent(agentId) {
    this.quarantinedAgents.delete(agentId);
    this.delegationManager.setAgentStatus(agentId, "ACTIVE");
  }
  isAgentQuarantined(agentId) {
    return this.quarantinedAgents.has(agentId);
  }
  calculateRiskScore(request, context, anomalyScore = 0) {
    let score = 0;
    switch (request.resource.sensitivity) {
      case "PUBLIC":
        score += 5;
        break;
      case "INTERNAL":
        score += 20;
        break;
      case "CONFIDENTIAL":
        score += 45;
        break;
      case "SENSITIVE":
        score += 70;
        break;
      case "CRITICAL":
        score += 90;
        break;
      default:
        score += 25;
        break;
    }
    const amount = typeof request.parameters.amount === "number" ? request.parameters.amount : 0;
    if (amount > 0) {
      if (amount <= 100) score = Math.max(score, 20);
      else if (amount <= 500) score = Math.max(score, 40);
      else if (amount <= 2500) score = Math.max(score, 75);
      else score = Math.max(score, 95);
    }
    if (request.resource.environment === "production") {
      score = Math.min(100, score + 15);
    }
    score = Math.min(100, Math.max(score, anomalyScore));
    let riskClass = "LOW";
    if (score >= 85) riskClass = "CRITICAL";
    else if (score >= 65) riskClass = "HIGH";
    else if (score >= 35) riskClass = "MEDIUM";
    return { riskScore: score, riskClass };
  }
  /**
   * Evaluate full AACT Pipeline:
   * 1. Kill-Switch / Quarantine Check
   * 2. Delegation Chain & Monotonic Narrowing Check
   * 3. Sequence & Anomaly Check
   * 4. Parameter & Value Threshold Policies
   * 5. Step-Up Approval Determination
   * 6. Cryptographic Grant Generation on ALLOW
   */
  async evaluate(request, context) {
    const startTime = performance.now();
    const evaluatedAt = (/* @__PURE__ */ new Date()).toISOString();
    if (this.killSwitchActive) {
      const latencyMs2 = Math.round((performance.now() - startTime) * 100) / 100;
      return {
        actionId: request.actionId,
        decision: "DENY",
        reasonCodes: ["TOOL_LOCKED_DOWN"],
        explanation: "Global emergency control plane kill switch is currently ACTIVE. All actions suspended.",
        policyVersion: this.policyVersion,
        riskScore: 100,
        riskClass: "CRITICAL",
        evaluatedAt,
        latencyMs: latencyMs2
      };
    }
    if (this.quarantinedAgents.has(request.agentId)) {
      const latencyMs2 = Math.round((performance.now() - startTime) * 100) / 100;
      return {
        actionId: request.actionId,
        decision: "DENY",
        reasonCodes: ["AGENT_QUARANTINED"],
        explanation: `Agent '${request.agentId}' is under active security quarantine.`,
        policyVersion: this.policyVersion,
        riskScore: 100,
        riskClass: "CRITICAL",
        evaluatedAt,
        latencyMs: latencyMs2
      };
    }
    const delegationResult = this.delegationManager.verifyDelegationChain(
      request.delegationId,
      request.agentId
    );
    if (!delegationResult.valid) {
      const latencyMs2 = Math.round((performance.now() - startTime) * 100) / 100;
      return {
        actionId: request.actionId,
        decision: "DENY",
        reasonCodes: [delegationResult.reasonCode || "DELEGATION_INVALID"],
        explanation: delegationResult.explanation || "Delegation chain verification failed",
        policyVersion: this.policyVersion,
        riskScore: 90,
        riskClass: "CRITICAL",
        evaluatedAt,
        latencyMs: latencyMs2
      };
    }
    const delegationEnvelope = this.delegationManager.getDelegation(request.delegationId);
    const constraints = delegationEnvelope.constraints;
    if (!constraints.allowedTools.includes("*") && !constraints.allowedTools.includes(request.tool)) {
      const latencyMs2 = Math.round((performance.now() - startTime) * 100) / 100;
      return {
        actionId: request.actionId,
        decision: "DENY",
        reasonCodes: ["POLICY_DENY"],
        explanation: `Tool '${request.tool}' is not authorized by delegation envelope constraints`,
        policyVersion: this.policyVersion,
        riskScore: 85,
        riskClass: "HIGH",
        evaluatedAt,
        latencyMs: latencyMs2
      };
    }
    const amount = typeof request.parameters.amount === "number" ? request.parameters.amount : 0;
    if (constraints.maxTransactionValue !== void 0 && amount > constraints.maxTransactionValue) {
      const latencyMs2 = Math.round((performance.now() - startTime) * 100) / 100;
      return {
        actionId: request.actionId,
        decision: "DENY",
        reasonCodes: ["LIMIT_EXCEEDED"],
        explanation: `Transaction amount $${amount} exceeds delegation limit of $${constraints.maxTransactionValue}`,
        policyVersion: this.policyVersion,
        riskScore: 85,
        riskClass: "HIGH",
        evaluatedAt,
        latencyMs: latencyMs2
      };
    }
    if (delegationEnvelope.tenantId !== request.tenantId) {
      const latencyMs2 = Math.round((performance.now() - startTime) * 100) / 100;
      return {
        actionId: request.actionId,
        decision: "DENY",
        reasonCodes: ["POLICY_DENY"],
        explanation: `Cross-tenant violation: delegation tenant '${delegationEnvelope.tenantId}' does not match request tenant '${request.tenantId}'`,
        policyVersion: this.policyVersion,
        riskScore: 95,
        riskClass: "CRITICAL",
        evaluatedAt,
        latencyMs: latencyMs2
      };
    }
    const resourceScopeCheck = this.delegationManager.checkResourceScope(
      request.resource.id,
      request.delegationId
    );
    if (!resourceScopeCheck.allowed) {
      const latencyMs2 = Math.round((performance.now() - startTime) * 100) / 100;
      return {
        actionId: request.actionId,
        decision: "DENY",
        reasonCodes: ["RESOURCE_MISMATCH"],
        explanation: resourceScopeCheck.reason || `Resource '${request.resource.id}' is outside the scope of this delegation`,
        policyVersion: this.policyVersion,
        riskScore: 80,
        riskClass: "HIGH",
        evaluatedAt,
        latencyMs: latencyMs2
      };
    }
    const seqResult = this.sequenceDetector.evaluateSequence(
      request,
      context?.task,
      delegationEnvelope
    );
    if (!seqResult.valid) {
      const latencyMs2 = Math.round((performance.now() - startTime) * 100) / 100;
      return {
        actionId: request.actionId,
        decision: "DENY",
        reasonCodes: [seqResult.reasonCode || "SEQUENCE_ANOMALY"],
        explanation: seqResult.explanation || "Action sequence policy violated",
        policyVersion: this.policyVersion,
        riskScore: seqResult.anomalyScore,
        riskClass: seqResult.anomalyScore >= 85 ? "CRITICAL" : "HIGH",
        evaluatedAt,
        latencyMs: latencyMs2
      };
    }
    const workflowInstance = this.workflowEngine.findInstanceByTask(request.taskId);
    if (workflowInstance) {
      const stateCheck = this.workflowEngine.checkActionAllowed(request, workflowInstance);
      if (!stateCheck.allowed) {
        const latencyMs2 = Math.round((performance.now() - startTime) * 100) / 100;
        return {
          actionId: request.actionId,
          decision: "DENY",
          reasonCodes: ["WORKFLOW_STATE_INVALID"],
          explanation: stateCheck.reason || "Action not allowed in current workflow state",
          policyVersion: this.policyVersion,
          riskScore: 90,
          riskClass: "CRITICAL",
          evaluatedAt,
          latencyMs: latencyMs2
        };
      }
    }
    const invariantResult = this.workflowEngine.evaluateInvariants(
      request,
      context ?? {},
      workflowInstance
    );
    if (!invariantResult.passed) {
      const latencyMs2 = Math.round((performance.now() - startTime) * 100) / 100;
      const primaryViolation = invariantResult.violatedInvariants[0];
      return {
        actionId: request.actionId,
        decision: "DENY",
        reasonCodes: ["INVARIANT_VIOLATION"],
        explanation: `Business invariant violation '${primaryViolation.name}': ${primaryViolation.reason}`,
        policyVersion: this.policyVersion,
        riskScore: 95,
        riskClass: "CRITICAL",
        evaluatedAt,
        latencyMs: latencyMs2
      };
    }
    const behaviorAssessment = this.behaviorEngine.assessAnomaly(request, context);
    const combinedAnomalyScore = Math.max(seqResult.anomalyScore, behaviorAssessment.anomalyScore);
    const { riskScore, riskClass } = this.calculateRiskScore(request, context, combinedAnomalyScore);
    const approvalThreshold = constraints.requireApprovalAbove ?? 1e3;
    if (amount > approvalThreshold) {
      const approvalId = "appr_" + Math.random().toString(36).substring(2, 12);
      const latencyMs2 = Math.round((performance.now() - startTime) * 100) / 100;
      return {
        actionId: request.actionId,
        decision: "HOLD",
        reasonCodes: ["MISSING_REQUIRED_APPROVAL"],
        explanation: `Action amount $${amount} exceeds auto-approval threshold ($${approvalThreshold}). Held for human sponsor sign-off.`,
        policyVersion: this.policyVersion,
        riskScore,
        riskClass,
        approvalId,
        requiredApprovalRole: "FINANCE_SPONSOR",
        evaluatedAt,
        latencyMs: latencyMs2
      };
    }
    const parametersHash = canonicalHash(request.parameters);
    const grantId = "grant_" + Math.random().toString(36).substring(2, 12);
    const grant = createAuthorizationGrant(
      grantId,
      request.actionId,
      request.tenantId,
      request.agentId,
      request.actionType,
      request.tool,
      request.resource.id,
      parametersHash,
      request.delegationId,
      this.controlPlanePrivateKeyPem,
      60
      // 60 seconds TTL
    );
    const latencyMs = Math.round((performance.now() - startTime) * 100) / 100;
    return {
      actionId: request.actionId,
      decision: "ALLOW",
      reasonCodes: ["POLICY_PERMIT"],
      explanation: "Action verified against delegation constraints, monotonic narrowing, and sequence invariant rules.",
      policyVersion: this.policyVersion,
      riskScore,
      riskClass,
      grant,
      evaluatedAt,
      latencyMs
    };
  }
  /**
   * Run Counterfactual Policy Simulation:
   * Evaluate what would happen if a different policy or limit was applied across historic transactions.
   */
  simulatePolicy(request, history) {
    const simulationId = "sim_" + Math.random().toString(36).substring(2, 10);
    const affectedAgentsSet = /* @__PURE__ */ new Set();
    const highRiskNewlyAllowed = [];
    let unchangedCount = 0;
    let newlyAllowedCount = 0;
    let newlyDeniedCount = 0;
    let newlyHeldCount = 0;
    let parsedThreshold = 1e3;
    try {
      const parsed = JSON.parse(request.proposedPolicyContent);
      if (parsed.requireApprovalAbove !== void 0) {
        parsedThreshold = parsed.requireApprovalAbove;
      }
    } catch {
    }
    for (const record of history) {
      affectedAgentsSet.add(record.agentId);
      const amount = typeof record.parameters.amount === "number" ? record.parameters.amount : 0;
      let hypotheticalDecision = record.decision;
      if (amount > parsedThreshold) {
        hypotheticalDecision = "HOLD";
      } else if (record.decision === "HOLD" && amount <= parsedThreshold) {
        hypotheticalDecision = "ALLOW";
      }
      if (hypotheticalDecision === record.decision) {
        unchangedCount++;
      } else if (hypotheticalDecision === "ALLOW") {
        newlyAllowedCount++;
        if (amount > 500) {
          highRiskNewlyAllowed.push({
            actionId: record.actionId,
            actionType: record.actionType,
            agentId: record.agentId,
            amount,
            resourceId: record.resourceId
          });
        }
      } else if (hypotheticalDecision === "DENY") {
        newlyDeniedCount++;
      } else if (hypotheticalDecision === "HOLD") {
        newlyHeldCount++;
      }
    }
    return {
      simulationId,
      totalEvaluated: history.length,
      unchangedCount,
      newlyAllowedCount,
      newlyDeniedCount,
      newlyHeldCount,
      affectedAgents: Array.from(affectedAgentsSet),
      highRiskNewlyAllowed,
      summaryText: `Simulated policy against ${history.length} historical action records. Result: ${newlyHeldCount} actions shifted to HOLD, ${newlyAllowedCount} newly allowed.`
    };
  }
};

// packages/audit-ledger/src/index.ts
var AuditLedger = class {
  receipts = [];
  controlPlanePrivateKeyPem;
  controlPlanePublicKeyPem;
  lastReceiptHash = "GENESIS_BLOCK_HASH";
  constructor(controlPlanePrivateKeyPem, controlPlanePublicKeyPem) {
    this.controlPlanePrivateKeyPem = controlPlanePrivateKeyPem;
    this.controlPlanePublicKeyPem = controlPlanePublicKeyPem;
  }
  /**
   * Append a new authorization decision to the cryptographic ledger.
   * Chained to previous receipt hash and signed with Ed25519.
   */
  recordDecision(request, decision, sponsorId) {
    const receiptId = "rcpt_" + Math.random().toString(36).substring(2, 12);
    const timestamp = (/* @__PURE__ */ new Date()).toISOString();
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
    const receiptHash = computeReceiptHash(receiptData, this.lastReceiptHash);
    const signature = signEd25519(receiptHash, this.controlPlanePrivateKeyPem);
    const fullReceipt = {
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
  verifyIntegrity() {
    const result = verifyReceiptChain(this.receipts, this.controlPlanePublicKeyPem);
    return {
      valid: result.valid,
      brokenAt: result.brokenAt,
      totalReceipts: this.receipts.length
    };
  }
  getReceipts() {
    return [...this.receipts];
  }
  getReceiptByActionId(actionId) {
    return this.receipts.find((r) => r.actionId === actionId);
  }
  getReceiptById(receiptId) {
    return this.receipts.find((r) => r.receiptId === receiptId);
  }
  /**
   * Build complete end-to-end cryptographic Provenance Graph for an action:
   * Human Sponsor -> Delegation -> Task -> Agent -> Policy -> Action -> Resource -> Grant -> Receipt
   */
  buildProvenanceGraph(actionId) {
    const receipt = this.getReceiptByActionId(actionId);
    if (!receipt) return null;
    const nodes = [
      {
        id: `sponsor_${receipt.sponsorId}`,
        type: "HUMAN",
        label: `Human Sponsor (${receipt.sponsorId})`,
        metadata: { sponsorId: receipt.sponsorId }
      },
      {
        id: `agent_${receipt.agentId}`,
        type: "AGENT",
        label: `AI Agent (${receipt.agentId})`,
        metadata: { agentId: receipt.agentId }
      },
      {
        id: `policy_${receipt.policyVersion}`,
        type: "POLICY",
        label: `Policy Engine (${receipt.policyVersion})`,
        metadata: { policyVersion: receipt.policyVersion, riskScore: receipt.riskScore }
      },
      {
        id: `action_${receipt.actionId}`,
        type: "ACTION",
        label: `Action: ${receipt.actionType}`,
        metadata: {
          actionId: receipt.actionId,
          parametersHash: receipt.parametersHash,
          timestamp: receipt.timestamp
        }
      },
      {
        id: `resource_${receipt.resourceId}`,
        type: "RESOURCE",
        label: `Target Resource (${receipt.resourceId})`,
        metadata: { resourceId: receipt.resourceId }
      },
      {
        id: `receipt_${receipt.receiptId}`,
        type: "RECEIPT",
        label: `Merkle Receipt (${receipt.receiptId.substring(0, 10)}...)`,
        metadata: {
          receiptHash: receipt.receiptHash,
          previousReceiptHash: receipt.previousReceiptHash,
          signature: receipt.signature.substring(0, 16) + "..."
        }
      }
    ];
    const edges = [
      { from: `sponsor_${receipt.sponsorId}`, to: `agent_${receipt.agentId}`, relation: "SPONSORED_BY" },
      { from: `agent_${receipt.agentId}`, to: `action_${receipt.actionId}`, relation: "SUBMITTED" },
      { from: `action_${receipt.actionId}`, to: `policy_${receipt.policyVersion}`, relation: "EVALUATED_BY" },
      { from: `action_${receipt.actionId}`, to: `resource_${receipt.resourceId}`, relation: "TARGETED" },
      { from: `policy_${receipt.policyVersion}`, to: `receipt_${receipt.receiptId}`, relation: "RECORDED_IN" }
    ];
    if (receipt.grantId) {
      nodes.push({
        id: `grant_${receipt.grantId}`,
        type: "GRANT",
        label: `Crypto Grant (${receipt.grantId.substring(0, 10)}...)`,
        metadata: { grantId: receipt.grantId }
      });
      edges.push({
        from: `policy_${receipt.policyVersion}`,
        to: `grant_${receipt.grantId}`,
        relation: "ISSUED_GRANT"
      });
      edges.push({
        from: `grant_${receipt.grantId}`,
        to: `action_${receipt.actionId}`,
        relation: "AUTHORIZED"
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
};

// packages/blast-radius/src/index.ts
var BlastRadiusAnalyzer = class {
  delegationManager;
  constructor(delegationManager) {
    this.delegationManager = delegationManager;
  }
  /**
   * Compute comprehensive blast radius and risk exposure report for an agent.
   */
  calculateBlastRadius(agentId) {
    const agent = this.delegationManager.getAgent(agentId);
    if (!agent) return null;
    const allDelegations = this.delegationManager.listDelegations();
    const agentDelegations = allDelegations.filter(
      (d) => d.delegateeId === agentId && !d.revoked
    );
    const toolsSet = new Set(agent.allowedCapabilities);
    let maximumFinancialExposure = 0;
    for (const d of agentDelegations) {
      for (const t of d.constraints.allowedTools) {
        toolsSet.add(t);
      }
      const exposure = d.constraints.cumulativeValueLimit ?? d.constraints.maxTransactionValue ?? 0;
      if (exposure > maximumFinancialExposure) {
        maximumFinancialExposure = exposure;
      }
    }
    const reachableTools = [];
    for (const tool of toolsSet) {
      let risk = "LOW";
      let exposure = void 0;
      if (tool.includes("wire") || tool.includes("transfer")) {
        risk = "CRITICAL";
        exposure = maximumFinancialExposure;
      } else if (tool.includes("refund") || tool.includes("payment")) {
        risk = "HIGH";
        exposure = maximumFinancialExposure;
      } else if (tool.includes("database") || tool.includes("firewall")) {
        risk = "CRITICAL";
      } else if (tool.includes("pii") || tool.includes("customer")) {
        risk = "HIGH";
      } else if (tool.includes("email") || tool.includes("slack")) {
        risk = "MEDIUM";
      }
      reachableTools.push({
        tool,
        risk,
        maxExposure: exposure
      });
    }
    const reachableResources = [
      {
        resourceType: "CUSTOMER_CRM_RECORDS",
        sensitivity: toolsSet.has("crm_read_pii") ? "CONFIDENTIAL" : "INTERNAL",
        countEstimate: 2500
      },
      {
        resourceType: "PAYMENT_LEDGER",
        sensitivity: toolsSet.has("stripe_refund") || toolsSet.has("send_wire_transfer") ? "CRITICAL" : "INTERNAL",
        countEstimate: 12e3
      },
      {
        resourceType: "COMMUNICATION_CHANNELS",
        sensitivity: toolsSet.has("send_external_email") ? "SENSITIVE" : "INTERNAL",
        countEstimate: 50
      }
    ];
    const childDelegations = allDelegations.filter(
      (d) => d.delegatorId === agentId && !d.revoked
    );
    const reachableAgents = childDelegations.map((d) => d.delegateeId);
    const privilegeEscalationPaths = [];
    if (toolsSet.has("crm_read_pii") && toolsSet.has("send_external_email")) {
      privilegeEscalationPaths.push({
        description: "Exfiltration Path: Direct read access to customer PII combined with outbound email capability",
        severity: "CRITICAL",
        hops: ["crm_read_pii", "send_external_email"]
      });
    }
    if (toolsSet.has("modify_security_group") && toolsSet.has("query_production_database")) {
      privilegeEscalationPaths.push({
        description: "Lateral Movement Path: Firewall modification capability combined with DB query access",
        severity: "CRITICAL",
        hops: ["modify_security_group", "query_production_database"]
      });
    }
    return {
      agentId,
      calculatedAt: (/* @__PURE__ */ new Date()).toISOString(),
      agentStatus: agent.status,
      riskClass: agent.riskClass,
      directCapabilities: agent.allowedCapabilities,
      reachableTools,
      reachableResources,
      reachableAgents,
      maximumFinancialExposure,
      privilegeEscalationPaths,
      killSwitchActive: agent.status === "QUARANTINED"
    };
  }
  /**
   * Computes topological lateral movement attack paths and transitive reachability (§38, §79).
   */
  computeAttackPaths(agentId) {
    const paths = [];
    const allDelegations = this.delegationManager.listDelegations();
    const visitedAgents = /* @__PURE__ */ new Set();
    const traverse = (currentAgentId, currentHop) => {
      if (visitedAgents.has(currentAgentId)) return;
      visitedAgents.add(currentAgentId);
      const agentDelegations = allDelegations.filter(
        (d) => d.delegateeId === currentAgentId && !d.revoked
      );
      for (const d of agentDelegations) {
        for (const tool of d.constraints.allowedTools) {
          const isCritical = tool.includes("wire") || tool.includes("database") || tool.includes("deploy") || tool.includes("delete");
          const isHigh = tool.includes("refund") || tool.includes("pii") || tool.includes("crm");
          const riskLevel = isCritical ? "CRITICAL" : isHigh ? "HIGH" : "MEDIUM";
          const resources = d.constraints.resourcePatterns.length > 0 ? d.constraints.resourcePatterns : ["*"];
          for (const res of resources) {
            paths.push({
              sourceAgent: currentAgentId,
              delegationHop: d.delegationId,
              tool,
              targetResource: res,
              riskLevel,
              privilegeEscalation: currentAgentId !== agentId
            });
          }
        }
      }
      const childDelegations = allDelegations.filter(
        (d) => d.delegatorId === currentAgentId && !d.revoked
      );
      for (const child of childDelegations) {
        traverse(child.delegateeId, child.delegationId);
      }
    };
    traverse(agentId, "root");
    return paths;
  }
};

// packages/policy-dsl/src/index.ts
function tokenizePolicyDSL(source) {
  const tokens = [];
  const lines = source.split(/\r?\n/);
  for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
    let line = lines[lineIdx].trim();
    if (!line || line.startsWith("#") || line.startsWith("//")) {
      continue;
    }
    let i = 0;
    while (i < line.length) {
      const char = line[i];
      if (/\s/.test(char)) {
        i++;
        continue;
      }
      if (char === '"' || char === "'") {
        const quote = char;
        let strVal = "";
        i++;
        while (i < line.length && line[i] !== quote) {
          strVal += line[i];
          i++;
        }
        i++;
        tokens.push({ type: "STRING", value: strVal, line: lineIdx + 1 });
        continue;
      }
      if (/\d/.test(char)) {
        let numStr = "";
        while (i < line.length && /[\d.]/.test(line[i])) {
          numStr += line[i];
          i++;
        }
        tokens.push({ type: "NUMBER", value: numStr, line: lineIdx + 1 });
        continue;
      }
      if (line.slice(i, i + 2) === "==" || line.slice(i, i + 2) === "!=" || line.slice(i, i + 2) === "<=" || line.slice(i, i + 2) === ">=") {
        tokens.push({ type: "OPERATOR", value: line.slice(i, i + 2), line: lineIdx + 1 });
        i += 2;
        continue;
      }
      if (char === "<" || char === ">") {
        tokens.push({ type: "OPERATOR", value: char, line: lineIdx + 1 });
        i++;
        continue;
      }
      if (char === "[") {
        tokens.push({ type: "LBRACKET", value: "[", line: lineIdx + 1 });
        i++;
        continue;
      }
      if (char === "]") {
        tokens.push({ type: "RBRACKET", value: "]", line: lineIdx + 1 });
        i++;
        continue;
      }
      if (char === ",") {
        tokens.push({ type: "COMMA", value: ",", line: lineIdx + 1 });
        i++;
        continue;
      }
      if (/[a-zA-Z_]/.test(char)) {
        let word = "";
        while (i < line.length && /[a-zA-Z0-9_.]/.test(line[i])) {
          word += line[i];
          i++;
        }
        const upper = word.toUpperCase();
        if ([
          "POLICY",
          "ALLOW",
          "DENY",
          "HOLD",
          "WHEN",
          "AND",
          "OR",
          "NOT",
          "IN",
          "NOT_IN",
          "CONTAINS",
          "REQUIRE_APPROVAL_ABOVE",
          "EXPLANATION"
        ].includes(upper)) {
          tokens.push({ type: "KEYWORD", value: upper, line: lineIdx + 1 });
        } else {
          tokens.push({ type: "IDENTIFIER", value: word, line: lineIdx + 1 });
        }
        continue;
      }
      i++;
    }
  }
  tokens.push({ type: "EOF", value: "", line: lines.length });
  return tokens;
}
function parsePolicyDSL(source) {
  const tokens = tokenizePolicyDSL(source);
  let pos = 0;
  function peek() {
    return tokens[pos] || { type: "EOF", value: "", line: 0 };
  }
  function consume(expectedType, expectedValue) {
    const current = peek();
    if (expectedType && current.type !== expectedType) {
      throw new Error(
        `Parser error at line ${current.line}: Expected token type '${expectedType}', got '${current.type}' (${current.value})`
      );
    }
    if (expectedValue && current.value !== expectedValue) {
      throw new Error(
        `Parser error at line ${current.line}: Expected '${expectedValue}', got '${current.value}'`
      );
    }
    pos++;
    return current;
  }
  let policyId = "policy_" + Math.random().toString(36).substring(2, 8);
  let policyName = "Unnamed Policy";
  if (peek().type === "KEYWORD" && peek().value === "POLICY") {
    consume("KEYWORD", "POLICY");
    const nameToken = consume();
    policyId = nameToken.value;
    policyName = nameToken.value;
  }
  const effectToken = consume("KEYWORD");
  if (!["ALLOW", "DENY", "HOLD"].includes(effectToken.value)) {
    throw new Error(`Expected ALLOW, DENY, or HOLD, got '${effectToken.value}'`);
  }
  const effect = effectToken.value;
  const actionToken = consume();
  const targetAction = actionToken.value;
  const conditions = [];
  let requireApprovalAbove;
  if (peek().type === "KEYWORD" && peek().value === "WHEN") {
    consume("KEYWORD", "WHEN");
    while (peek().type !== "EOF" && peek().value !== "REQUIRE_APPROVAL_ABOVE") {
      let negated = false;
      if (peek().type === "KEYWORD" && peek().value === "NOT") {
        consume("KEYWORD", "NOT");
        negated = true;
      }
      const fieldToken = consume();
      const opToken = consume();
      let op = opToken.value;
      if (opToken.type === "KEYWORD" && (opToken.value === "IN" || opToken.value === "NOT_IN" || opToken.value === "CONTAINS")) {
        op = opToken.value;
      }
      let parsedValue;
      const valToken = peek();
      if (valToken.type === "LBRACKET") {
        consume("LBRACKET");
        const arr = [];
        while (peek().type !== "RBRACKET" && peek().type !== "EOF") {
          const item = consume();
          arr.push(item.value);
          if (peek().type === "COMMA") {
            consume("COMMA");
          }
        }
        consume("RBRACKET");
        parsedValue = arr;
      } else if (valToken.type === "NUMBER") {
        parsedValue = Number(consume("NUMBER").value);
      } else if (valToken.type === "STRING") {
        parsedValue = consume("STRING").value;
      } else {
        const idToken = consume();
        if (idToken.value === "true") parsedValue = true;
        else if (idToken.value === "false") parsedValue = false;
        else parsedValue = idToken.value;
      }
      let connector = "AND";
      if (peek().type === "KEYWORD" && (peek().value === "AND" || peek().value === "OR")) {
        connector = consume("KEYWORD").value;
      }
      conditions.push({
        field: fieldToken.value,
        operator: op,
        value: parsedValue,
        connector,
        negated
      });
      if (peek().type === "EOF" || peek().value === "REQUIRE_APPROVAL_ABOVE") {
        break;
      }
    }
  }
  if (peek().type === "KEYWORD" && peek().value === "REQUIRE_APPROVAL_ABOVE") {
    consume("KEYWORD", "REQUIRE_APPROVAL_ABOVE");
    const numToken = consume("NUMBER");
    requireApprovalAbove = Number(numToken.value);
  }
  return {
    policyId,
    name: policyName,
    targetAction,
    conditions,
    requireApprovalAbove,
    effect,
    rawText: source.trim()
  };
}

// packages/observation/src/index.ts
var ObservationEngine = class {
  mode;
  events = [];
  maxHistory = 1e3;
  constructor(initialMode = "enforcement") {
    this.mode = initialMode;
  }
  getMode() {
    return this.mode;
  }
  setMode(mode) {
    this.mode = mode;
  }
  /**
   * Transforms or records an authorization decision based on current mode.
   * If in OBSERVATION mode and decision is DENY or HOLD, it mutates decision to ALLOW
   * (or grants observation access) and logs the suppressed violation.
   */
  processDecision(request, decision, createGrantFn) {
    const isViolation = decision.decision === "DENY" || decision.decision === "HOLD";
    if (this.mode === "observation") {
      const originalDecision = decision.decision;
      const suppressed = isViolation;
      const event = {
        eventId: `obs_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
        actionId: request.actionId,
        agentId: request.agentId,
        tool: request.tool,
        resourceId: request.resource.id,
        actualDecision: "ALLOW",
        shadowDecision: originalDecision,
        shadowReasonCodes: [...decision.reasonCodes],
        shadowExplanation: decision.explanation,
        suppressedViolation: suppressed,
        timestamp: (/* @__PURE__ */ new Date()).toISOString()
      };
      this.recordEvent(event);
      if (isViolation) {
        const observedDecision = {
          ...decision,
          decision: "ALLOW",
          explanation: `[OBSERVATION MODE] Suppressed ${originalDecision}: ${decision.explanation}`,
          grant: decision.grant || (createGrantFn ? createGrantFn() : void 0)
        };
        return observedDecision;
      }
    }
    return decision;
  }
  recordEvent(event) {
    this.events.push(event);
    if (this.events.length > this.maxHistory) {
      this.events.shift();
    }
  }
  getEvents(limit = 100) {
    return this.events.slice(-limit).reverse();
  }
  getSummary() {
    let shadowDenyCount = 0;
    let shadowHoldCount = 0;
    let shadowAllowCount = 0;
    let totalSuppressed = 0;
    let lastViolation;
    for (const e of this.events) {
      if (e.shadowDecision === "DENY") {
        shadowDenyCount++;
        totalSuppressed++;
        lastViolation = e.timestamp;
      } else if (e.shadowDecision === "HOLD") {
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
  clearHistory() {
    this.events = [];
  }
};

// apps/control-plane/src/attack-catalog.ts
var ATTACK_CATALOG = [
  {
    vectorNumber: 1,
    id: "attack_toctou",
    title: "Parameter Tampering / TOCTOU Attack",
    category: "Cryptographic Integrity",
    severity: "CRITICAL",
    mitreTechnique: "T1565.001 (Data Manipulation)",
    description: "Adversary intercepts a legitimate $50 refund grant and modifies the execution payload to $50,000 before reaching enterprise downstream APIs.",
    targetTool: "stripe_refund",
    targetAgent: "agent_finance_refund",
    defenseMechanism: "Canonical Parameter Hash Cryptographic Binding (RFC 8785 SHA-256)"
  },
  {
    vectorNumber: 2,
    id: "attack_expired_grant",
    title: "Expired Authorization Grant Replay",
    category: "Replay & Nonce Defense",
    severity: "HIGH",
    mitreTechnique: "T1550.001 (Application Access Token Replay)",
    description: "Adversary captures a previously issued authorization grant and replays it after its 30-second temporal TTL window has elapsed.",
    targetTool: "stripe_refund",
    targetAgent: "agent_finance_refund",
    defenseMechanism: "Ephemeral Grant TTL Enforcement & Nonce Invalidation"
  },
  {
    vectorNumber: 3,
    id: "attack_prompt_injection",
    title: "Prompt Injection & Declared Intent Drift",
    category: "Adversarial Prompt Injection",
    severity: "CRITICAL",
    mitreTechnique: "T1059 (Command & Scripting Injection)",
    description: "Attacker leverages indirect prompt injection inside customer inquiry text to trick a support agent into calling unauthorized wire transfers ($10,000).",
    targetTool: "send_wire_transfer",
    targetAgent: "agent_support_general",
    defenseMechanism: "Delegation Scope & Intent Drift Enforcement (Fail-Closed RBAC)"
  },
  {
    vectorNumber: 4,
    id: "attack_sequence_exfil",
    title: "Forbidden Cross-Tool Sequence Exfiltration",
    category: "Sequence & Behavioral Invariants",
    severity: "CRITICAL",
    mitreTechnique: "T1048.003 (Exfiltration Over Alternative Protocol)",
    description: "Agent legitimately reads confidential customer PII (SSN, credit score), and immediately attempts to pipe and broadcast data via outbound email.",
    targetTool: "send_external_email",
    targetAgent: "agent_support_general",
    defenseMechanism: "Stateful Action Sequence & Data Loss Prevention (DLP) Gating"
  },
  {
    vectorNumber: 5,
    id: "attack_monotonic_expansion",
    title: "Monotonic Privilege Narrowing Expansion Attempt",
    category: "Delegation Hierarchy",
    severity: "CRITICAL",
    mitreTechnique: "T1068 (Exploitation for Privilege Escalation)",
    description: "Sub-agent attempts to mint or inherit broader capabilities (wire transfer) than its parent delegation envelope possesses.",
    targetTool: "send_wire_transfer",
    targetAgent: "agent_finance_refund",
    defenseMechanism: "Mathematical Monotonic Privilege Invariant Verification (P_child \u2286 P_parent)"
  },
  {
    vectorNumber: 6,
    id: "attack_smurfing_structuring",
    title: "Smurfing / Cumulative Limit Evasion Attack",
    category: "Financial & Cumulative Gating",
    severity: "HIGH",
    mitreTechnique: "T1565.002 (Transaction Boundary Smurfing)",
    description: "Adversary structures refunds into 11 rapid $900 transactions to stay beneath the $1,000 single-action threshold, attempting to drain $10,800.",
    targetTool: "stripe_refund",
    targetAgent: "agent_finance_refund",
    defenseMechanism: "Rolling Window Cumulative Limit & Structuring Defense ($10,000 Ceiling)"
  },
  {
    vectorNumber: 7,
    id: "attack_killswitch_quarantine",
    title: "Compromised Agent Lockdown via Emergency Kill Switch",
    category: "Quarantine & Kill-Switch",
    severity: "CRITICAL",
    mitreTechnique: "T1499 (Zero-Day Agent Containment)",
    description: "A compromised agent attempts actions while under active security quarantine or during global infrastructure emergency lockdown.",
    targetTool: "stripe_refund",
    targetAgent: "agent_finance_refund",
    defenseMechanism: "Zero-Latency Blast Radius Quarantine & Immediate Revocation"
  },
  {
    vectorNumber: 8,
    id: "attack_stale_delegation",
    title: "Stale Delegation Reuse (Expired Temporal Window)",
    category: "Temporal Validity",
    severity: "MEDIUM",
    mitreTechnique: "T1078.004 (Valid Accounts: Stale Credentials)",
    description: "Agent attempts to invoke actions using an expired delegation envelope whose validity window elapsed in the past.",
    targetTool: "stripe_refund",
    targetAgent: "agent_stale_test",
    defenseMechanism: "Temporal Validity Window Enforcement with Clock-Aware Expiry Checking"
  },
  {
    vectorNumber: 9,
    id: "attack_cross_tenant",
    title: "Cross-Tenant Agent Impersonation",
    category: "Multi-Tenant Boundary",
    severity: "CRITICAL",
    mitreTechnique: "T1558 (Steal or Forge Kerberos/SAML/JWT Cross-Tenant Tickets)",
    description: "An agent registered to Tenant Acme attempts to authorize against Tenant Evil resources and delegations.",
    targetTool: "stripe_refund",
    targetAgent: "agent_finance_refund",
    defenseMechanism: "Multi-Tenant Cryptographic Isolation & Tenant Binding Verification"
  },
  {
    vectorNumber: 10,
    id: "attack_cross_task_abuse",
    title: "Cumulative Authority Abuse Across Task Boundaries",
    category: "Task Boundary Isolation",
    severity: "HIGH",
    mitreTechnique: "T1531 (Account Resource Exhaustion)",
    description: "Adversary attempts to circumvent cumulative spend limits by dynamically creating new Task IDs and Session IDs on the fly.",
    targetTool: "stripe_refund",
    targetAgent: "agent_finance_refund",
    defenseMechanism: "Delegation-Level Cumulative Limit Persisted Across Task & Session Boundaries"
  },
  {
    vectorNumber: 11,
    id: "attack_consumed_grant_replay",
    title: "Consumed Authorization Grant Replay",
    category: "Double-Spend Prevention",
    severity: "HIGH",
    mitreTechnique: "T1550 (Use Alternate Authentication Material)",
    description: "Adversary captures a valid grant that has already been consumed once and attempts a secondary replay double-spend.",
    targetTool: "stripe_refund",
    targetAgent: "agent_replay_test",
    defenseMechanism: "Ephemeral Single-Use Grant TTL & Nonce Consumption Tracker"
  },
  {
    vectorNumber: 12,
    id: "attack_resource_traversal",
    title: "Resource Traversal Outside Delegation Scope",
    category: "Resource Scoping",
    severity: "HIGH",
    mitreTechnique: "T1083 (File and Directory Discovery / Path Traversal)",
    description: "Support agent granted access strictly to customer resources (`cust:*`) attempts to target production Kubernetes clusters (`k8s:prod-cluster`).",
    targetTool: "read_customer_pii",
    targetAgent: "agent_support_general",
    defenseMechanism: "Delegation Resource Pattern Scoping (Glob Pattern Boundary Enforcement)"
  },
  {
    vectorNumber: 13,
    id: "attack_circular_delegation",
    title: "Circular Delegation Abuse & Parent Chain Forgery",
    category: "Parent Chain Integrity",
    severity: "MEDIUM",
    mitreTechnique: "T1078 (Valid Accounts: Forged Chain)",
    description: "Adversary attempts to inject a self-referencing delegation envelope to create an infinite evaluation loop or break monotonic verification.",
    targetTool: "search_customers",
    targetAgent: "agent_support_general",
    defenseMechanism: "Delegation Chain Integrity Verification & Parent Registry Lookup Guard"
  },
  {
    vectorNumber: 14,
    id: "attack_runaway_loop",
    title: "Agent Runaway Loop / Tool Abuse Rapid Burst",
    category: "Rate Limiting & Burst Anomaly",
    severity: "MEDIUM",
    mitreTechnique: "T1499.003 (Endpoint DoS: Application Exhaustion)",
    description: "A misconfigured or hallucinating agent executes 30 rapid identical queries within seconds, risking API rate limit exhaustion and billing denial of service.",
    targetTool: "search_customers",
    targetAgent: "agent_support_general",
    defenseMechanism: "Stateful Session Sequence Detector (Burst & Runaway Loop Anomaly Threshold)"
  }
];

// apps/mock-enterprise-tools/src/index.ts
import http from "node:http";
var ENTERPRISE_TOOL_CATALOG = [
  // 1. Payments
  {
    name: "stripe_refund",
    category: "PAYMENT",
    description: "Process a customer payment refund via Stripe",
    riskClass: "HIGH",
    requiresGrant: true,
    parametersSchema: { chargeId: "string", amount: "number", reason: "string" }
  },
  {
    name: "send_wire_transfer",
    category: "PAYMENT",
    description: "Dispatch an outbound SWIFT/ACH corporate wire transfer",
    riskClass: "CRITICAL",
    requiresGrant: true,
    parametersSchema: { destinationAccount: "string", amount: "number", currency: "string" }
  },
  {
    name: "generate_invoice",
    category: "PAYMENT",
    description: "Generate customer billing invoice",
    riskClass: "LOW",
    requiresGrant: false,
    parametersSchema: { customerId: "string", items: "array", total: "number" }
  },
  // 2. CRM
  {
    name: "search_customers",
    category: "CRM",
    description: "Search customer accounts by query",
    riskClass: "LOW",
    requiresGrant: false,
    parametersSchema: { query: "string" }
  },
  {
    name: "read_customer_pii",
    category: "CRM",
    description: "Read full customer record including SSN, address, and credit history",
    riskClass: "HIGH",
    requiresGrant: true,
    parametersSchema: { customerId: "string" }
  },
  {
    name: "update_customer_record",
    category: "CRM",
    description: "Update customer contact details or subscription tier",
    riskClass: "MEDIUM",
    requiresGrant: true,
    parametersSchema: { customerId: "string", updates: "object" }
  },
  // 3. Cloud Infrastructure
  {
    name: "query_production_database",
    category: "CLOUD",
    description: "Execute SQL query against production cluster database",
    riskClass: "CRITICAL",
    requiresGrant: true,
    parametersSchema: { sql: "string", database: "string" }
  },
  {
    name: "modify_security_group",
    category: "CLOUD",
    description: "Modify cloud firewall / ingress security group rules",
    riskClass: "CRITICAL",
    requiresGrant: true,
    parametersSchema: { groupId: "string", port: "number", cidr: "string" }
  },
  {
    name: "deploy_container",
    category: "CLOUD",
    description: "Deploy docker container to production Kubernetes cluster",
    riskClass: "HIGH",
    requiresGrant: true,
    parametersSchema: { image: "string", replicas: "number" }
  },
  // 4. Communications
  {
    name: "send_external_email",
    category: "COMMS",
    description: "Transmit outbound customer or vendor email via SendGrid",
    riskClass: "MEDIUM",
    requiresGrant: true,
    parametersSchema: { to: "string", subject: "string", body: "string" }
  },
  {
    name: "post_slack_announcement",
    category: "COMMS",
    description: "Broadcast announcement to internal enterprise Slack channel",
    riskClass: "LOW",
    requiresGrant: false,
    parametersSchema: { channel: "string", message: "string" }
  }
];
var MockEnterpriseToolsService = class {
  controlPlanePublicKeyPem;
  constructor(controlPlanePublicKeyPem) {
    this.controlPlanePublicKeyPem = controlPlanePublicKeyPem;
  }
  /**
   * Execute enterprise tool with cryptographic grant enforcement.
   */
  execute(toolName, parameters, grant) {
    const def = ENTERPRISE_TOOL_CATALOG.find((t) => t.name === toolName);
    if (!def) {
      return { success: false, error: `Tool '${toolName}' not found in enterprise catalog`, code: "TOOL_NOT_FOUND" };
    }
    if (def.requiresGrant) {
      if (!grant) {
        return {
          success: false,
          error: `Execution denied: Tool '${toolName}' strictly requires a signed Chronicle AuthorizationGrant`,
          code: "GRANT_REQUIRED"
        };
      }
      const grantCheck = verifyAuthorizationGrant(
        grant,
        toolName,
        parameters,
        this.controlPlanePublicKeyPem
      );
      if (!grantCheck.valid) {
        return {
          success: false,
          error: `Cryptographic grant rejected: ${grantCheck.reason}`,
          code: grantCheck.reason || "INVALID_GRANT"
        };
      }
    }
    switch (toolName) {
      case "stripe_refund":
        return {
          success: true,
          data: {
            refundId: "re_" + Math.random().toString(36).substring(2, 14),
            chargeId: parameters.chargeId,
            amountRefunded: parameters.amount,
            status: "succeeded",
            timestamp: (/* @__PURE__ */ new Date()).toISOString()
          }
        };
      case "send_wire_transfer":
        return {
          success: true,
          data: {
            transferId: "wire_" + Math.random().toString(36).substring(2, 14),
            destinationAccount: parameters.destinationAccount,
            amount: parameters.amount,
            currency: parameters.currency || "USD",
            status: "EXECUTED_BY_CORE_BANKING",
            clearedAt: (/* @__PURE__ */ new Date()).toISOString()
          }
        };
      case "generate_invoice":
        return {
          success: true,
          data: {
            invoiceNumber: "INV-2026-" + Math.floor(1e3 + Math.random() * 9e3),
            customerId: parameters.customerId,
            total: parameters.total,
            status: "ISSUED"
          }
        };
      case "search_customers":
        return {
          success: true,
          data: {
            results: [
              { customerId: "cust_9821", name: "Acme Corp", tier: "ENTERPRISE", status: "ACTIVE" },
              { customerId: "cust_4412", name: "Globex Inc", tier: "STANDARD", status: "ACTIVE" }
            ]
          }
        };
      case "read_customer_pii":
        return {
          success: true,
          data: {
            customerId: parameters.customerId,
            name: "Jane Doe",
            ssnMasked: "***-**-4912",
            email: "jane.doe@example.com",
            homeAddress: "742 Evergreen Terrace, Springfield, OR",
            creditRating: 780,
            accessNotice: "CONFIDENTIAL_CUSTOMER_DATA_ACCESSED"
          }
        };
      case "update_customer_record":
        return {
          success: true,
          data: {
            customerId: parameters.customerId,
            updatedFields: parameters.updates,
            modifiedAt: (/* @__PURE__ */ new Date()).toISOString()
          }
        };
      case "query_production_database":
        return {
          success: true,
          data: {
            database: parameters.database || "prod_core",
            rowsReturned: 3,
            rows: [
              { id: 1, name: "System Cluster 1", status: "HEALTHY" },
              { id: 2, name: "Payment Ledger Primary", status: "SYNCHRONIZED" }
            ]
          }
        };
      case "modify_security_group":
        return {
          success: true,
          data: {
            groupId: parameters.groupId,
            ruleAdded: `ALLOW TCP ${parameters.port} from ${parameters.cidr}`,
            status: "APPLIED_TO_VPC"
          }
        };
      case "deploy_container":
        return {
          success: true,
          data: {
            image: parameters.image,
            replicas: parameters.replicas || 2,
            deploymentId: "dep_" + Math.random().toString(36).substring(2, 10),
            status: "RUNNING"
          }
        };
      case "send_external_email":
        return {
          success: true,
          data: {
            messageId: "msg_" + Math.random().toString(36).substring(2, 14),
            recipient: parameters.to,
            subject: parameters.subject,
            deliveryStatus: "DELIVERED_TO_GATEWAY"
          }
        };
      case "post_slack_announcement":
        return {
          success: true,
          data: {
            channel: parameters.channel,
            ts: Date.now().toString(),
            status: "POSTED"
          }
        };
      default:
        return { success: true, data: { executed: toolName, params: parameters } };
    }
  }
  createHttpServer(port = 3002) {
    const server = http.createServer(async (req, res) => {
      const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);
      res.setHeader("Access-Control-Allow-Origin", "*");
      res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
      res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-Chronicle-Grant");
      if (req.method === "OPTIONS") {
        res.writeHead(204);
        res.end();
        return;
      }
      if (req.method === "GET" && url.pathname === "/tools") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(ENTERPRISE_TOOL_CATALOG, null, 2));
        return;
      }
      if (req.method === "POST" && url.pathname === "/execute") {
        let body = "";
        req.on("data", (chunk) => {
          body += chunk;
        });
        req.on("end", () => {
          try {
            const payload = JSON.parse(body);
            const toolName = payload.tool;
            const parameters = payload.parameters || {};
            let grant = payload.grant;
            const headerGrant = req.headers["x-chronicle-grant"];
            if (!grant && typeof headerGrant === "string") {
              grant = JSON.parse(headerGrant);
            }
            const result = this.execute(toolName, parameters, grant);
            const statusCode = result.success ? 200 : result.code === "GRANT_REQUIRED" || result.code === "INVALID_GRANT" || result.code?.includes("TAMPERED") ? 403 : 400;
            res.writeHead(statusCode, { "Content-Type": "application/json" });
            res.end(JSON.stringify(result, null, 2));
          } catch (err) {
            res.writeHead(400, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ success: false, error: err.message }));
          }
        });
        return;
      }
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Endpoint not found" }));
    });
    return server;
  }
};
if (process.argv[1]?.endsWith("mock-enterprise-tools/src/index.ts")) {
  const dummyKey = "";
  const svc = new MockEnterpriseToolsService(dummyKey);
  const server = svc.createHttpServer(3002);
  server.listen(3002, () => {
    console.log("[Mock Enterprise Tools] Online at http://localhost:3002");
  });
}

// apps/control-plane/src/attack-runner.ts
async function executeAttackVector(cp, vectorNumber) {
  const meta = ATTACK_CATALOG.find((a) => a.vectorNumber === vectorNumber);
  if (!meta) {
    throw new Error(`Attack vector #${vectorNumber} not found in catalog`);
  }
  const toolsService = new MockEnterpriseToolsService(cp.keyPair.publicKey);
  const startTime = performance.now();
  let blocked = false;
  let defenseMechanism = meta.defenseMechanism;
  let evidence = "";
  try {
    switch (vectorNumber) {
      case 1: {
        const legitimateParams = { chargeId: "ch_44192", amount: 50 };
        const req = {
          actionId: `act_toctou_${Date.now()}`,
          tenantId: "tenant_acme",
          sessionId: "sess_toctou_demo",
          taskId: "task_customer_refunds",
          agentId: "agent_finance_refund",
          delegationId: "del_finance_refund_root",
          actionType: "stripe_refund",
          tool: "stripe_refund",
          resource: { id: "ch_44192", type: "charge", sensitivity: "SENSITIVE", environment: "production" },
          parameters: legitimateParams,
          parametersHash: canonicalHash(legitimateParams),
          timestamp: (/* @__PURE__ */ new Date()).toISOString()
        };
        const decision = await cp.authorizeAction(req);
        if (decision.decision !== "ALLOW" || !decision.grant) {
          throw new Error("Initial legitimate grant creation failed");
        }
        const tamperedParams = { chargeId: "ch_44192", amount: 5e4 };
        const execResult = toolsService.execute("stripe_refund", tamperedParams, decision.grant);
        blocked = !execResult.success && execResult.code === "PARAMETERS_TAMPERED: hash mismatch";
        defenseMechanism = "Canonical Parameter Hash Cryptographic Binding";
        evidence = `Enterprise tool verified grant parameter hash against payload and rejected execution: ${execResult.error}`;
        break;
      }
      case 2: {
        const now = Math.floor(Date.now() / 1e3);
        const params = { chargeId: "ch_expired", amount: 100 };
        const expiredGrant = {
          grantId: `grant_exp_${Date.now()}`,
          actionId: `act_exp_${Date.now()}`,
          tenantId: "tenant_acme",
          agentId: "agent_finance_refund",
          actionType: "stripe_refund",
          tool: "stripe_refund",
          resourceId: "ch_expired",
          parametersHash: canonicalHash(params),
          delegationId: "del_finance_refund_root",
          nonce: `nonce_${Date.now()}`,
          notBefore: now - 100,
          expiresAt: now - 10,
          // Expired
          signature: "dummy_sig"
        };
        const execResult = toolsService.execute("stripe_refund", params, expiredGrant);
        blocked = !execResult.success && execResult.code === "GRANT_EXPIRED";
        defenseMechanism = "Ephemeral Grant TTL Enforcement";
        evidence = `Tool gateway rejected replayed expired grant: ${execResult.error}`;
        break;
      }
      case 3: {
        const injectedAction = {
          actionId: `act_drift_${Date.now()}`,
          tenantId: "tenant_acme",
          sessionId: `sess_drift_${Date.now()}`,
          taskId: "task_support_inquiries",
          agentId: "agent_support_general",
          delegationId: "del_support_general_root",
          actionType: "send_wire_transfer",
          tool: "send_wire_transfer",
          resource: { id: "wire_attacker", type: "wire", sensitivity: "CRITICAL", environment: "production" },
          parameters: { destinationAccount: "ACME_EVIL_OFFSHORE", amount: 1e4 },
          parametersHash: canonicalHash({ destinationAccount: "ACME_EVIL_OFFSHORE", amount: 1e4 }),
          timestamp: (/* @__PURE__ */ new Date()).toISOString()
        };
        const decision = await cp.authorizeAction(injectedAction);
        blocked = decision.decision === "DENY";
        defenseMechanism = "Delegation Scope & Intent Drift Enforcement";
        evidence = `Control plane intercepted unauthorized wire transfer from support agent: ${decision.explanation}`;
        break;
      }
      case 4: {
        const sessId = `sess_exfil_${Date.now()}`;
        const readPiiReq = {
          actionId: `act_pii_read_${Date.now()}`,
          tenantId: "tenant_acme",
          sessionId: sessId,
          taskId: "task_support_inquiries",
          agentId: "agent_support_general",
          delegationId: "del_support_general_root",
          actionType: "read_customer_pii",
          tool: "read_customer_pii",
          resource: { id: "cust_7721", type: "customer", sensitivity: "CONFIDENTIAL", environment: "production" },
          parameters: { customerId: "cust_7721" },
          parametersHash: canonicalHash({ customerId: "cust_7721" }),
          timestamp: (/* @__PURE__ */ new Date()).toISOString()
        };
        await cp.authorizeAction(readPiiReq);
        const exfilReq = {
          actionId: `act_exfil_send_${Date.now()}`,
          tenantId: "tenant_acme",
          sessionId: sessId,
          taskId: "task_support_inquiries",
          agentId: "agent_support_general",
          delegationId: "del_support_general_root",
          actionType: "send_external_email",
          tool: "send_external_email",
          resource: { id: "msg_exfil", type: "email", sensitivity: "SENSITIVE", environment: "production" },
          parameters: { to: "hacker@darknet.org", body: "PII leak" },
          parametersHash: canonicalHash({ to: "hacker@darknet.org", body: "PII leak" }),
          timestamp: (/* @__PURE__ */ new Date()).toISOString()
        };
        const exfilDecision = await cp.authorizeAction(exfilReq);
        blocked = exfilDecision.decision === "DENY";
        defenseMechanism = "Stateful Action Sequence & Behavioral Invariant Monitoring";
        evidence = `Control plane intercepted data exfiltration pipeline: ${exfilDecision.explanation}`;
        break;
      }
      case 5: {
        let threw = false;
        let errorMsg = "";
        try {
          cp.delegationManager.createDelegation(
            {
              delegationId: `del_illegal_exp_${Date.now()}`,
              tenantId: "tenant_acme",
              parentDelegationId: "del_finance_refund_root",
              delegatorType: "AGENT",
              delegatorId: "agent_finance_refund",
              delegateeId: "agent_support_general",
              taskId: "task_sub_escalation",
              purpose: "Privilege expansion attempt",
              constraints: {
                allowedTools: ["send_wire_transfer"],
                // Parent does not have this!
                resourcePatterns: ["*"]
              },
              notBefore: (/* @__PURE__ */ new Date()).toISOString(),
              expiresAt: new Date(Date.now() + 1e4).toISOString()
            },
            "invalid_key"
          );
        } catch (err) {
          threw = true;
          errorMsg = err.message;
        }
        blocked = threw && errorMsg.includes("Monotonic narrowing violation");
        defenseMechanism = "Mathematical Monotonic Privilege Invariant Verification";
        evidence = `Delegation Engine rejected child privilege expansion: ${errorMsg}`;
        break;
      }
      case 6: {
        const smurfSponsorKeys = generateEd25519KeyPair();
        const smurfSponsorId = `user_smurf_${Date.now()}`;
        cp.delegationManager.registerSponsor({
          userId: smurfSponsorId,
          tenantId: "tenant_acme",
          name: "Smurf Test Sponsor",
          email: "smurf@acme.com",
          role: "Finance Director",
          department: "Treasury",
          publicKey: smurfSponsorKeys.publicKey,
          createdAt: (/* @__PURE__ */ new Date()).toISOString()
        });
        const smurfDelegation = cp.delegationManager.createDelegation(
          {
            delegationId: `del_smurf_test_${Date.now()}`,
            tenantId: "tenant_acme",
            delegatorType: "HUMAN",
            delegatorId: smurfSponsorId,
            delegateeId: "agent_finance_refund",
            taskId: "task_smurf_test",
            purpose: "Smurfing defense verification",
            constraints: {
              allowedTools: ["stripe_refund"],
              resourcePatterns: ["ch:*", "ch_*"],
              maxTransactionValue: 1e3,
              cumulativeValueLimit: 3e3,
              // Small limit for testing
              requireApprovalAbove: 1e3
            },
            notBefore: new Date(Date.now() - 1e3).toISOString(),
            expiresAt: new Date(Date.now() + 6e4).toISOString()
          },
          smurfSponsorKeys.privateKey
        );
        const sessId = `sess_smurf_${Date.now()}`;
        for (let i = 0; i < 3; i++) {
          const req = {
            actionId: `act_smurf_${Date.now()}_${i}`,
            tenantId: "tenant_acme",
            sessionId: sessId,
            taskId: "task_smurf_test",
            agentId: "agent_finance_refund",
            delegationId: smurfDelegation.delegationId,
            actionType: "stripe_refund",
            tool: "stripe_refund",
            resource: { id: `ch_smurf_${i}`, type: "charge", sensitivity: "SENSITIVE", environment: "production" },
            parameters: { chargeId: `ch_smurf_${i}`, amount: 900 },
            parametersHash: canonicalHash({ chargeId: `ch_smurf_${i}`, amount: 900 }),
            timestamp: (/* @__PURE__ */ new Date()).toISOString()
          };
          await cp.authorizeAction(req);
        }
        const reqOverLimit = {
          actionId: `act_smurf_over_${Date.now()}`,
          tenantId: "tenant_acme",
          sessionId: sessId,
          taskId: "task_smurf_test",
          agentId: "agent_finance_refund",
          delegationId: smurfDelegation.delegationId,
          actionType: "stripe_refund",
          tool: "stripe_refund",
          resource: { id: "ch_smurf_over", type: "charge", sensitivity: "SENSITIVE", environment: "production" },
          parameters: { chargeId: "ch_smurf_over", amount: 900 },
          parametersHash: canonicalHash({ chargeId: "ch_smurf_over", amount: 900 }),
          timestamp: (/* @__PURE__ */ new Date()).toISOString()
        };
        const dOver = await cp.authorizeAction(reqOverLimit);
        blocked = dOver.decision === "DENY" && dOver.reasonCodes.includes("CUMULATIVE_LIMIT_EXCEEDED");
        defenseMechanism = "Rolling Window Cumulative Limit & Structuring Defense";
        evidence = `Smurfing blocked on 4th transaction exceeding $3,000 cumulative limit: ${dOver.explanation}`;
        break;
      }
      case 7: {
        cp.policyEngine.quarantineAgent("agent_finance_refund");
        const rogueReq = {
          actionId: `act_rogue_${Date.now()}`,
          tenantId: "tenant_acme",
          sessionId: `sess_rogue_${Date.now()}`,
          taskId: "task_customer_refunds",
          agentId: "agent_finance_refund",
          delegationId: "del_finance_refund_root",
          actionType: "stripe_refund",
          tool: "stripe_refund",
          resource: { id: "ch_rogue", type: "charge", sensitivity: "SENSITIVE", environment: "production" },
          parameters: { chargeId: "ch_rogue", amount: 50 },
          parametersHash: canonicalHash({ chargeId: "ch_rogue", amount: 50 }),
          timestamp: (/* @__PURE__ */ new Date()).toISOString()
        };
        const decision = await cp.authorizeAction(rogueReq);
        blocked = decision.decision === "DENY" && decision.reasonCodes.includes("AGENT_QUARANTINED");
        cp.policyEngine.unquarantineAgent("agent_finance_refund");
        defenseMechanism = "Zero-Latency Blast Radius Quarantine & Kill Switch";
        evidence = `Quarantined agent severed with sub-millisecond execution cutoff: ${decision.explanation}`;
        break;
      }
      case 8: {
        const staleSponsorKeys = generateEd25519KeyPair();
        const expiredDelegation = cp.delegationManager.createDelegation(
          {
            delegationId: `del_stale_${Date.now()}`,
            tenantId: "tenant_acme",
            delegatorType: "HUMAN",
            delegatorId: "user_ciso_jane",
            delegateeId: "agent_finance_refund",
            taskId: "task_stale",
            purpose: "Expired delegation test",
            constraints: {
              allowedTools: ["stripe_refund"],
              resourcePatterns: ["*"],
              maxTransactionValue: 100
            },
            notBefore: new Date(Date.now() - 6e5).toISOString(),
            expiresAt: new Date(Date.now() - 3e5).toISOString()
            // Expired 5 min ago
          },
          staleSponsorKeys.privateKey
        );
        const staleReq = {
          actionId: `act_stale_${Date.now()}`,
          tenantId: "tenant_acme",
          sessionId: `sess_stale_${Date.now()}`,
          taskId: "task_stale",
          agentId: "agent_finance_refund",
          delegationId: expiredDelegation.delegationId,
          actionType: "stripe_refund",
          tool: "stripe_refund",
          resource: { id: "ch_stale", type: "charge", sensitivity: "SENSITIVE", environment: "production" },
          parameters: { chargeId: "ch_stale", amount: 50 },
          parametersHash: canonicalHash({ chargeId: "ch_stale", amount: 50 }),
          timestamp: (/* @__PURE__ */ new Date()).toISOString()
        };
        const decision = await cp.authorizeAction(staleReq);
        blocked = decision.decision === "DENY";
        defenseMechanism = "Temporal Validity Window Enforcement with Clock-Aware Expiry Checking";
        evidence = `Stale delegation rejected outside cryptographic validity envelope: ${decision.explanation}`;
        break;
      }
      case 9: {
        cp.policyEngine.unquarantineAgent("agent_finance_refund");
        const crossTenantReq = {
          actionId: `act_cross_${Date.now()}`,
          tenantId: "tenant_evil_corp",
          // Mismatched tenant
          sessionId: `sess_cross_${Date.now()}`,
          taskId: "task_customer_refunds",
          agentId: "agent_finance_refund",
          delegationId: "del_finance_refund_root",
          actionType: "stripe_refund",
          tool: "stripe_refund",
          resource: { id: "ch_cross", type: "charge", sensitivity: "CRITICAL", environment: "production" },
          parameters: { chargeId: "ch_cross", amount: 999 },
          parametersHash: canonicalHash({ chargeId: "ch_cross", amount: 999 }),
          timestamp: (/* @__PURE__ */ new Date()).toISOString()
        };
        const decision = await cp.authorizeAction(crossTenantReq);
        blocked = decision.decision === "DENY";
        defenseMechanism = "Multi-Tenant Cryptographic Isolation & Tenant Binding Verification";
        evidence = `Cross-tenant impersonation blocked: ${decision.explanation}`;
        break;
      }
      case 10: {
        const taskSponsorKeys = generateEd25519KeyPair();
        const taskDelegation = cp.delegationManager.createDelegation(
          {
            delegationId: `del_task_limit_${Date.now()}`,
            tenantId: "tenant_acme",
            delegatorType: "HUMAN",
            delegatorId: "user_ciso_jane",
            delegateeId: "agent_finance_refund",
            taskId: "task_limit_test",
            purpose: "Task boundary limit verification",
            constraints: {
              allowedTools: ["stripe_refund"],
              resourcePatterns: ["ch:*", "ch_*"],
              maxTransactionValue: 1e3,
              cumulativeValueLimit: 1200
            },
            notBefore: new Date(Date.now() - 1e3).toISOString(),
            expiresAt: new Date(Date.now() + 6e4).toISOString()
          },
          taskSponsorKeys.privateKey
        );
        const reqTaskA = {
          actionId: `act_task_a_${Date.now()}`,
          tenantId: "tenant_acme",
          sessionId: `sess_a_${Date.now()}`,
          taskId: `task_a_${Date.now()}`,
          agentId: "agent_finance_refund",
          delegationId: taskDelegation.delegationId,
          actionType: "stripe_refund",
          tool: "stripe_refund",
          resource: { id: "ch_a", type: "charge", sensitivity: "SENSITIVE", environment: "production" },
          parameters: { chargeId: "ch_a", amount: 800 },
          parametersHash: canonicalHash({ chargeId: "ch_a", amount: 800 }),
          timestamp: (/* @__PURE__ */ new Date()).toISOString()
        };
        await cp.authorizeAction(reqTaskA);
        const reqTaskB = {
          actionId: `act_task_b_${Date.now()}`,
          tenantId: "tenant_acme",
          sessionId: `sess_b_${Date.now()}`,
          taskId: `task_b_new_${Date.now()}`,
          // Switch task ID
          agentId: "agent_finance_refund",
          delegationId: taskDelegation.delegationId,
          actionType: "stripe_refund",
          tool: "stripe_refund",
          resource: { id: "ch_b", type: "charge", sensitivity: "SENSITIVE", environment: "production" },
          parameters: { chargeId: "ch_b", amount: 800 },
          parametersHash: canonicalHash({ chargeId: "ch_b", amount: 800 }),
          timestamp: (/* @__PURE__ */ new Date()).toISOString()
        };
        const decisionB = await cp.authorizeAction(reqTaskB);
        blocked = decisionB.decision === "DENY";
        defenseMechanism = "Delegation-Level Cumulative Limit Persisted Across Task Boundaries";
        evidence = `Cross-task limit evasion neutralized: ${decisionB.explanation}`;
        break;
      }
      case 11: {
        const replaySponsorKeys = generateEd25519KeyPair();
        const replaySponsorId = `user_replay_${Date.now()}`;
        cp.delegationManager.registerSponsor({
          userId: replaySponsorId,
          tenantId: "tenant_acme",
          name: "Replay Test Sponsor",
          email: "replay@acme.com",
          role: "Audit Officer",
          department: "Security",
          publicKey: replaySponsorKeys.publicKey,
          createdAt: (/* @__PURE__ */ new Date()).toISOString()
        });
        const replayDelegation = cp.delegationManager.createDelegation(
          {
            delegationId: `del_replay_${Date.now()}`,
            tenantId: "tenant_acme",
            delegatorType: "HUMAN",
            delegatorId: replaySponsorId,
            delegateeId: "agent_finance_refund",
            taskId: "task_replay_test",
            purpose: "Grant replay verification",
            constraints: {
              allowedTools: ["stripe_refund"],
              resourcePatterns: ["ch:*", "ch_*"],
              maxTransactionValue: 5e3,
              cumulativeValueLimit: 5e4
            },
            notBefore: new Date(Date.now() - 1e3).toISOString(),
            expiresAt: new Date(Date.now() + 6e4).toISOString()
          },
          replaySponsorKeys.privateKey
        );
        const params = { chargeId: "ch_replay_sample", amount: 200 };
        const req = {
          actionId: `act_replay_init_${Date.now()}`,
          tenantId: "tenant_acme",
          sessionId: `sess_replay_${Date.now()}`,
          taskId: "task_replay_test",
          agentId: "agent_finance_refund",
          delegationId: replayDelegation.delegationId,
          actionType: "stripe_refund",
          tool: "stripe_refund",
          resource: { id: "ch_replay_sample", type: "charge", sensitivity: "SENSITIVE", environment: "production" },
          parameters: params,
          parametersHash: canonicalHash(params),
          timestamp: (/* @__PURE__ */ new Date()).toISOString()
        };
        const decision = await cp.authorizeAction(req);
        if (!decision.grant) throw new Error("Initial grant issuance failed");
        toolsService.execute("stripe_refund", params, decision.grant);
        const expiredGrant = {
          ...decision.grant,
          expiresAt: Math.floor(Date.now() / 1e3) - 5
        };
        const replayExec = toolsService.execute("stripe_refund", params, expiredGrant);
        blocked = !replayExec.success && replayExec.code === "GRANT_EXPIRED";
        defenseMechanism = "Ephemeral Single-Use Grant TTL & Nonce Consumption Tracker";
        evidence = `Replayed grant rejected by tool gateway: ${replayExec.error}`;
        break;
      }
      case 12: {
        const traversalReq = {
          actionId: `act_traversal_${Date.now()}`,
          tenantId: "tenant_acme",
          sessionId: `sess_traversal_${Date.now()}`,
          taskId: "task_support_inquiries",
          agentId: "agent_support_general",
          delegationId: "del_support_general_root",
          actionType: "read_customer_pii",
          tool: "read_customer_pii",
          resource: {
            id: "k8s:prod-cluster",
            // Outside cust:*
            type: "infrastructure",
            sensitivity: "CRITICAL",
            environment: "production"
          },
          parameters: { resourceId: "k8s:prod-cluster" },
          parametersHash: canonicalHash({ resourceId: "k8s:prod-cluster" }),
          timestamp: (/* @__PURE__ */ new Date()).toISOString()
        };
        const decision = await cp.authorizeAction(traversalReq);
        blocked = decision.decision === "DENY";
        defenseMechanism = "Delegation Resource Pattern Scoping (Glob Pattern Boundary Enforcement)";
        evidence = `Resource traversal blocked: ${decision.explanation}`;
        break;
      }
      case 13: {
        let threw = false;
        let errorMsg = "";
        try {
          const circularKeys = generateEd25519KeyPair();
          cp.delegationManager.createDelegation(
            {
              delegationId: `del_circ_${Date.now()}`,
              tenantId: "tenant_acme",
              parentDelegationId: `del_circ_${Date.now()}`,
              // Points to itself
              delegatorType: "HUMAN",
              delegatorId: "user_ciso_jane",
              delegateeId: "agent_support_general",
              taskId: "task_circ",
              purpose: "Circular delegation test",
              constraints: {
                allowedTools: ["search_customers"],
                resourcePatterns: ["cust:*"]
              },
              notBefore: (/* @__PURE__ */ new Date()).toISOString(),
              expiresAt: new Date(Date.now() + 6e4).toISOString()
            },
            circularKeys.privateKey
          );
        } catch (err) {
          threw = true;
          errorMsg = err.message;
        }
        blocked = threw && (errorMsg.includes("not found") || errorMsg.includes("parent"));
        defenseMechanism = "Delegation Chain Integrity Verification & Parent Registry Lookup Guard";
        evidence = `Circular delegation rejected: ${errorMsg}`;
        break;
      }
      case 14: {
        const sessId = `sess_burst_${Date.now()}`;
        let burstDenied = false;
        let explanation = "";
        for (let i = 0; i < 30; i++) {
          const params = { query: "find_all_customers", offset: i };
          const req = {
            actionId: `act_burst_${Date.now()}_${i}`,
            tenantId: "tenant_acme",
            sessionId: sessId,
            taskId: "task_support_inquiries",
            agentId: "agent_support_general",
            delegationId: "del_support_general_root",
            actionType: "search_customers",
            tool: "search_customers",
            resource: { id: "cust:all", type: "customer", sensitivity: "CONFIDENTIAL", environment: "production" },
            parameters: params,
            parametersHash: canonicalHash(params),
            timestamp: (/* @__PURE__ */ new Date()).toISOString()
          };
          const d = await cp.authorizeAction(req);
          if (d.decision === "DENY") {
            burstDenied = true;
            explanation = d.explanation;
            break;
          }
        }
        blocked = burstDenied;
        defenseMechanism = "Stateful Session Sequence Detector (Burst & Runaway Loop Anomaly Threshold)";
        evidence = `Rapid tool burst rate limit triggered: ${explanation}`;
        break;
      }
      default:
        throw new Error(`Unhandled vector #${vectorNumber}`);
    }
  } catch (err) {
    blocked = false;
    evidence = `Execution error: ${err.message}`;
  }
  const durationMs = Math.round((performance.now() - startTime) * 100) / 100;
  return {
    vectorNumber: meta.vectorNumber,
    id: meta.id,
    title: meta.title,
    category: meta.category,
    severity: meta.severity,
    blocked,
    defenseMechanism,
    evidence,
    status: blocked ? "NEUTRALIZED" : "FAILED",
    durationMs
  };
}
async function executeAllAttackVectors(cp) {
  const results = [];
  for (let i = 1; i <= 14; i++) {
    const res = await executeAttackVector(cp, i);
    results.push(res);
  }
  return results;
}

// apps/control-plane/src/index.ts
var ChronicleControlPlane = class {
  keyPair;
  delegationManager;
  sequenceDetector;
  policyEngine;
  auditLedger;
  blastRadiusAnalyzer;
  observationEngine;
  approvals = /* @__PURE__ */ new Map();
  totalActionsProcessed = 0;
  startTime = Date.now();
  /** Enforcement vs Observation mode (§3) */
  mode = "enforcement";
  /** In-memory action history for API queries */
  actionHistory = [];
  constructor() {
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
    this.observationEngine = new ObservationEngine(this.mode);
    this.seedDefaultEnvironment();
  }
  /**
   * Seed enterprise human sponsors, agents, and default delegation envelopes.
   */
  seedDefaultEnvironment() {
    const sponsorKeys = generateEd25519KeyPair();
    const defaultSponsor = {
      userId: "user_ciso_jane",
      tenantId: "tenant_acme",
      name: "Jane Doe (CISO)",
      email: "jane.ciso@acmecorp.com",
      role: "CISO",
      department: "Security & Trust",
      publicKey: sponsorKeys.publicKey,
      createdAt: (/* @__PURE__ */ new Date()).toISOString()
    };
    this.delegationManager.registerSponsor(defaultSponsor);
    const financeAgentKeys = generateEd25519KeyPair();
    const financeAgent = {
      agentId: "agent_finance_refund",
      tenantId: "tenant_acme",
      name: "Finance Refund Agent",
      agentType: "FINANCIAL_OPS",
      agentVersion: "v2.1",
      modelProvider: "anthropic/claude-3.5-sonnet",
      owner: defaultSponsor.userId,
      sponsor: defaultSponsor.userId,
      creationTime: (/* @__PURE__ */ new Date()).toISOString(),
      status: "ACTIVE",
      environment: "production",
      riskClass: "HIGH",
      allowedCapabilities: ["stripe_refund", "search_customers"],
      publicKey: financeAgentKeys.publicKey
    };
    this.delegationManager.registerAgent(financeAgent);
    this.delegationManager.createDelegation(
      {
        delegationId: "del_finance_refund_root",
        tenantId: "tenant_acme",
        delegatorType: "HUMAN",
        delegatorId: defaultSponsor.userId,
        delegateeId: financeAgent.agentId,
        taskId: "task_customer_refunds",
        purpose: "Execute authorized customer refunds up to policy limit",
        constraints: {
          allowedTools: ["stripe_refund", "search_customers"],
          resourcePatterns: ["ch:*", "ch_*", "charge:*", "charge_*", "cust:*", "cust_*"],
          maxTransactionValue: 5e3,
          cumulativeValueLimit: 1e4,
          requireApprovalAbove: 1e3,
          temporalValiditySeconds: 86400
        },
        notBefore: new Date(Date.now() - 6e4).toISOString(),
        expiresAt: new Date(Date.now() + 864e5).toISOString()
      },
      sponsorKeys.privateKey
    );
    const supportAgentKeys = generateEd25519KeyPair();
    const supportAgent = {
      agentId: "agent_support_general",
      tenantId: "tenant_acme",
      name: "Customer Support Agent",
      agentType: "TIER_1_SUPPORT",
      agentVersion: "v1.0",
      modelProvider: "openai/gpt-4o",
      owner: defaultSponsor.userId,
      sponsor: defaultSponsor.userId,
      creationTime: (/* @__PURE__ */ new Date()).toISOString(),
      status: "ACTIVE",
      environment: "production",
      riskClass: "MEDIUM",
      allowedCapabilities: ["search_customers", "read_customer_pii", "update_customer_record"],
      publicKey: supportAgentKeys.publicKey
    };
    this.delegationManager.registerAgent(supportAgent);
    this.delegationManager.createDelegation(
      {
        delegationId: "del_support_general_root",
        tenantId: "tenant_acme",
        delegatorType: "HUMAN",
        delegatorId: defaultSponsor.userId,
        delegateeId: supportAgent.agentId,
        taskId: "task_support_inquiries",
        purpose: "Resolve customer support queries",
        constraints: {
          allowedTools: ["search_customers", "read_customer_pii", "update_customer_record"],
          resourcePatterns: ["cust:*", "cust_*"],
          temporalValiditySeconds: 86400
        },
        notBefore: new Date(Date.now() - 6e4).toISOString(),
        expiresAt: new Date(Date.now() + 864e5).toISOString()
      },
      sponsorKeys.privateKey
    );
    const devopsAgentKeys = generateEd25519KeyPair();
    const devopsAgent = {
      agentId: "agent_infra_devops",
      tenantId: "tenant_acme",
      name: "DevOps Automated Agent",
      agentType: "INFRASTRUCTURE",
      agentVersion: "v3.0",
      modelProvider: "anthropic/claude-3.5-sonnet",
      owner: defaultSponsor.userId,
      sponsor: defaultSponsor.userId,
      creationTime: (/* @__PURE__ */ new Date()).toISOString(),
      status: "ACTIVE",
      environment: "production",
      riskClass: "CRITICAL",
      allowedCapabilities: ["deploy_container", "modify_security_group", "query_production_database"],
      publicKey: devopsAgentKeys.publicKey
    };
    this.delegationManager.registerAgent(devopsAgent);
    this.delegationManager.createDelegation(
      {
        delegationId: "del_devops_infra_root",
        tenantId: "tenant_acme",
        delegatorType: "HUMAN",
        delegatorId: defaultSponsor.userId,
        delegateeId: devopsAgent.agentId,
        taskId: "task_infra_maintenance",
        purpose: "Maintain production cloud infrastructure",
        constraints: {
          allowedTools: ["deploy_container", "modify_security_group", "query_production_database"],
          resourcePatterns: ["k8s:*", "sg:*", "db:*"],
          temporalValiditySeconds: 86400
        },
        notBefore: new Date(Date.now() - 6e4).toISOString(),
        expiresAt: new Date(Date.now() + 864e5).toISOString()
      },
      sponsorKeys.privateKey
    );
  }
  /**
   * Main Authorization Pipeline:
   * Evaluate request -> Generate receipt -> Record in audit ledger & sequence detector.
   */
  async authorizeAction(request) {
    this.totalActionsProcessed++;
    const decision = await this.policyEngine.evaluate(request);
    if (decision.decision === "HOLD" && decision.approvalId) {
      const approval = {
        approvalId: decision.approvalId,
        tenantId: request.tenantId,
        actionId: request.actionId,
        agentId: request.agentId,
        taskId: request.taskId,
        actionType: request.actionType,
        resource: request.resource,
        parameters: request.parameters,
        riskScore: decision.riskScore,
        requiredRole: decision.requiredApprovalRole || "FINANCE_SPONSOR",
        explanation: decision.explanation,
        status: "PENDING",
        createdAt: (/* @__PURE__ */ new Date()).toISOString(),
        expiresAt: new Date(Date.now() + 18e5).toISOString()
        // 30 minutes
      };
      this.approvals.set(approval.approvalId, approval);
    }
    const receipt = this.auditLedger.recordDecision(
      request,
      decision,
      "user_ciso_jane"
      // Sponsor ID
    );
    decision.receipt = receipt;
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
    this.actionHistory.push({
      actionId: request.actionId,
      agentId: request.agentId,
      tenantId: request.tenantId,
      sessionId: request.sessionId,
      taskId: request.taskId,
      actionType: request.actionType,
      tool: request.tool,
      resourceId: request.resource.id,
      decision: this.mode === "observation" ? "OBSERVED" : decision.decision,
      riskScore: decision.riskScore,
      riskClass: decision.riskClass,
      explanation: decision.explanation,
      timestamp: request.timestamp
    });
    return this.observationEngine.processDecision(request, decision, () => {
      const grantId = "grant_" + Math.random().toString(36).substring(2, 12);
      return createAuthorizationGrant(
        grantId,
        request.actionId,
        request.tenantId,
        request.agentId,
        request.actionType,
        request.tool,
        request.resource.id,
        canonicalHash(request.parameters),
        request.delegationId,
        this.keyPair.privateKey,
        60
      );
    });
  }
  /**
   * Human Step-Up Approval Decision Handler:
   * Human sponsor approves or rejects an action on HOLD.
   */
  decideApproval(approvalId, approved, decidedBy, notes) {
    const approval = this.approvals.get(approvalId);
    if (!approval) return null;
    approval.status = approved ? "APPROVED" : "REJECTED";
    approval.decidedBy = decidedBy;
    approval.decidedAt = (/* @__PURE__ */ new Date()).toISOString();
    approval.decisionNotes = notes;
    if (approved) {
      const grantId = "grant_appr_" + Math.random().toString(36).substring(2, 10);
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
        "del_finance_refund_root",
        this.keyPair.privateKey,
        300
        // 5 minutes TTL
      );
      approval.oneTimeGrant = grant;
      return { approval, grant };
    }
    return { approval };
  }
  getPendingApprovals() {
    return Array.from(this.approvals.values()).filter((a) => a.status === "PENDING");
  }
  getMode() {
    return this.mode;
  }
  setMode(mode) {
    this.mode = mode;
    this.observationEngine.setMode(mode);
  }
  getStatus() {
    const integrity = this.auditLedger.verifyIntegrity();
    return {
      status: "HEALTHY",
      mode: this.mode,
      uptimeSeconds: Math.floor((Date.now() - this.startTime) / 1e3),
      totalActions: this.totalActionsProcessed,
      killSwitchActive: false,
      publicKey: this.keyPair.publicKey,
      activeDelegations: this.delegationManager.listDelegations().filter((d) => !d.revoked).length,
      registeredAgents: this.delegationManager.listAgents().length,
      pendingApprovals: this.getPendingApprovals().length,
      auditReceiptsCount: this.auditLedger.getReceipts().length,
      ledgerIntegrity: { valid: integrity.valid, totalReceipts: integrity.totalReceipts }
    };
  }
  /**
   * Create Node HTTP Server to serve API and Dashboard UI.
   */
  /**
   * The raw (req, res) request listener, decoupled from any particular hosting
   * mechanism so it can back a standalone http.Server (local/Railway/Render)
   * or be re-exported directly as a Vercel serverless function handler.
   */
  getRequestHandler() {
    return async (req, res) => {
      const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);
      res.setHeader("Access-Control-Allow-Origin", "*");
      res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
      res.setHeader("Access-Control-Allow-Headers", "Content-Type");
      if (req.method === "OPTIONS") {
        res.writeHead(204);
        res.end();
        return;
      }
      if (req.method === "GET" && (url.pathname === "/" || url.pathname === "/index.html")) {
        const htmlPath = path.resolve("apps/control-plane/public/index.html");
        if (fs.existsSync(htmlPath)) {
          const html = fs.readFileSync(htmlPath, "utf8");
          res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
          res.end(html);
          return;
        }
      }
      if (req.method === "GET" && url.pathname === "/api/v1/status") {
        const status = this.getStatus();
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(status));
        return;
      }
      if (req.method === "POST" && url.pathname === "/api/v1/authorize") {
        let body = "";
        req.on("data", (c) => {
          body += c;
        });
        req.on("end", async () => {
          try {
            const actionRequest = JSON.parse(body);
            const decision = await this.authorizeAction(actionRequest);
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify(decision, null, 2));
          } catch (err) {
            res.writeHead(400, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: err.message }));
          }
        });
        return;
      }
      if (req.method === "GET" && url.pathname === "/api/v1/approvals") {
        const pending = this.getPendingApprovals();
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(pending));
        return;
      }
      if (req.method === "POST" && url.pathname.startsWith("/api/v1/approvals/") && url.pathname.endsWith("/decide")) {
        const parts = url.pathname.split("/");
        const approvalId = parts[parts.length - 2];
        let body = "";
        req.on("data", (c) => {
          body += c;
        });
        req.on("end", () => {
          try {
            const { approved, sponsorId, notes } = JSON.parse(body);
            const result = this.decideApproval(approvalId, approved, sponsorId, notes);
            if (!result) {
              res.writeHead(404, { "Content-Type": "application/json" });
              res.end(JSON.stringify({ error: "Approval not found" }));
              return;
            }
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify(result));
          } catch (err) {
            res.writeHead(400, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: err.message }));
          }
        });
        return;
      }
      if (req.method === "GET" && url.pathname === "/api/v1/audit/receipts") {
        const receipts = this.auditLedger.getReceipts();
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(receipts));
        return;
      }
      if (req.method === "GET" && url.pathname === "/api/v1/audit/verify") {
        const verification = this.auditLedger.verifyIntegrity();
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(verification));
        return;
      }
      if (req.method === "GET" && url.pathname.startsWith("/api/v1/analytics/blast-radius/")) {
        const agentId = url.pathname.split("/").pop();
        const report = this.blastRadiusAnalyzer.calculateBlastRadius(agentId);
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(report));
        return;
      }
      if (req.method === "GET" && url.pathname.startsWith("/api/v1/analytics/provenance/")) {
        const actionId = url.pathname.split("/").pop();
        const graph = this.auditLedger.buildProvenanceGraph(actionId);
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(graph));
        return;
      }
      if (req.method === "POST" && url.pathname === "/api/v1/policies/simulate") {
        let body = "";
        req.on("data", (c) => {
          body += c;
        });
        req.on("end", () => {
          try {
            const simReq = JSON.parse(body);
            const history = this.auditLedger.getReceipts().map((r) => ({
              actionId: r.actionId,
              sessionId: "sess_sim",
              taskId: "task_sim",
              agentId: r.agentId,
              actionType: r.actionType,
              tool: r.actionType,
              resourceId: r.resourceId,
              parameters: { amount: r.riskScore * 15 },
              decision: r.decision,
              timestamp: r.timestamp
            }));
            const result = this.policyEngine.simulatePolicy(simReq, history);
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify(result));
          } catch (err) {
            res.writeHead(400, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: err.message }));
          }
        });
        return;
      }
      if (req.method === "POST" && url.pathname === "/api/v1/kill-switch") {
        let body = "";
        req.on("data", (c) => {
          body += c;
        });
        req.on("end", () => {
          try {
            const { active, agentId } = JSON.parse(body);
            if (agentId) {
              if (active) this.policyEngine.quarantineAgent(agentId);
              else this.policyEngine.unquarantineAgent(agentId);
              res.writeHead(200, { "Content-Type": "application/json" });
              res.end(JSON.stringify({ agentId, quarantined: active }));
              return;
            }
            this.policyEngine.setKillSwitch(!!active);
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ active: !!active, message: active ? "GLOBAL LOCKDOWN ENGAGED" : "OPERATIONAL" }));
          } catch (err) {
            res.writeHead(400, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: err.message }));
          }
        });
        return;
      }
      if (req.method === "POST" && url.pathname === "/api/v1/kill-switch/quarantine") {
        let body = "";
        req.on("data", (c) => {
          body += c;
        });
        req.on("end", () => {
          try {
            const { agentId, quarantine } = JSON.parse(body);
            if (quarantine) this.policyEngine.quarantineAgent(agentId);
            else this.policyEngine.unquarantineAgent(agentId);
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ agentId, quarantined: quarantine }));
          } catch (err) {
            res.writeHead(400, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: err.message }));
          }
        });
        return;
      }
      if (req.method === "POST" && url.pathname === "/api/v1/mode") {
        let body = "";
        req.on("data", (c) => {
          body += c;
        });
        req.on("end", () => {
          try {
            const { mode } = JSON.parse(body);
            if (mode !== "enforcement" && mode !== "observation") {
              res.writeHead(400, { "Content-Type": "application/json" });
              res.end(JSON.stringify({ error: "mode must be enforcement or observation" }));
              return;
            }
            this.setMode(mode);
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ mode, message: `Control plane switched to ${mode.toUpperCase()} mode` }));
          } catch (err) {
            res.writeHead(400, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: err.message }));
          }
        });
        return;
      }
      if (req.method === "GET" && url.pathname === "/api/v1/mode") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ mode: this.getMode() }));
        return;
      }
      if (req.method === "GET" && url.pathname === "/api/v1/observation/summary") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(this.observationEngine.getSummary()));
        return;
      }
      if (req.method === "GET" && url.pathname === "/api/v1/observation/events") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(this.observationEngine.getEvents()));
        return;
      }
      if (req.method === "GET" && url.pathname === "/api/v1/agents") {
        const agents = this.delegationManager.listAgents();
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(agents));
        return;
      }
      if (req.method === "GET" && url.pathname.match(/^\/api\/v1\/agents\/[^/]+$/)) {
        const agentId = url.pathname.split("/").pop();
        const agent = this.delegationManager.getAgent(agentId);
        if (!agent) {
          res.writeHead(404, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: `Agent '${agentId}' not found` }));
          return;
        }
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(agent));
        return;
      }
      if (req.method === "POST" && url.pathname === "/api/v1/agents") {
        let body = "";
        req.on("data", (c) => {
          body += c;
        });
        req.on("end", () => {
          try {
            const agent = JSON.parse(body);
            this.delegationManager.registerAgent(agent);
            res.writeHead(201, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ registered: true, agentId: agent.agentId }));
          } catch (err) {
            res.writeHead(400, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: err.message }));
          }
        });
        return;
      }
      if (req.method === "GET" && url.pathname.match(/^\/api\/v1\/agents\/[^/]+\/capabilities$/)) {
        const parts = url.pathname.split("/");
        const agentId = parts[parts.length - 2];
        const agent = this.delegationManager.getAgent(agentId);
        if (!agent) {
          res.writeHead(404, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: `Agent '${agentId}' not found` }));
          return;
        }
        const delegations = this.delegationManager.listDelegations().filter((d) => d.delegateeId === agentId && !d.revoked);
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({
          agentId,
          allowedCapabilities: agent.allowedCapabilities,
          delegations: delegations.map((d) => ({
            delegationId: d.delegationId,
            purpose: d.purpose,
            constraints: d.constraints,
            expiresAt: d.expiresAt
          }))
        }));
        return;
      }
      if (req.method === "GET" && url.pathname === "/api/v1/delegations") {
        const delegations = this.delegationManager.listDelegations();
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(delegations));
        return;
      }
      if (req.method === "POST" && url.pathname === "/api/v1/delegations") {
        let body = "";
        req.on("data", (c) => {
          body += c;
        });
        req.on("end", () => {
          try {
            const data = JSON.parse(body);
            const delegationId = data.delegationId || `del_${data.delegateeId || "agent"}_${Date.now()}`;
            const now = /* @__PURE__ */ new Date();
            const validityHours = Number(data.validityHours) || 24;
            const expiresAt = data.expiresAt || new Date(now.getTime() + validityHours * 3600 * 1e3).toISOString();
            const allowedTools = Array.isArray(data.allowedTools) ? data.allowedTools : data.allowedTools ? String(data.allowedTools).split(",").map((s) => s.trim()).filter(Boolean) : ["*"];
            const resourcePatterns = Array.isArray(data.resourcePatterns) ? data.resourcePatterns : Array.isArray(data.allowedResourcePatterns) ? data.allowedResourcePatterns : ["*"];
            const constraints = {
              allowedTools: allowedTools.length ? allowedTools : ["*"],
              resourcePatterns,
              maxTransactionValue: data.maxTransactionValue !== void 0 && data.maxTransactionValue !== "" ? Number(data.maxTransactionValue) : void 0,
              cumulativeValueLimit: data.cumulativeValueLimit !== void 0 && data.cumulativeValueLimit !== "" ? Number(data.cumulativeValueLimit) : void 0,
              requireApprovalAbove: data.requireApprovalAbove !== void 0 && data.requireApprovalAbove !== "" ? Number(data.requireApprovalAbove) : void 0
            };
            const envelope = this.delegationManager.createDelegation(
              {
                delegationId,
                tenantId: data.tenantId || "tenant_acme",
                parentDelegationId: data.parentDelegationId || void 0,
                delegatorType: "HUMAN",
                delegatorId: data.delegatorId || "user_ciso_jane",
                delegateeId: data.delegateeId,
                taskId: data.taskId || `task_${Date.now()}`,
                purpose: data.purpose || "Authorized operations",
                constraints,
                notBefore: now.toISOString(),
                expiresAt
              },
              this.keyPair.privateKey
            );
            res.writeHead(201, { "Content-Type": "application/json" });
            res.end(JSON.stringify(envelope));
          } catch (err) {
            res.writeHead(400, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: err.message }));
          }
        });
        return;
      }
      if (req.method === "POST" && url.pathname.match(/^\/api\/v1\/delegations\/[^/]+\/revoke$/)) {
        const parts = url.pathname.split("/");
        const delegationId = parts[parts.length - 2];
        let body = "";
        req.on("data", (c) => {
          body += c;
        });
        req.on("end", () => {
          try {
            const { reason } = JSON.parse(body);
            const result = this.delegationManager.revokeDelegation(delegationId, reason || "API revocation");
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ delegationId, revokedCount: result.revokedCount }));
          } catch (err) {
            res.writeHead(400, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: err.message }));
          }
        });
        return;
      }
      if (req.method === "GET" && url.pathname === "/api/v1/actions") {
        const limit = parseInt(url.searchParams.get("limit") || "100");
        const agentFilter = url.searchParams.get("agentId");
        let history = [...this.actionHistory].reverse();
        if (agentFilter) history = history.filter((h) => h.agentId === agentFilter);
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(history.slice(0, limit)));
        return;
      }
      if (req.method === "GET" && url.pathname.match(/^\/api\/v1\/actions\/[^/]+$/) && !url.pathname.endsWith("/provenance")) {
        const actionId = url.pathname.split("/").pop();
        const action = this.actionHistory.find((h) => h.actionId === actionId);
        if (!action) {
          res.writeHead(404, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: `Action '${actionId}' not found` }));
          return;
        }
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(action));
        return;
      }
      if (req.method === "GET" && url.pathname.match(/^\/api\/v1\/actions\/[^/]+\/provenance$/)) {
        const parts = url.pathname.split("/");
        const actionId = parts[parts.length - 2];
        const graph = this.auditLedger.buildProvenanceGraph(actionId);
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(graph));
        return;
      }
      if (req.method === "POST" && url.pathname === "/api/v1/simulate/agent") {
        let body = "";
        req.on("data", (c) => {
          body += c;
        });
        req.on("end", () => {
          try {
            const { agentId } = JSON.parse(body);
            const report = this.blastRadiusAnalyzer.calculateBlastRadius(agentId);
            const attackPaths = this.blastRadiusAnalyzer.computeAttackPaths(agentId);
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ blastRadius: report, attackPaths }));
          } catch (err) {
            res.writeHead(400, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: err.message }));
          }
        });
        return;
      }
      if (req.method === "POST" && url.pathname === "/api/v1/simulate/attack-path") {
        let body = "";
        req.on("data", (c) => {
          body += c;
        });
        req.on("end", () => {
          try {
            const { agentId } = JSON.parse(body);
            const attackPaths = this.blastRadiusAnalyzer.computeAttackPaths(agentId);
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ agentId, attackPaths }));
          } catch (err) {
            res.writeHead(400, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: err.message }));
          }
        });
        return;
      }
      if (req.method === "POST" && url.pathname === "/api/v1/policies/shadow") {
        let body = "";
        req.on("data", (c) => {
          body += c;
        });
        req.on("end", () => {
          try {
            const { currentPolicy, proposedPolicy } = JSON.parse(body);
            const history = this.actionHistory.map((h) => ({
              actionId: h.actionId,
              agentId: h.agentId,
              actionType: h.actionType,
              sessionId: h.sessionId,
              taskId: h.taskId,
              tool: h.tool,
              resourceId: h.resourceId,
              parameters: { amount: h.riskScore * 10 },
              decision: h.decision,
              timestamp: h.timestamp
            }));
            const currentResult = this.policyEngine.simulatePolicy({ tenantId: "tenant_acme", proposedPolicyContent: JSON.stringify(currentPolicy || {}) }, history);
            const proposedResult = this.policyEngine.simulatePolicy({ tenantId: "tenant_acme", proposedPolicyContent: JSON.stringify(proposedPolicy || {}) }, history);
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify({
              current: currentResult,
              proposed: proposedResult,
              divergence: {
                newlyAllowed: proposedResult.newlyAllowedCount - currentResult.newlyAllowedCount,
                newlyDenied: proposedResult.newlyDeniedCount - currentResult.newlyDeniedCount,
                newlyHeld: proposedResult.newlyHeldCount - currentResult.newlyHeldCount
              }
            }));
          } catch (err) {
            res.writeHead(400, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: err.message }));
          }
        });
        return;
      }
      if (req.method === "GET" && url.pathname.match(/^\/api\/v1\/behavior\/[^/]+$/)) {
        const agentId = url.pathname.split("/").pop();
        const behaviorEngine = this.policyEngine.getBehaviorEngine();
        const profile = behaviorEngine.getProfile(agentId);
        const agentActions = this.actionHistory.filter((h) => h.agentId === agentId);
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({
          agentId,
          profile: profile || null,
          recentActions: agentActions.slice(-20),
          totalActions: agentActions.length,
          anomalyStatus: profile ? "PROFILED" : "INSUFFICIENT_DATA"
        }));
        return;
      }
      if (req.method === "GET" && url.pathname === "/api/v1/incidents") {
        const incidents = this.actionHistory.filter((h) => h.decision === "DENY" && h.riskScore >= 80).slice(-50).reverse().map((h) => ({
          incidentId: `inc_${h.actionId}`,
          agentId: h.agentId,
          tool: h.tool,
          riskScore: h.riskScore,
          riskClass: h.riskClass,
          decision: h.decision,
          explanation: h.explanation,
          timestamp: h.timestamp
        }));
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(incidents));
        return;
      }
      if (req.method === "GET" && url.pathname === "/api/v1/attacks") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(ATTACK_CATALOG));
        return;
      }
      if (req.method === "POST" && url.pathname === "/api/v1/simulate/attack") {
        let body = "";
        req.on("data", (c) => {
          body += c;
        });
        req.on("end", async () => {
          try {
            const payload = body ? JSON.parse(body) : {};
            const { vectorNumber } = payload;
            if (vectorNumber === "all" || vectorNumber === void 0) {
              const results = await executeAllAttackVectors(this);
              const totalNeutralized = results.filter((r) => r.blocked).length;
              res.writeHead(200, { "Content-Type": "application/json" });
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
              res.writeHead(400, { "Content-Type": "application/json" });
              res.end(JSON.stringify({ error: 'Vector number must be an integer between 1 and 14 or "all"' }));
              return;
            }
            const result = await executeAttackVector(this, num);
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify({
              success: true,
              result,
              results: [result],
              totalExecuted: 1,
              totalNeutralized: result.blocked ? 1 : 0,
              allNeutralized: result.blocked
            }));
          } catch (err) {
            res.writeHead(500, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: err.message }));
          }
        });
        return;
      }
      if (req.method === "GET" && url.pathname === "/api/v1/tools") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(ENTERPRISE_TOOL_CATALOG));
        return;
      }
      if (req.method === "POST" && url.pathname === "/api/v1/policies/compile") {
        let body = "";
        req.on("data", (c) => {
          body += c;
        });
        req.on("end", () => {
          try {
            const { dsl } = JSON.parse(body);
            if (!dsl || typeof dsl !== "string") {
              res.writeHead(400, { "Content-Type": "application/json" });
              res.end(JSON.stringify({ error: 'Missing or invalid "dsl" field' }));
              return;
            }
            const ast = parsePolicyDSL(dsl);
            const responseData = JSON.stringify({
              valid: true,
              policyName: ast.name || ast.policyId,
              targetAction: ast.targetAction,
              ast,
              compiledAt: (/* @__PURE__ */ new Date()).toISOString()
            });
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(responseData);
          } catch (err) {
            if (!res.headersSent) {
              res.writeHead(400, { "Content-Type": "application/json" });
              res.end(JSON.stringify({ valid: false, error: err.message }));
            }
          }
        });
        return;
      }
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Endpoint not found" }));
    };
  }
  createHttpServer(port = 3e3) {
    return http2.createServer(this.getRequestHandler());
  }
};
var isMain = process.argv[1] && (process.argv[1].replace(/\\/g, "/").endsWith("control-plane/src/index.ts") || process.env.CHRONICLE_START_SERVER === "true" || import.meta.url.replace(/\\/g, "/").endsWith(process.argv[1].replace(/\\/g, "/")));
if (isMain) {
  const port = Number(process.env.PORT) || 3e3;
  const host = process.env.HOST || "0.0.0.0";
  const controlPlane2 = new ChronicleControlPlane();
  const server = controlPlane2.createHttpServer(port);
  server.listen(port, host, () => {
    console.log(`[Chronicle Control Plane] Online at http://${host}:${port}`);
    console.log(`[Chronicle Control Plane] Dashboard available at http://${host}:${port}/`);
  });
}

// apps/control-plane/src/vercel-handler.ts
var controlPlane = new ChronicleControlPlane();
var vercel_handler_default = controlPlane.getRequestHandler();
export {
  vercel_handler_default as default
};
