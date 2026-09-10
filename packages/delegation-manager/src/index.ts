import type {
  TenantId,
  AgentId,
  UserId,
  DelegationId,
  HumanSponsor,
  AgentIdentity,
  DelegationEnvelope,
  DelegationConstraints,
  DelegationChain,
  ReasonCode
} from '@chronicle/core-types';
import {
  signEd25519,
  verifyEd25519,
  canonicalJsonStringify
} from '@chronicle/crypto-primitives';

export interface DelegationValidationResult {
  valid: boolean;
  reasonCode?: ReasonCode;
  explanation?: string;
  chain?: DelegationChain;
}

export class DelegationManager {
  private sponsors: Map<UserId, HumanSponsor> = new Map();
  private agents: Map<AgentId, AgentIdentity> = new Map();
  private delegations: Map<DelegationId, DelegationEnvelope> = new Map();
  private childDelegations: Map<DelegationId, Set<DelegationId>> = new Map();

  // 1. Identity Management
  public registerSponsor(sponsor: HumanSponsor): void {
    this.sponsors.set(sponsor.userId, { ...sponsor });
  }

  public getSponsor(userId: UserId): HumanSponsor | undefined {
    return this.sponsors.get(userId);
  }

  public registerAgent(agent: AgentIdentity): void {
    this.agents.set(agent.agentId, { ...agent });
  }

  public getAgent(agentId: AgentId): AgentIdentity | undefined {
    return this.agents.get(agentId);
  }

  public listAgents(): AgentIdentity[] {
    return Array.from(this.agents.values());
  }

  public listSponsors(): HumanSponsor[] {
    return Array.from(this.sponsors.values());
  }

  public setAgentStatus(agentId: AgentId, status: AgentIdentity['status']): boolean {
    const agent = this.agents.get(agentId);
    if (!agent) return false;
    agent.status = status;
    return true;
  }

  // 2. Monotonic Privilege Narrowing Validation
  public validateMonotonicNarrowing(
    parentConstraints: DelegationConstraints,
    childConstraints: DelegationConstraints
  ): { valid: boolean; violation?: string } {
    // A. Tools narrowing: child tools must be subset of parent tools
    for (const tool of childConstraints.allowedTools) {
      if (!parentConstraints.allowedTools.includes('*') && !parentConstraints.allowedTools.includes(tool)) {
        return {
          valid: false,
          violation: `Child delegation requests unauthorized tool '${tool}' not granted by parent`
        };
      }
    }

    // B. Transaction value limit narrowing: child max <= parent max
    if (parentConstraints.maxTransactionValue !== undefined) {
      if (
        childConstraints.maxTransactionValue === undefined ||
        childConstraints.maxTransactionValue > parentConstraints.maxTransactionValue
      ) {
        return {
          valid: false,
          violation: `Child maxTransactionValue (${childConstraints.maxTransactionValue}) exceeds parent limit (${parentConstraints.maxTransactionValue})`
        };
      }
    }

    // C. Cumulative value limit narrowing: child cumulative <= parent cumulative
    if (parentConstraints.cumulativeValueLimit !== undefined) {
      if (
        childConstraints.cumulativeValueLimit === undefined ||
        childConstraints.cumulativeValueLimit > parentConstraints.cumulativeValueLimit
      ) {
        return {
          valid: false,
          violation: `Child cumulativeValueLimit (${childConstraints.cumulativeValueLimit}) exceeds parent cumulative limit (${parentConstraints.cumulativeValueLimit})`
        };
      }
    }

    // D. Action types narrowing
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
  public createDelegation(
    envelope: Omit<DelegationEnvelope, 'signature' | 'createdAt' | 'revoked'>,
    signerPrivateKeyPem: string
  ): DelegationEnvelope {
    // If child delegation, verify monotonic narrowing against parent
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

      // Temporal validity check
      const parentExp = new Date(parent.expiresAt).getTime();
      const childExp = new Date(envelope.expiresAt).getTime();
      if (childExp > parentExp) {
        throw new Error(`Child delegation expiration (${envelope.expiresAt}) cannot exceed parent expiration (${parent.expiresAt})`);
      }
    }

    const createdAt = new Date().toISOString();
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

    const fullEnvelope: DelegationEnvelope = {
      ...envelope,
      createdAt,
      revoked: false,
      signature
    };

    this.delegations.set(fullEnvelope.delegationId, fullEnvelope);

    if (fullEnvelope.parentDelegationId) {
      if (!this.childDelegations.has(fullEnvelope.parentDelegationId)) {
        this.childDelegations.set(fullEnvelope.parentDelegationId, new Set());
      }
      this.childDelegations.get(fullEnvelope.parentDelegationId)!.add(fullEnvelope.delegationId);
    }

    return fullEnvelope;
  }

  // 4. Revocation with Cascading Invalidation
  public revokeDelegation(delegationId: DelegationId, reason: string): { revokedCount: number } {
    const target = this.delegations.get(delegationId);
    if (!target) return { revokedCount: 0 };

    let count = 0;
    const toRevoke = [delegationId];

    while (toRevoke.length > 0) {
      const currentId = toRevoke.shift()!;
      const del = this.delegations.get(currentId);
      if (del && !del.revoked) {
        del.revoked = true;
        del.revokedAt = new Date().toISOString();
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
  public verifyDelegationChain(delegationId: DelegationId, agentId: AgentId): DelegationValidationResult {
    const chain: DelegationEnvelope[] = [];
    let currentId: DelegationId | undefined = delegationId;
    const now = Date.now();

    while (currentId) {
      const envelope = this.delegations.get(currentId);
      if (!envelope) {
        return {
          valid: false,
          reasonCode: 'DELEGATION_INVALID',
          explanation: `Delegation '${currentId}' not found in registry`
        };
      }

      // Check Revocation
      if (envelope.revoked) {
        return {
          valid: false,
          reasonCode: 'DELEGATION_REVOKED',
          explanation: `Delegation '${envelope.delegationId}' has been revoked (${envelope.revokedReason || 'No reason provided'})`
        };
      }

      // Check Expiration
      const notBefore = new Date(envelope.notBefore).getTime();
      const expiresAt = new Date(envelope.expiresAt).getTime();
      if (now < notBefore) {
        return {
          valid: false,
          reasonCode: 'DELEGATION_INVALID',
          explanation: `Delegation '${envelope.delegationId}' is not yet valid (notBefore: ${envelope.notBefore})`
        };
      }
      if (now > expiresAt) {
        return {
          valid: false,
          reasonCode: 'DELEGATION_INVALID',
          explanation: `Delegation '${envelope.delegationId}' expired at ${envelope.expiresAt}`
        };
      }

      // Verify cryptographic signature
      let delegatorPublicKey: string | undefined;
      if (envelope.delegatorType === 'HUMAN') {
        const sponsor = this.sponsors.get(envelope.delegatorId);
        if (!sponsor) {
          return {
            valid: false,
            reasonCode: 'DELEGATION_INVALID',
            explanation: `Human sponsor '${envelope.delegatorId}' not found`
          };
        }
        delegatorPublicKey = sponsor.publicKey;
      } else {
        const parentAgent = this.agents.get(envelope.delegatorId);
        if (!parentAgent) {
          return {
            valid: false,
            reasonCode: 'DELEGATION_INVALID',
            explanation: `Delegating agent '${envelope.delegatorId}' not found`
          };
        }
        if (parentAgent.status !== 'ACTIVE') {
          return {
            valid: false,
            reasonCode: 'AGENT_QUARANTINED',
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
          reasonCode: 'DELEGATION_INVALID',
          explanation: `Cryptographic signature on delegation '${envelope.delegationId}' failed verification`
        };
      }

      chain.unshift(envelope); // Root first
      currentId = envelope.parentDelegationId;
    }

    if (chain.length === 0) {
      return {
        valid: false,
        reasonCode: 'DELEGATION_INVALID',
        explanation: 'Empty delegation chain'
      };
    }

    // Verify root is human sponsor
    const rootEnvelope = chain[0];
    if (rootEnvelope.delegatorType !== 'HUMAN') {
      return {
        valid: false,
        reasonCode: 'DELEGATION_INVALID',
        explanation: `Root delegation '${rootEnvelope.delegationId}' must originate from a HUMAN sponsor`
      };
    }

    const rootSponsor = this.sponsors.get(rootEnvelope.delegatorId);
    if (!rootSponsor) {
      return {
        valid: false,
        reasonCode: 'DELEGATION_INVALID',
        explanation: `Root sponsor '${rootEnvelope.delegatorId}' not found`
      };
    }

    // Verify terminal delegatee matches requested active agent
    const terminalEnvelope = chain[chain.length - 1];
    if (terminalEnvelope.delegateeId !== agentId) {
      return {
        valid: false,
        reasonCode: 'DELEGATION_INVALID',
        explanation: `Delegation chain terminates at agent '${terminalEnvelope.delegateeId}', but action was submitted by '${agentId}'`
      };
    }

    // Verify tenant isolation: all delegation hops must share the same tenant (§71, §114)
    const rootTenant = chain[0].tenantId;
    for (const link of chain) {
      if (link.tenantId !== rootTenant) {
        return {
          valid: false,
          reasonCode: 'DELEGATION_INVALID',
          explanation: `Cross-tenant delegation detected: chain mixes tenants '${rootTenant}' and '${link.tenantId}'`
        };
      }
    }

    const activeAgent = this.agents.get(agentId);
    if (!activeAgent) {
      return {
        valid: false,
        reasonCode: 'DELEGATION_INVALID',
        explanation: `Active agent '${agentId}' not found in registry`
      };
    }

    if (activeAgent.status !== 'ACTIVE') {
      return {
        valid: false,
        reasonCode: 'AGENT_QUARANTINED',
        explanation: `Active agent '${agentId}' is ${activeAgent.status}`
      };
    }

    // Verify monotonic narrowing across all hops in chain
    for (let i = 0; i < chain.length - 1; i++) {
      const parent = chain[i];
      const child = chain[i + 1];
      const narrowing = this.validateMonotonicNarrowing(parent.constraints, child.constraints);
      if (!narrowing.valid) {
        return {
          valid: false,
          reasonCode: 'MONOTONIC_NARROWING_VIOLATION',
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
  private matchesGlobPattern(resourceId: string, pattern: string): boolean {
    if (pattern === '*' || pattern === '**') return true;
    const regexStr = '^' + pattern
      .replace(/[.+^${}()|[\]\\]/g, '\\$&')
      .replace(/\*\*/g, '__DS__')
      .replace(/\*/g, '[^:]+')
      .replace(/__DS__/g, '.*') + '$';
    return new RegExp(regexStr).test(resourceId);
  }

  /**
   * Verify that a resource ID is within the scope of a delegation's resource patterns.
   * Blocks resource traversal attacks where an agent accesses out-of-scope resources.
   */
  public checkResourceScope(resourceId: string, delegationId: DelegationId): { allowed: boolean; reason?: string } {
    const delegation = this.delegations.get(delegationId);
    if (!delegation) {
      return { allowed: false, reason: `Delegation '${delegationId}' not found` };
    }
    const patterns = delegation.constraints.resourcePatterns;
    if (!patterns || patterns.length === 0 || patterns.includes('*')) {
      return { allowed: true };
    }
    const matches = patterns.some(p => this.matchesGlobPattern(resourceId, p));
    if (!matches) {
      return {
        allowed: false,
        reason: `Resource '${resourceId}' does not match delegation resource patterns: [${patterns.join(', ')}]`
      };
    }
    return { allowed: true };
  }

  public getDelegation(delegationId: DelegationId): DelegationEnvelope | undefined {
    return this.delegations.get(delegationId);
  }

  public listDelegations(): DelegationEnvelope[] {
    return Array.from(this.delegations.values());
  }
}
