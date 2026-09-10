/**
 * Chronicle Adversarial Attack Catalog (§106, §107)
 * Definitive taxonomy of the 14 real-world attack vectors neutralized by Chronicle AACT.
 */

export interface AttackVectorMetadata {
  vectorNumber: number;
  id: string;
  title: string;
  category: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  mitreTechnique: string;
  description: string;
  targetTool: string;
  targetAgent: string;
  defenseMechanism: string;
}

export const ATTACK_CATALOG: AttackVectorMetadata[] = [
  {
    vectorNumber: 1,
    id: 'attack_toctou',
    title: 'Parameter Tampering / TOCTOU Attack',
    category: 'Cryptographic Integrity',
    severity: 'CRITICAL',
    mitreTechnique: 'T1565.001 (Data Manipulation)',
    description: 'Adversary intercepts a legitimate $50 refund grant and modifies the execution payload to $50,000 before reaching enterprise downstream APIs.',
    targetTool: 'stripe_refund',
    targetAgent: 'agent_finance_refund',
    defenseMechanism: 'Canonical Parameter Hash Cryptographic Binding (RFC 8785 SHA-256)'
  },
  {
    vectorNumber: 2,
    id: 'attack_expired_grant',
    title: 'Expired Authorization Grant Replay',
    category: 'Replay & Nonce Defense',
    severity: 'HIGH',
    mitreTechnique: 'T1550.001 (Application Access Token Replay)',
    description: 'Adversary captures a previously issued authorization grant and replays it after its 30-second temporal TTL window has elapsed.',
    targetTool: 'stripe_refund',
    targetAgent: 'agent_finance_refund',
    defenseMechanism: 'Ephemeral Grant TTL Enforcement & Nonce Invalidation'
  },
  {
    vectorNumber: 3,
    id: 'attack_prompt_injection',
    title: 'Prompt Injection & Declared Intent Drift',
    category: 'Adversarial Prompt Injection',
    severity: 'CRITICAL',
    mitreTechnique: 'T1059 (Command & Scripting Injection)',
    description: 'Attacker leverages indirect prompt injection inside customer inquiry text to trick a support agent into calling unauthorized wire transfers ($10,000).',
    targetTool: 'send_wire_transfer',
    targetAgent: 'agent_support_general',
    defenseMechanism: 'Delegation Scope & Intent Drift Enforcement (Fail-Closed RBAC)'
  },
  {
    vectorNumber: 4,
    id: 'attack_sequence_exfil',
    title: 'Forbidden Cross-Tool Sequence Exfiltration',
    category: 'Sequence & Behavioral Invariants',
    severity: 'CRITICAL',
    mitreTechnique: 'T1048.003 (Exfiltration Over Alternative Protocol)',
    description: 'Agent legitimately reads confidential customer PII (SSN, credit score), and immediately attempts to pipe and broadcast data via outbound email.',
    targetTool: 'send_external_email',
    targetAgent: 'agent_support_general',
    defenseMechanism: 'Stateful Action Sequence & Data Loss Prevention (DLP) Gating'
  },
  {
    vectorNumber: 5,
    id: 'attack_monotonic_expansion',
    title: 'Monotonic Privilege Narrowing Expansion Attempt',
    category: 'Delegation Hierarchy',
    severity: 'CRITICAL',
    mitreTechnique: 'T1068 (Exploitation for Privilege Escalation)',
    description: 'Sub-agent attempts to mint or inherit broader capabilities (wire transfer) than its parent delegation envelope possesses.',
    targetTool: 'send_wire_transfer',
    targetAgent: 'agent_finance_refund',
    defenseMechanism: 'Mathematical Monotonic Privilege Invariant Verification (P_child ⊆ P_parent)'
  },
  {
    vectorNumber: 6,
    id: 'attack_smurfing_structuring',
    title: 'Smurfing / Cumulative Limit Evasion Attack',
    category: 'Financial & Cumulative Gating',
    severity: 'HIGH',
    mitreTechnique: 'T1565.002 (Transaction Boundary Smurfing)',
    description: 'Adversary structures refunds into 11 rapid $900 transactions to stay beneath the $1,000 single-action threshold, attempting to drain $10,800.',
    targetTool: 'stripe_refund',
    targetAgent: 'agent_finance_refund',
    defenseMechanism: 'Rolling Window Cumulative Limit & Structuring Defense ($10,000 Ceiling)'
  },
  {
    vectorNumber: 7,
    id: 'attack_killswitch_quarantine',
    title: 'Compromised Agent Lockdown via Emergency Kill Switch',
    category: 'Quarantine & Kill-Switch',
    severity: 'CRITICAL',
    mitreTechnique: 'T1499 (Zero-Day Agent Containment)',
    description: 'A compromised agent attempts actions while under active security quarantine or during global infrastructure emergency lockdown.',
    targetTool: 'stripe_refund',
    targetAgent: 'agent_finance_refund',
    defenseMechanism: 'Zero-Latency Blast Radius Quarantine & Immediate Revocation'
  },
  {
    vectorNumber: 8,
    id: 'attack_stale_delegation',
    title: 'Stale Delegation Reuse (Expired Temporal Window)',
    category: 'Temporal Validity',
    severity: 'MEDIUM',
    mitreTechnique: 'T1078.004 (Valid Accounts: Stale Credentials)',
    description: 'Agent attempts to invoke actions using an expired delegation envelope whose validity window elapsed in the past.',
    targetTool: 'stripe_refund',
    targetAgent: 'agent_stale_test',
    defenseMechanism: 'Temporal Validity Window Enforcement with Clock-Aware Expiry Checking'
  },
  {
    vectorNumber: 9,
    id: 'attack_cross_tenant',
    title: 'Cross-Tenant Agent Impersonation',
    category: 'Multi-Tenant Boundary',
    severity: 'CRITICAL',
    mitreTechnique: 'T1558 (Steal or Forge Kerberos/SAML/JWT Cross-Tenant Tickets)',
    description: 'An agent registered to Tenant Acme attempts to authorize against Tenant Evil resources and delegations.',
    targetTool: 'stripe_refund',
    targetAgent: 'agent_finance_refund',
    defenseMechanism: 'Multi-Tenant Cryptographic Isolation & Tenant Binding Verification'
  },
  {
    vectorNumber: 10,
    id: 'attack_cross_task_abuse',
    title: 'Cumulative Authority Abuse Across Task Boundaries',
    category: 'Task Boundary Isolation',
    severity: 'HIGH',
    mitreTechnique: 'T1531 (Account Resource Exhaustion)',
    description: 'Adversary attempts to circumvent cumulative spend limits by dynamically creating new Task IDs and Session IDs on the fly.',
    targetTool: 'stripe_refund',
    targetAgent: 'agent_finance_refund',
    defenseMechanism: 'Delegation-Level Cumulative Limit Persisted Across Task & Session Boundaries'
  },
  {
    vectorNumber: 11,
    id: 'attack_consumed_grant_replay',
    title: 'Consumed Authorization Grant Replay',
    category: 'Double-Spend Prevention',
    severity: 'HIGH',
    mitreTechnique: 'T1550 (Use Alternate Authentication Material)',
    description: 'Adversary captures a valid grant that has already been consumed once and attempts a secondary replay double-spend.',
    targetTool: 'stripe_refund',
    targetAgent: 'agent_replay_test',
    defenseMechanism: 'Ephemeral Single-Use Grant TTL & Nonce Consumption Tracker'
  },
  {
    vectorNumber: 12,
    id: 'attack_resource_traversal',
    title: 'Resource Traversal Outside Delegation Scope',
    category: 'Resource Scoping',
    severity: 'HIGH',
    mitreTechnique: 'T1083 (File and Directory Discovery / Path Traversal)',
    description: 'Support agent granted access strictly to customer resources (`cust:*`) attempts to target production Kubernetes clusters (`k8s:prod-cluster`).',
    targetTool: 'read_customer_pii',
    targetAgent: 'agent_support_general',
    defenseMechanism: 'Delegation Resource Pattern Scoping (Glob Pattern Boundary Enforcement)'
  },
  {
    vectorNumber: 13,
    id: 'attack_circular_delegation',
    title: 'Circular Delegation Abuse & Parent Chain Forgery',
    category: 'Parent Chain Integrity',
    severity: 'MEDIUM',
    mitreTechnique: 'T1078 (Valid Accounts: Forged Chain)',
    description: 'Adversary attempts to inject a self-referencing delegation envelope to create an infinite evaluation loop or break monotonic verification.',
    targetTool: 'search_customers',
    targetAgent: 'agent_support_general',
    defenseMechanism: 'Delegation Chain Integrity Verification & Parent Registry Lookup Guard'
  },
  {
    vectorNumber: 14,
    id: 'attack_runaway_loop',
    title: 'Agent Runaway Loop / Tool Abuse Rapid Burst',
    category: 'Rate Limiting & Burst Anomaly',
    severity: 'MEDIUM',
    mitreTechnique: 'T1499.003 (Endpoint DoS: Application Exhaustion)',
    description: 'A misconfigured or hallucinating agent executes 30 rapid identical queries within seconds, risking API rate limit exhaustion and billing denial of service.',
    targetTool: 'search_customers',
    targetAgent: 'agent_support_general',
    defenseMechanism: 'Stateful Session Sequence Detector (Burst & Runaway Loop Anomaly Threshold)'
  }
];
