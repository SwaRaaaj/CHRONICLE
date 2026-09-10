<div align="center">

```
   ██████╗██╗  ██╗██████╗  ██████╗ ███╗   ██╗██╗ ██████╗██╗     ███████╗
  ██╔════╝██║  ██║██╔══██╗██╔═══██╗████╗  ██║██║██╔════╝██║     ██╔════╝
  ██║     ███████║██████╔╝██║   ██║██╔██╗ ██║██║██║     ██║     █████╗  
  ██║     ██╔══██║██╔══██╗██║   ██║██║╚██╗██║██║██║     ██║     ██╔══╝  
  ╚██████╗██║  ██║██║  ██║╚██████╔╝██║ ╚████║██║╚██████╗███████╗███████╗
   ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝ ╚═════╝╚══════╝╚══════╝
```

# CHRONICLE (AACT)
### **Autonomous Action Control Plane for AI Agents**
#### *Behavior-Aware, Sequence-Aware Authorization & Runtime Side-Effect Control Kernel*

<br/>

[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D22.6.0-22c55e.svg?style=for-the-badge&logo=node.js&logoColor=white)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-Native%20Strip--Types-3178c6.svg?style=for-the-badge&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Cryptography](https://img.shields.io/badge/Cryptography-Ed25519%20%7C%20SHA--256%20Merkle-6366f1.svg?style=for-the-badge&logo=target&logoColor=white)](#)
[![Latency](https://img.shields.io/badge/Latency-p50%200.71ms%20%7C%20p99%201.61ms-06b6d4.svg?style=for-the-badge)](#)
[![Throughput](https://img.shields.io/badge/Throughput-1%2C307%20decisions%2Fsec-f59e0b.svg?style=for-the-badge)](#)
[![Security Suite](https://img.shields.io/badge/Adversarial%20Attacks-14%2F14%20Neutralized-emerald.svg?style=for-the-badge)](#)
[![Unit Tests](https://img.shields.io/badge/Test%20Matrix-150%2F150%20Passing-22c55e.svg?style=for-the-badge)](#)
[![PRs Welcome](https://img.shields.io/badge/PRs-Welcome-brightgreen.svg?style=for-the-badge&logo=github)](CONTRIBUTING.md)
[![Architect](https://img.shields.io/badge/Architect-Swaraj-ec4899.svg?style=for-the-badge)](#)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=for-the-badge)](LICENSE)

<br/>

**[Explore Documentation](#table-of-contents)** • **[Quickstart](#19-quickstart--local-deployment-guide)** • **[Architecture God Diagram](#3-high-level-system-topology)** • **[Attack Suite](#15-adversarial-attack-neutralization-matrix-1414-verified)** • **[REST API Reference](#17-complete-rest-api-reference)** • **[Contributing](#20-contributing-to-chronicle-community-rfcs--pull-requests)**

---

</div>

> [!IMPORTANT]
> **Production Status (v1.0.0 GA)**: Chronicle has passed all **150 automated verification suites** and neutralized **14/14 adversarial attack vectors** with zero runtime dependencies on external AI models in the blocking path. Core authorization latency operates between **0.71 ms and 1.34 ms**.

---

## Table of Contents

- [0. Author & System Attribution](#0-author--system-attribution)
- [1. Executive Summary: The Autonomous Agency Paradox](#1-executive-summary-the-autonomous-agency-paradox)
  - [The Fundamental Flaw of Traditional IAM](#the-fundamental-flaw-of-traditional-iam)
  - [The Chronicle Paradigm Shift](#the-chronicle-paradigm-shift)
- [2. The 4-Tier Zero-Trust Ring Model](#2-the-4-tier-zero-trust-ring-model)
- [3. High-Level System Topology](#3-high-level-system-topology)
- [4. End-to-End Zero-Trust Runtime Lifecycle](#4-end-to-end-zero-trust-runtime-lifecycle)
- [5. Mathematical Foundations & Security Invariants](#5-mathematical-foundations--security-invariants)
  - [5.1 Lattice-Theoretic Monotonic Privilege Narrowing](#51-lattice-theoretic-monotonic-privilege-narrowing)
  - [5.2 Anti-TOCTOU Canonical Parameter Hashing (RFC 8785)](#52-anti-toctou-canonical-parameter-hashing-rfc-8785)
  - [5.3 Stateful Sequence Automata & Cross-Tool Exfiltration DFA](#53-stateful-sequence-automata--cross-tool-exfiltration-dfa)
  - [5.4 Sliding-Window Cumulative Velocity & Structuring Defense](#54-sliding-window-cumulative-velocity--structuring-defense)
  - [5.5 Runaway Agent Loop Circuit Breaker](#55-runaway-agent-loop-circuit-breaker)
  - [5.6 Multi-Factor Dynamic Risk Scoring Tensor](#56-multi-factor-dynamic-risk-scoring-tensor)
  - [5.7 Streaming Gaussian Anomaly Quantification (Welford's Algorithm)](#57-streaming-gaussian-anomaly-quantification-welfords-algorithm)
  - [5.8 Merkle-Chained Tamper-Evident Ledger & Ed25519 Signatures](#58-merkle-chained-tamper-evident-ledger--ed25519-signatures)
- [6. Deep-Dive Subsystem Specifications](#6-deep-dive-subsystem-specifications)
  - [6.1 Delegation Engine & Monotonic Narrowing](#61-delegation-engine--monotonic-narrowing-packagesdelegation-manager)
  - [6.2 Cryptographic Primitives & Grant Issuance](#62-cryptographic-primitives--grant-issuance-packagescrypto-primitives)
  - [6.3 Sequence Detector & Invariant Engine](#63-sequence-detector--invariant-engine-packagessequence-detector)
  - [6.4 Formal Workflow Engine & State Machine](#64-formal-workflow-engine--state-machine-packagesworkflow-engine)
  - [6.5 Behavioral Profiling Engine](#65-behavioral-profiling-engine-packagesbehavior-engine)
  - [6.6 Declarative Policy DSL & Shadow Comparator](#66-declarative-policy-dsl--shadow-comparator-packagespolicy-dsl)
  - [6.7 Observation Mode & Shadow Telemetry](#67-observation-mode--shadow-telemetry-packagesobservation)
  - [6.8 AI Policy Assistant & NLP Synthesis](#68-ai-policy-assistant--nlp-synthesis-packagesai)
  - [6.9 Topological Blast Radius & Lateral Movement Engine](#69-topological-blast-radius--lateral-movement-engine-packagesblast-radius)
  - [6.10 Merkle Audit Ledger & Provenance DAG](#610-merkle-audit-ledger--provenance-dag-packagesaudit-ledger)
  - [6.11 Enterprise Identity & OIDC Federation Bridge](#611-enterprise-identity--oidc-federation-bridge-packagesintegrations)
  - [6.12 Distributed Persistence Adapter & Database Migrations](#612-distributed-persistence-adapter--database-migrations-packagespersistence)
  - [6.13 Developer Client SDK & Grant Verification Kernel](#613-developer-client-sdk--grant-verification-kernel-packagessdk)
- [7. Application Tier Overview](#7-application-tier-overview)
  - [7.1 Central Control Plane Server (:3000)](#71-central-control-plane-server-3000)
  - [7.2 Model Context Protocol (MCP) Security Gateway (:3001)](#72-model-context-protocol-mcp-security-gateway-3001)
  - [7.3 Unified Command-Line Interface (`aact`)](#73-unified-command-line-interface-aact)
  - [7.4 Enterprise Cybersecurity Web Console](#74-enterprise-cybersecurity-web-console)
- [8. Complete Monorepo Workspace Structure](#8-complete-monorepo-workspace-structure)
- [9. Complete REST API Reference](#9-complete-rest-api-reference)
- [10. Unified CLI Manual (`aact`)](#10-unified-cli-manual-aact)
- [11. Adversarial Attack Neutralization Matrix (14/14 Verified)](#11-adversarial-attack-neutralization-matrix-1414-verified)
- [12. Empirical Performance & Latency Benchmarks](#12-empirical-performance--latency-benchmarks)
- [13. Quickstart & Local Deployment Guide](#13-quickstart--local-deployment-guide)
- [14. Production Deployment & Kubernetes Configuration](#14-production-deployment--kubernetes-configuration)
- [15. Contributing to Chronicle: Community RFCs & Pull Requests](#15-contributing-to-chronicle-community-rfcs--pull-requests)
- [16. Security Vulnerability Disclosure Policy](#16-security-vulnerability-disclosure-policy)
- [17. Frequently Asked Questions (FAQ)](#17-frequently-asked-questions-faq)
- [18. License & Attribution](#18-license--attribution)

---

## 0. Author & System Attribution

| Specification Metric | Architectural Standard |
|---|---|
| **Founder & Principal Systems Architect** | **Swaraj** |
| **System Classification** | Autonomous Action Control Plane (AACT) / Zero-Trust AI Agent Kernel |
| **Official Repository** | [`https://github.com/SwaRaaaj/CHRONICLE`](https://github.com/SwaRaaaj/CHRONICLE) |
| **Canonical Cryptography Standards** | **RFC 8785** (JSON Canonicalization Scheme - JCS)<br/>**RFC 8032** (Edwards-Curve Digital Signature Algorithm - Ed25519)<br/>**RFC 6962** (Certificate Transparency Append-Only Merkle Hash Trees) |
| **Network & Interop Protocols** | **JSON-RPC 2.0** (Model Context Protocol - MCP)<br/>**OpenID Connect Core 1.0** (Enterprise Identity Federation)<br/>**HTTP/1.1 & WebSocket** (Real-Time Action Telemetry) |
| **Execution Guarantees** | Sub-millisecond deterministic evaluation. **Zero non-deterministic AI models in synchronous blocking path.** |

---

## 1. Executive Summary: The Autonomous Agency Paradox

### The Fundamental Flaw of Traditional IAM

Traditional enterprise cybersecurity architectures (Role-Based Access Control, Attribute-Based Access Control, OAuth 2.0 Scopes, AWS IAM Policy Documents) evaluate a static, two-dimensional authorization function:

$$\mathcal{F}_{\text{traditional}} : \text{Subject} \times \text{Permission} \longrightarrow \{\text{ALLOW}, \text{DENY}\}$$

In deterministic software systems, this model functions adequately because application code execution paths, control branches, and database queries are compiled and pre-determined by human developers.

**In autonomous AI agent meshes, however, this model collapses completely.**

When an LLM agent (powered by Claude, GPT-4, Gemini, or open weights) is granted API access to high-impact external systems—payment gateways (Stripe, Adyen), production databases (PostgreSQL, Snowflake), cloud infrastructure (Kubernetes, AWS IAM, Terraform), or communication rails (SendGrid, Slack, Twilio)—the security question is **never whether the agent possesses the static permission to call the tool**.

The true, zero-trust security question is:

> *"Given Human Sponsor Alice, Task 'Resolve Support Ticket #892', Monotonic Delegation Limit $1,000, Prior Action 'read-customer-pii', Resource Sensitivity 'CONFIDENTIAL', Rolling Velocity $4,200/hour, and DFA State S1: **SHOULD THIS EXACT $450 REFUND ON CHARGE `ch_8812` BE PERMITTED AT THIS EXACT MICROSECOND?**"*

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                          THE AUTONOMOUS AGENCY PARADOX                                 │
├────────────────────────────────────────────────────────────────────────────────────────┤
│ Traditional Static IAM:                                                                │
│ Agent Identity: "SupportAgent" ──► Has Scope "stripe:refund"? ──► YES ──► EXECUTED!     │
│ [DISASTER]: Prompt Injection instructs agent to refund $80,000 to an attacker account. │
│                                                                                        │
│ Chronicle Autonomous Action Control Plane (AACT):                                      │
│ Agent Tool Call ──► Trapped at MCP Layer ──► Normalized to ActionRequest                │
│    │                                                                                   │
│    ├── 1. Verify Active Quarantine / Global Kill Switch              [0.01 ms]         │
│    ├── 2. Verify Cryptographic Delegation Chain to Human Sponsor     [0.08 ms]         │
│    ├── 3. Enforce Monotonic Privilege Narrowing Invariant            [0.05 ms]         │
│    ├── 4. Verify Declared Task Intent & Detect Scope Drift           [0.02 ms]         │
│    ├── 5. Execute Stateful Sequence Automaton (Anti-Exfiltration)    [0.12 ms]         │
│    ├── 6. Compute Sliding-Window Velocity (Anti-Smurfing Structuring)[0.06 ms]         │
│    ├── 7. Calculate Multi-Factor Risk Tensor                         [0.03 ms]         │
│    ├── 8. Determine Action Gate: ALLOW / HOLD / DENY                 [0.01 ms]         │
│    ├── 9. Emit Signed Single-Use RFC-8785 Ephemeral Grant            [0.09 ms]         │
│    └── 10. Commit Cryptographic Merkle Block to Append-Only Ledger   [0.11 ms]         │
│                                                                                        │
│ Result: Execution permitted only with single-use nonce-bound cryptographic proof!      │
│ Total Decision Latency: 0.71 - 1.34 ms (747 - 1,307 decisions/sec). Zero LLMs in loop.│
└────────────────────────────────────────────────────────────────────────────────────────┘
```

### The Chronicle Paradigm Shift

Chronicle decouples **Intent Generation** (the non-deterministic LLM) from **Execution Capability** (the enterprise side-effect tool):

1. **No Direct Tool Credentials**: Autonomous AI agents never hold direct API keys, database credentials, or cloud secrets.
2. **Deterministic Interception**: Every proposed action is intercepted at the Model Context Protocol (MCP) or SDK layer and evaluated deterministically in sub-millisecond time.
3. **Cryptographic Proof Tokens**: Protected downstream tools execute side effects *only* upon presentation of a freshly signed, single-use, canonical hash-bound `AuthorizationGrant` signed by the Chronicle Control Plane.
4. **Zero AI in the Ring 1 Blocking Loop**: Authorization rules, invariants, and sequence automata are purely deterministic mathematical algorithms. No probabilistic LLM decides whether an action is authorized.

---

## 2. The 4-Tier Zero-Trust Ring Model

Inspired by CPU hardware protection rings (Ring 0 through Ring 3), Chronicle establishes the **Autonomous Execution Ring Model**:

```
 ═══════════════════════════════════════════════════════════════════════════════
  RING 0: Hardware Root of Trust & Human Sponsors
  • Hardware Security Modules (HSM) / Cloud KMS Ed25519 Root Keypairs
  • Authenticated Human Sponsors (CISO, VP Engineering, Financial Controllers)
  • Root Delegation Envelopes (Ceilings, Lifetimes, Permissible Tools & Resources)
 ───────────────────────────────────────────────────────────────────────────────
       │ Issues Signed Delegation Envelopes (Monotonic Lattice Root D_0)
       ▼
  RING 1: Chronicle AACT Kernel & Cryptographic Ledger
  • Monotonic Narrowing Lattice Verifier (D_c ⊑ D_p)
  • Stateful Sequence Invariant Automaton (Deterministic Finite Automata)
  • Anti-Smurfing Rolling Cumulative Velocity Engine & Runaway Loop Breaker
  • Formal Business Workflow State Machine & Business Invariant Gate
  • Ephemeral Grant Signer (RFC 8032 Ed25519, 60s TTL, Nonce, JCS Hash)
  • Append-Only Merkle Hash Chain (RFC 6962 Tamper-Evident Ledger)
 ───────────────────────────────────────────────────────────────────────────────
       │ Emits Single-Use Cryptographically Signed Authorization Grants
       ▼
  RING 2: Security Gateways & Proxy Interceptors
  • Model Context Protocol (MCP) Reverse Proxy Gateway (:3001)
  • RFC 8785 Canonical JSON Parameter Canonicalizer & Anti-TOCTOU Verifier
  • Client SDK Local Grant Verification Kernel (@chronicle/sdk)
 ───────────────────────────────────────────────────────────────────────────────
       │ Proxies Authenticated Execution with X-Chronicle-Grant Header
       ▼
  RING 3: Untrusted Autonomous Agents & Downstream Tools
  • LLM Autonomous Reasoning Cores (Claude 3.7, GPT-4o, Gemini 2.5, DeepSeek)
  • Dynamic Sub-Agent Swarms & Delegated Worker Threads
  • Protected Enterprise Tools (Stripe, SWIFT, AWS IAM, Kubernetes, PostgreSQL)
 ═══════════════════════════════════════════════════════════════════════════════
```

---

## 3. High-Level System Topology

```mermaid
flowchart TB
    subgraph Ring0["Ring 0: Human Authority & Cryptographic Root"]
        HS["Human Sponsor<br/>(CISO / Controller)"]
        HSM["Hardware Root of Trust<br/>(Ed25519 Signing Keys)"]
    end

    subgraph Ring3A["Ring 3: Untrusted AI Agent Mesh"]
        LLM["Autonomous LLM Agent<br/>(Claude / GPT-4 / Gemini)"]
        SWARM["Delegated Sub-Agent Swarm<br/>(Worker 1 ... Worker N)"]
    end

    subgraph Ring2["Ring 2: Interception Gateways"]
        MCP["Model Context Protocol Gateway<br/>(:3001 /mcp)"]
        SDK["Chronicle Developer SDK<br/>(@chronicle/sdk)"]
    end

    subgraph Ring1["Ring 1: Chronicle AACT Kernel (:3000)"]
        direction TB
        AUTH["Authorization Pipeline<br/>(Multi-Vector Gate)"]
        LAT["Lattice Narrowing Verifier"]
        SEQ["Stateful DFA Automaton"]
        SMURF["Anti-Smurfing Velocity Engine"]
        WORKFLOW["Business Invariant Engine"]
        BEHAVIOR["Statistical Baselining (Z-Score)"]
        OBS["Observation / Enforcement Switcher"]
        SIGNER["RFC 8032 Ed25519 Signer"]
        LEDGER["RFC 6962 Merkle Hash Ledger"]
    end

    subgraph Ring3B["Ring 3: Protected Enterprise Endpoints (:3002)"]
        TOOL1["Stripe Financial Gateway"]
        TOOL2["PostgreSQL Core Database"]
        TOOL3["Kubernetes Cluster Admin API"]
        TOOL4["SendGrid / Internal Slack"]
    end

    subgraph Storage["Distributed Persistence Tier"]
        PG[(PostgreSQL Database<br/>Tables & Audits)]
        REDIS[(Redis Hot Cache<br/>Delegation & Nonces)]
    end

    HS -->|Issues Root Delegation| AUTH
    HSM -.->|Protects Private Keys| SIGNER
    LLM -->|tools/call via JSON-RPC| MCP
    SWARM -->|Delegate Task| MCP
    MCP -->|Canonical JCS ActionRequest| AUTH
    SDK -->|Direct Ingestion| AUTH

    AUTH --> LAT
    AUTH --> SEQ
    AUTH --> SMURF
    AUTH --> WORKFLOW
    AUTH --> BEHAVIOR
    AUTH --> OBS
    AUTH --> SIGNER
    AUTH --> LEDGER

    LEDGER --> PG
    AUTH <--> REDIS

    SIGNER -->|X-Chronicle-Grant| MCP
    MCP -->|Forward Call + Grant Token| TOOL1
    MCP -->|Forward Call + Grant Token| TOOL2
    MCP -->|Forward Call + Grant Token| TOOL3
    MCP -->|Forward Call + Grant Token| TOOL4

    TOOL1 -->|Verify Grant Signature & Hash| TOOL1
    TOOL2 -->|Verify Grant Signature & Hash| TOOL2
```

---

## 4. End-to-End Zero-Trust Runtime Lifecycle

```mermaid
sequenceDiagram
    autonumber
    actor Sponsor as Human Sponsor (Finance VP)
    participant Agent as Autonomous AI Agent
    participant Gateway as Chronicle MCP Gateway (:3001)
    participant Kernel as Chronicle Control Plane (:3000)
    participant Invariants as Sequence & Invariant Engines
    participant Ledger as Merkle Audit Ledger
    participant Tool as Protected Tool (Stripe API :3002)

    Note over Sponsor,Kernel: Step 1: Human Delegation Enrollment (Ring 0)
    Sponsor->>Kernel: Issue Root Delegation Envelope D_0 (Max: $1,000, Tools: ['stripe_refund'], TTL: 8h)
    Kernel->>Kernel: Register in Monotonic Delegation Tree

    Note over Agent,Gateway: Step 2: Agent Dispatches Tool Call (Ring 3 -> Ring 2)
    Agent->>Gateway: JSON-RPC 2.0 tools/call { name: "stripe_refund", arguments: { amount: 450, id: "ch_1" } }
    Gateway->>Gateway: Canonicalize Parameters via RFC 8785 JCS
    Gateway->>Gateway: Compute SHA-256 Digest: sha256:7f83b165...
    Gateway->>Kernel: POST /api/v1/authorize (ActionRequest + Canonical Hash)

    Note over Kernel,Invariants: Step 3: Zero-Trust Multi-Vector Evaluation (Ring 1)
    Kernel->>Kernel: Check Emergency Quarantine & Global Kill-Switch
    Kernel->>Kernel: Verify Monotonic Lattice Narrowing (D_c ⊑ D_p)
    Kernel->>Kernel: Verify Declared Task Intent & Detect Drift
    Kernel->>Invariants: Check Stateful Sequence DFA (Anti-Exfiltration)
    Invariants-->>Kernel: DFA State: OK (No forbidden sequence)
    Kernel->>Invariants: Calculate Rolling Velocity (Anti-Smurfing Structuring)
    Invariants-->>Kernel: Cumulative: $450 <= Ceiling: $1,000 (Pass)
    Kernel->>Kernel: Compute Multi-Factor Risk Score (24/100 -> LOW_RISK)

    Note over Kernel,Ledger: Step 4: Ephemeral Grant Issuance & Ledger Commit
    Kernel->>Kernel: Generate Nonce & Issue AuthorizationGrant (TTL: 60s)
    Kernel->>Kernel: Sign Grant with Ed25519 Control Plane Private Key
    Kernel->>Ledger: Append Receipt Block #i: H_i = SHA256(H_{i-1} || ReceiptData)
    Ledger-->>Kernel: Receipt Committed (Merkle Root Updated)
    Kernel-->>Gateway: 200 OK: Decision = ALLOW, Grant = "eyJhbGciOiJFZDI1NTE5..."

    Note over Gateway,Tool: Step 5: Downstream Anti-TOCTOU Execution
    Gateway->>Tool: POST /tools/stripe_refund with Header X-Chronicle-Grant
    Tool->>Tool: Verify Ed25519 Signature against Kernel Public Key
    Tool->>Tool: Recompute Parameter Hash from HTTP Body
    Tool->>Tool: Assert Recomputed Hash == Grant.parametersHash (Anti-TOCTOU)
    Tool->>Tool: Execute Native Refund ($450)
    Tool-->>Gateway: 200 OK: { status: "refunded", txId: "tx_9921" }
    Gateway-->>Agent: JSON-RPC Result: "Refund of $450 processed successfully."
```

---

## 5. Mathematical Foundations & Security Invariants

### 5.1 Lattice-Theoretic Monotonic Privilege Narrowing

Every sub-agent spawned in an autonomous swarm is bound by a **formal mathematical security lattice** $(\mathcal{L}, \sqsubseteq)$:

$$\mathcal{L} = \langle \mathcal{D}, \sqsubseteq, \sqcap, \sqcup, \top, \bot \rangle$$

Where each delegation envelope $D \in \mathcal{D}$ is defined as a 5-tuple:

$$D = \langle \mathcal{T}, \mathcal{R}, \mathcal{M}_{\text{tx}}, \mathcal{M}_{\text{cumul}}, \mathcal{I}_{\text{valid}} \rangle$$

- $\mathcal{T} \subseteq \Sigma_{\text{tools}}$: Finite set of permitted tool names.
- $\mathcal{R} \subseteq \Sigma_{\text{resources}}$: Finite set of resource path glob patterns.
- $\mathcal{M}_{\text{tx}} \in \mathbb{R}^+$: Maximum financial ceiling for any single transaction.
- $\mathcal{M}_{\text{cumul}} \in \mathbb{R}^+$: Cumulative financial ceiling across the entire task lifetime.
- $\mathcal{I}_{\text{valid}} = [t_{\text{start}}, t_{\text{end}}]$: Absolute temporal validity window.

```mermaid
graph TD
    classDef root fill:#064e3b,stroke:#10b981,stroke-width:2px,color:#fff;
    classDef child fill:#082f49,stroke:#0ea5e9,stroke-width:2px,color:#fff;
    classDef denied fill:#450a0a,stroke:#ef4444,stroke-width:2px,color:#fff;

    D0["Root Delegation D_0 (Human Sponsor)<br/>Tools: [search, refund, email]<br/>MaxTx: $1,000 | Cumul: $10,000 | TTL: 8h"]:::root

    D1["Child Delegation D_1 (Support Lead)<br/>Tools: [search, refund]<br/>MaxTx: $500 | Cumul: $5,000 | TTL: 4h<br/>✓ D_1 ⊑ D_0 (VALID NARROWING)"]:::child

    D2["Worker Delegation D_2 (Refund Worker)<br/>Tools: [refund]<br/>MaxTx: $200 | Cumul: $1,000 | TTL: 1h<br/>✓ D_2 ⊑ D_1 (VALID NARROWING)"]:::child

    D3["Adversarial Escalation D_3 (Malicious Child)<br/>Tools: [refund, wire_transfer]<br/>MaxTx: $50,000 | TTL: 24h<br/>✗ D_3 ⋢ D_1: ESCALATION BLOCKED"]:::denied

    D0 --> D1
    D1 --> D2
    D1 -.->|REJECTED BY LATTICE| D3
```

#### The Monotonic Invariant Theorem
For child delegation $D_c$ derived from parent delegation $D_p$, monotonic narrowing $D_c \sqsubseteq D_p$ holds if and only if all five invariant criteria are met:

$$D_c \sqsubseteq D_p \iff \begin{cases}
\mathcal{T}_c \subseteq \mathcal{T}_p & \text{(Tool set must be a strict subset)} \\
\mathcal{R}_c \subseteq \mathcal{R}_p & \text{(Resource patterns must be a subset)} \\
\mathcal{M}_{\text{tx}, c} \le \mathcal{M}_{\text{tx}, p} & \text{(Per-action ceiling must not exceed parent)} \\
\mathcal{M}_{\text{cumul}, c} \le \mathcal{M}_{\text{cumul}, p} & \text{(Cumulative ceiling must not exceed parent)} \\
t_{\text{start}, c} \ge t_{\text{start}, p} \;\wedge\; t_{\text{end}, c} \le t_{\text{end}, p} & \text{(Lifetime must be fully enclosed within parent window)}
\end{cases}$$

#### Chain Monotonicity Proof
For any delegation chain of arbitrary depth $k$ rooted at Human Sponsor $A_0$:

$$\forall t \in \mathcal{I}_{\text{valid}}, \quad \text{Privileges}(A_k, t) \subseteq \text{Privileges}(A_{k-1}, t) \subseteq \dots \subseteq \text{Privileges}(A_0, t)$$

---

### 5.2 Anti-TOCTOU Canonical Parameter Hashing (RFC 8785)

```mermaid
flowchart LR
    A["Raw Agent JSON Parameters<br/>{ 'b': 2, 'a': 1 }"] --> B["RFC 8785 JSON Canonicalization<br/>Deterministic: {'a':1,'b':2}"]
    B --> C["SHA-256 Digest<br/>sha256:4b227777d4dd1fc..."]
    C --> D["Ed25519 Grant Signer<br/>Sign(PrivKey, Digest || Nonce || ActionId)"]
    D --> E["Downstream Tool / Microservice<br/>(Receives Grant + HTTP Body)"]
    E --> F{"Recomputed Hash ==<br/>Grant.parametersHash?"}
    F -->|MATCH: Cryptographically Bound| G["PERMIT EXECUTION"]
    F -->|MISMATCH: Modified in Transit| H["ABORT: PARAMETERS_TAMPERED"]
```

Chronicle enforces deterministic parameter canonicalization:

$$h_{\text{params}} = \text{"sha256:"} \parallel \text{Hex}\Big(\text{SHA-256}\big(\text{JCS}(P)\big)\Big)$$

Downstream enterprise microservices recompute $h_{\text{params}}$ directly from the received HTTP body. If a single character or parameter key order is altered, verification fails immediately with `PARAMETERS_TAMPERED`.

---

### 5.3 Stateful Sequence Automata & Cross-Tool Exfiltration DFA

```mermaid
stateDiagram-v2
    [*] --> S0_Clean: Session Initialized

    S0_Clean --> S1_PII_Contaminated: read_customer_pii
    S0_Clean --> S0_Clean: search_catalog

    state "S1: PII Contaminated State" as S1_PII_Contaminated {
        note right of S1_PII_Contaminated
            Context tainted with Sensitive PII.
            Outbound transmission tools are armed with tripwires.
        end note
        S1_PII_Contaminated --> S1_PII_Contaminated: calculate_discount
    }

    S1_PII_Contaminated --> Trap_Exfiltration: Attempt send_external_email
    S1_PII_Contaminated --> Trap_Exfiltration: Attempt post_slack_webhook
    S1_PII_Contaminated --> Trap_Exfiltration: Attempt s3_bulk_export

    state "S2: Security Violation Trapped" as Trap_Exfiltration {
        note left of Trap_Exfiltration
            Tripwire Triggered!
            Action DENIED (FORBIDDEN_SEQUENCE)
            Risk Score = 95
            Agent Auto-Quarantined
        end note
    }

    Trap_Exfiltration --> [*]: Incident Emitted to Merkle Ledger
```

Chronicle evaluates the sequence state of the session before approving an action. When a forbidden sequence is attempted, the state automaton transitions to a trap state and returns `FORBIDDEN_SEQUENCE`.

---

### 5.4 Sliding-Window Cumulative Velocity & Structuring Defense

To defeat structuring attacks ("smurfing"), Chronicle computes cumulative velocity across a rolling temporal window $W$:

$$\mathcal{S}_{\text{cumul}}(t_{\text{now}}, W) = \sum_{a \in \mathcal{H}_{\text{task}}} \Big\{ a.\text{parameters}.\text{amount} \;\Big|\; a.\text{decision} = \text{"ALLOW"} \;\wedge\; (t_{\text{now}} - a.\text{timestamp}) \le W \Big\}$$

$$\text{If } \Big(\mathcal{S}_{\text{cumul}}(t_{\text{now}}, W) + \text{current}.\text{amount}\Big) > D.\text{constraints}.\text{cumulativeValueLimit} \implies \mathbf{DENY}(\text{CUMULATIVE-LIMIT-EXCEEDED})$$

---

### 5.5 Runaway Agent Loop Circuit Breaker

When an LLM enters an infinite tool loop, Chronicle's invocation counter trips a circuit breaker over a 15-second window:

$$\text{Count}\Big( a_i \mid a_i.\text{tool} = \text{tool}_{\text{curr}} \;\wedge\; a_i.\text{hash} = \text{hash}_{\text{curr}} \;\wedge\; (t_{\text{now}} - t_i) \le 15\text{s} \Big) \ge 5 \implies \mathbf{DENY}(\text{RUNAWAY-LOOP-DETECTED})$$

---

### 5.6 Multi-Factor Dynamic Risk Scoring Tensor

Chronicle computes a deterministic risk score $\mathcal{R} \in [0, 100]$ using a multi-factor tensor:

$$\mathcal{R} = \min\left(100, \; w_{\text{base}} \cdot B(T) + w_{\text{res}} \cdot S(R) + w_{\text{val}} \cdot V(P) + w_{\text{seq}} \cdot H(S) + w_{\text{anom}} \cdot \mathcal{A}(Z)\right)$$

Where:
- $B(T) \in [0, 100]$: Intrinsic tool risk (e.g. read = 10, refund = 45, wire transfer = 90).
- $S(R) \in [1.0, 2.5]$: Resource sensitivity multiplier (PUBLIC = 1.0, INTERNAL = 1.2, CONFIDENTIAL = 1.8, RESTRICTED = 2.5).
- $V(P) \in [0, 100]$: Parameter value scale ($100 \times \frac{\text{amount}}{\text{ceiling}}$).
- $H(S) \in [0, 40]$: Sequence hazard bonus from the stateful DFA.
- $\mathcal{A}(Z) \in [0, 30]$: Statistical anomaly penalty derived from behavioral $Z$-score.

**Action Gate Mapping**:
- $\mathcal{R} < 40$: **ALLOW** (Signed Ephemeral Grant issued).
- $40 \le \mathcal{R} \le 75$: **HOLD** (Step-Up Human Sponsor review required).
- $\mathcal{R} > 75$: **DENY** (Execution blocked, incident recorded).

---

### 5.7 Streaming Gaussian Anomaly Quantification (Welford's Algorithm)

Chronicle maintains online streaming Gaussian baselines per tool and agent using Welford's algorithm ($O(1)$ time and memory):

$$M_k = M_{k-1} + \frac{x_k - M_{k-1}}{k}, \qquad S_k = S_{k-1} + (x_k - M_{k-1})(x_k - M_k), \qquad \sigma_k = \sqrt{\frac{S_k}{k-1}}$$

$$Z = \frac{x_k - M_k}{\sigma_k}$$

Invocations with $Z > 3.5$ are flagged as extreme behavioral outliers, dynamically elevating the risk tensor.

---

### 5.8 Merkle-Chained Tamper-Evident Ledger & Ed25519 Signatures

```mermaid
flowchart LR
    subgraph Block0["Receipt Block #0 (Genesis)"]
        H0["Hash: sha256:00000000...<br/>Genesis Seed"]
    end

    subgraph Block1["Receipt Block #1"]
        D1["ReceiptData: action_001<br/>Decision: ALLOW | Risk: 12<br/>ParamHash: sha256:7f83..."]
        H1["Hash: SHA256(H_0 || ReceiptData_1)<br/>Signature: Ed25519(H_1)"]
    end

    subgraph Block2["Receipt Block #2"]
        D2["ReceiptData: action_002<br/>Decision: DENY | Risk: 85<br/>Reason: FORBIDDEN_SEQUENCE"]
        H2["Hash: SHA256(H_1 || ReceiptData_2)<br/>Signature: Ed25519(H_2)"]
    end

    H0 --> H1
    D1 --> H1
    H1 --> H2
    D2 --> H2
```

Receipt hash chaining formula:

$$\mathcal{H}_i = \text{"sha256:"} \parallel \text{Hex}\left(\text{SHA-256}\left(\begin{array}{l}
\mathcal{H}_{i-1} \parallel \text{receiptId} \parallel \text{actionId} \parallel \text{tenantId} \parallel \text{agentId} \\
\parallel \text{sponsorId} \parallel \text{decision} \parallel \text{actionType} \parallel \text{resourceId} \\
\parallel \text{policyVersion} \parallel \text{riskScore} \parallel \text{reasonCodes} \parallel \text{parametersHash} \parallel \text{timestamp}
\end{array}\right)\right)$$

$$\text{Signature}_i = \text{Sign}_{\text{Ed25519}}\Big(\mathcal{H}_i, \;\text{PrivKey}_{\text{ControlPlane}}\Big)$$

---

## 6. Deep-Dive Subsystem Specifications

### 6.1 Delegation Engine & Monotonic Narrowing (`packages/delegation-manager`)
- **Monotonic Narrowing Validator**: Recursively checks that every child delegation strictly shrinks or maintains the parent's permissions.
- **Cascading Revocation**: When a human sponsor or security officer revokes delegation $D_i$, a Breadth-First Search (BFS) traverses the delegation hierarchy and instantly revokes all descendant delegations ($D_{i+1} \dots D_{i+n}$).
- **Intent Drift Guard**: Compares the declared task purpose with the requested tool to prevent unauthorized scope creep.

### 6.2 Cryptographic Primitives & Grant Issuance (`packages/crypto-primitives`)
- **Ed25519 Signatures**: Uses RFC 8032 curve keys with high-performance cryptographic operations (10,400+ signs/sec).
- **RFC 8785 JCS Engine**: Canonicalizes arbitrary JSON objects by sorting keys lexicographically and normalizing number encodings.
- **Merkle Ledger Integrity**: Traverses receipt blocks and recomputes the hash chain to mathematically prove that no historical records have been inserted, omitted, or altered.

### 6.3 Sequence Detector & Invariant Engine (`packages/sequence-detector`)
- **Deterministic Finite Automaton (DFA)**: Tracks the active security state of every agent session.
- **Prerequisite Enforcement**: Mandates that high-impact actions (e.g. `execute_wire_transfer`) cannot execute unless prerequisite verification actions (e.g. `verify_identity`, `dual_approval`) have occurred in the exact same session.
- **Exfiltration Tripwires**: Enforces immediate isolation if sensitive data reading is followed by outbound transmission tools.

### 6.4 Formal Workflow Engine & State Machine (`packages/workflow-engine`)
- **State-Aware Action Gates**: Links authorization to entity lifecycles (`DRAFT`, `PENDING_APPROVAL`, `APPROVED`, `EXECUTED`).
- **Deterministic Business Invariants**:
  - *Conservation of Value*: Refund amounts cannot exceed original payment minus prior refunds.
  - *Idempotency*: Prevents duplicate side-effect execution using unique transaction identifiers.
  - *Separation of Duties*: The creator of an invoice cannot be the approver of the invoice.

### 6.5 Behavioral Profiling Engine (`packages/behavior-engine`)
- **Streaming Baselines**: Computes statistical parameters per tool using streaming algorithms with $O(1)$ space complexity.
- **Z-Score Anomaly Detection**: Quantifies deviation from typical transaction values.
- **Entropy Scoring**: Flags sudden changes in tool invocation variety compared to baseline profiles.

### 6.6 Declarative Policy DSL & Shadow Comparator (`packages/policy-dsl`)
- **Human-Readable Policy Syntax**: Clean, intuitive security policy declarations.
- **Boolean Operators**: Native support for `AND`, `OR`, and `NOT` clauses with Disjunctive Normal Form evaluation.
- **Shadow Policy Comparator**: Replays proposed policy updates against hundreds of thousands of historical audit receipts to calculate concordance rates and detect unintended privilege expansions before deployment.

### 6.7 Observation Mode & Shadow Telemetry (`packages/observation`)
- **Dual Operating Modes**: Switchable at runtime via API or CLI.
- **Zero-Disruption Auditing**: In Observation Mode, violations are transformed to `ALLOW` for safe integration testing while generating full shadow decision logs and Prometheus metrics.

### 6.8 AI Policy Assistant & NLP Synthesis (`packages/ai`)
- **Natural Language Translation**: Synthesizes formal declarative PolicyASTs from plain-English security requirements.
- **Plain-English Explanations**: Generates human-readable explanations of complex authorization decisions for auditors.
- **Mandatory Safety Gates (§61)**: Validates synthesized policies to block dangerous wildcards (`*`) and unconstrained amounts.

### 6.9 Topological Blast Radius & Lateral Movement Engine (`packages/blast-radius`)
- **Reachability Analysis**: Computes the complete set of tools, resources, and systems an agent could compromise.
- **Worst-Case Financial Exposure**: Calculates the maximum financial liability bounded by the delegation envelope.
- **Lateral Movement Percolation (`computeAttackPaths`)**: Uses graph traversal algorithms to trace multi-hop lateral movement pathways.

### 6.10 Merkle Audit Ledger & Provenance DAG (`packages/audit-ledger`)
- **Tamper-Evident Receipts**: Commits every evaluated action to a cryptographically sealed Merkle chain.
- **Provenance Directed Acyclic Graph (DAG)**: Constructs a complete causal lineage graph tracing actions back to delegations, tasks, and human sponsors.

### 6.11 Enterprise Identity & OIDC Federation Bridge (`packages/integrations`)
- **Enterprise IDP Federation**: Bridges Microsoft Entra ID (Azure AD), Okta, and Google Workspace into Chronicle.
- **Cryptographic Trust Boundary**: Validates enterprise RS256 JWTs and maps claims to `HumanSponsor` records while keeping internal agent authorization bound to Ed25519 keypairs.

### 6.12 Distributed Persistence Adapter & Database Migrations (`packages/persistence`)
- **Dual-Mode Persistence**: Seamlessly switches between in-memory collections (for sub-millisecond edge testing) and PostgreSQL storage.
- **Relational Schema Migrations**:
  - `001_initial_schema.sql`: Core tables for tenants, agents, delegations, grants, receipts, and audit logs.
  - `002_behavior_and_workflow.sql`: Tables for behavior profiles, workflow instances, business invariants, and shadow runs.
- **Redis Hot Cache**: Caches hot delegations and active session states for fast lookup.

### 6.13 Developer Client SDK & Grant Verification Kernel (`packages/sdk`)
- **Anti-TOCTOU Verification**: Provides microservice middlewares to verify incoming `X-Chronicle-Grant` tokens locally before executing tool logic.
- **Zero External Network Overhead**: Recomputes canonical parameter hashes and verifies Ed25519 signatures in under 100 microseconds.

---

## 7. Application Tier Overview

### 7.1 Central Control Plane Server (:3000)
- Exposes 14 REST endpoints for authorization decisions, delegation management, agent quarantine, and audit verification.
- Houses the zero-trust evaluation pipeline and Merkle ledger commit logic.
- Serves the Enterprise Cybersecurity Web Console on `http://localhost:3000/`.

### 7.2 Model Context Protocol (MCP) Security Gateway (:3001)
- Reverse proxy implementing JSON-RPC 2.0 protocol translation for the Model Context Protocol (MCP).
- Intercepts agent `tools/call` invocations, canonicalizes arguments, queries the Control Plane, and forwards permitted calls with cryptographic grant headers.

### 7.3 Unified Command-Line Interface (`aact`)
- 15 operational subcommands for security administrators, DevOps engineers, and security analysts.
- Inspects system status, toggles operating modes, verifies Merkle chains, and manages agent quarantines.

### 7.4 Enterprise Cybersecurity Web Console
- 7 comprehensive panels providing live visibility into agent actions, step-up approvals, policy management, shadow comparisons, behavioral analytics, agent registries, and the cryptographic provenance DAG.

---

## 8. Complete Monorepo Workspace Structure

```text
d:\CHRONICLE/
├── packages/
│   ├── core-types/              # Domain models, enums, receipts, provenance schemas
│   ├── crypto-primitives/       # Ed25519 keygen/sign/verify, Canonical JCS (RFC 8785), Merkle verifier
│   ├── delegation-manager/      # Monotonic narrowing validation, cascading revocation, chain verification
│   ├── sequence-detector/       # Stateful sequence automaton, prerequisite DFA, rolling smurfing defense
│   ├── policy-engine/           # Dynamic risk scoring, Step-Up HOLD, counterfactual policy simulator
│   ├── workflow-engine/         # Formal state machine, event-aware transitions, business invariants
│   ├── behavior-engine/         # Streaming Gaussian baselines, Z-score anomaly quantification
│   ├── policy-dsl/              # Declarative Policy DSL parser, evaluator, and ShadowPolicyComparator
│   ├── observation/             # Observation vs Enforcement mode engine with shadow telemetry
│   ├── ai/                      # AI Policy Assistant: NLP synthesis, plain-English explanations
│   ├── persistence/             # Distributed PersistenceAdapter (memory + PostgreSQL) and Redis caching
│   ├── integrations/            # Enterprise OIDC Identity Federation Bridge (Entra, Okta, Google)
│   ├── audit-ledger/            # Append-only Merkle receipt ledger and provenance DAG builder
│   ├── blast-radius/            # Reachability graph, financial exposure, and attack path percolation
│   └── sdk/                     # Developer Client SDK with local anti-TOCTOU grant verification
├── apps/
│   ├── control-plane/           # Central AACT HTTP Server, 14 REST endpoints, and Web Dashboard (:3000)
│   ├── cli/                     # Unified CLI tool (`aact`) with 15 commands
│   ├── mcp-gateway/             # Model Context Protocol Proxy on :3001
│   └── mock-enterprise-tools/   # Realistic enterprise backend services on :3002
├── database/
│   └── migrations/
│       ├── 001_initial_schema.sql           # Core tables, delegations, grants, receipts, indexes
│       └── 002_behavior_and_workflow.sql   # Behavior profiles, workflows, invariants, shadow runs
├── tests/
│   ├── run_tests.ts                         # 22 Core integration & unit tests
│   ├── test_workflow_engine.ts              # 14 Workflow state machine & invariant tests
│   ├── test_behavior_engine.ts              # 13 Statistical behavioral baseline tests
│   ├── test_policy_dsl.ts                   # 27 Policy DSL, OR/NOT, & Shadow Comparator tests
│   ├── test_persistence_and_events.ts       # 33 Schema, Persistence, OIDC, & Observation tests
│   ├── test_cli_and_sdk.ts                  # 13 Unified CLI & Client SDK tests
│   ├── test_ai_assistant.ts                 # 14 AI Policy Assistant NLP tests
│   └── attack-scenarios/attack_suite.ts     # 14 Adversarial attack simulation tests
├── benchmarks/
│   └── benchmark.ts                         # Latency distribution and cryptographic throughput benchmark
├── .github/
│   ├── pull_request_template.md             # Formal PR checklist asserting architectural invariants
│   └── ISSUE_TEMPLATE/
│       ├── feature_request.md               # RFC & feature proposal template
│       └── bug_report.md                    # Structured defect report template
├── CONTRIBUTING.md                          # Open source contribution guide & community RFCs
├── package.json                             # Monorepo workspaces & modular test scripts
├── tsconfig.json                            # TypeScript ES2022 NodeNext configuration
└── README.md                                # Complete technical architecture specification
```

---

## 9. Complete REST API Reference

The Chronicle Control Plane exposes 14 REST endpoints on `http://localhost:3000`:

| Method | Endpoint | Description | Request Body Key Fields |
|:---:|---|---|---|
| `POST` | `/api/v1/authorize` | Core authorization decision & grant issuance | `{ actionId, agentId, tool, parameters, context }` |
| `GET` | `/api/v1/mode` | Query current operating mode | `None` |
| `POST` | `/api/v1/mode` | Switch mode (`ENFORCEMENT` vs `OBSERVATION`) | `{ mode: "OBSERVATION" \| "ENFORCEMENT" }` |
| `GET` | `/api/v1/telemetry/observation` | Retrieve shadow observation violation telemetry | `None` |
| `GET` | `/api/v1/agents` | List registered agents and risk tiers | `None` |
| `POST` | `/api/v1/agents/quarantine` | Emergency quarantine agent (Kill Switch) | `{ agentId: string, reason: string }` |
| `POST` | `/api/v1/agents/unquarantine` | Lift agent quarantine | `{ agentId: string }` |
| `GET` | `/api/v1/agents/:id/capabilities` | Inspect agent's authorized capabilities | `None` |
| `GET` | `/api/v1/delegations/:id` | Inspect delegation envelope & parent hierarchy | `None` |
| `GET` | `/api/v1/approvals/pending` | List actions currently in Step-Up `HOLD` | `None` |
| `POST` | `/api/v1/approvals/:id/resolve` | Approve or deny a held transaction | `{ resolution: "APPROVED" \| "REJECTED", sponsorId }` |
| `GET` | `/api/v1/blast-radius/:id` | Compute blast radius and max exposure | `None` |
| `GET` | `/api/v1/attack-paths/:id` | Compute topological lateral movement paths | `None` |
| `GET` | `/api/v1/audit/verify` | Verify Merkle audit chain cryptographic integrity | `None` |

---

## 10. Unified CLI Manual (`aact`)

```bash
# 1. System Status & Integrity
npm run aact -- status

# 2. Operating Mode Management
npm run aact -- mode get
npm run aact -- mode set observation
npm run aact -- mode set enforcement

# 3. Agent Lifecycle & Capabilities
npm run aact -- agent list
npm run aact -- agent capabilities agent_finance_refund
npm run aact -- quarantine agent_finance_refund --reason "Anomalous tool spike detected"
npm run aact -- unquarantine agent_finance_refund

# 4. Delegation Envelope Inspection
npm run aact -- delegation inspect del_finance_refund_root

# 5. Blast Radius & Attack Path Analysis
npm run aact -- blast-radius agent_finance_refund
npm run aact -- attack-path agent_finance_refund

# 6. Policy Testing & Counterfactual Simulation
npm run aact -- policy test
npm run aact -- policy simulate

# 7. Decision Explanation & Audit Ledger Verification
npm run aact -- action explain act_refund_001
npm run aact -- audit verify
```

---

## 11. Adversarial Attack Neutralization Matrix (14/14 Verified)

Chronicle includes a dedicated adversarial attack test harness ([`tests/attack-scenarios/attack_suite.ts`](file:///d:/CHRONICLE/tests/attack-scenarios/attack_suite.ts)). All 14 attack vectors are tested and neutralized:

| # | Attack Vector Name | Threat Scenario | Chronicle Defense Mechanism | Cryptographic / Systemic Evidence | Status |
|:---:|---|---|---|---|:---:|
| **1** | **Parameter Tampering (TOCTOU)** | Agent alters amount from $100 to $10,000 post-check | RFC 8785 Canonical Hash Parameter Binding | `Cryptographic grant rejected: PARAMETERS_TAMPERED: hash mismatch` | **NEUTRALIZED** |
| **2** | **Expired Grant Replay** | Replaying valid grant after TTL expires | Microsecond Ephemeral Grant TTL Verification | `Cryptographic grant rejected: GRANT_EXPIRED` | **NEUTRALIZED** |
| **3** | **Prompt Injection Intent Drift** | LLM persuaded to invoke wire transfer | Declared Delegation Intent Boundary Enforcement | `Tool 'send_wire_transfer' not authorized by delegation envelope` | **NEUTRALIZED** |
| **4** | **Cross-Tool Exfiltration** | PII Read followed immediately by External Email | Stateful Action Sequence DFA Automaton | `Forbidden sequence detected: [read_pii -> send_external_email]` | **NEUTRALIZED** |
| **5** | **Monotonic Privilege Escalation** | Sub-agent requests privileges greater than parent | Mathematical Monotonic Lattice Verifier ($D_c \sqsubseteq D_p$) | `Monotonic narrowing violation: child requests unauthorized tool` | **NEUTRALIZED** |
| **6** | **Smurfing / Structuring Attack** | 20 small transactions to evade $1,000 threshold | Rolling-Window Cumulative Velocity Engine | `Cumulative transaction sum ($10,850) exceeds cumulative limit` | **NEUTRALIZED** |
| **7** | **Emergency Agent Quarantine** | Rogue agent active; kill-switch activated | Zero-Latency Blast Radius Quarantine Gate | `Agent 'agent_finance_refund' is under active security quarantine` | **NEUTRALIZED** |
| **8** | **Stale Delegation Reuse** | Invoking tools using expired delegation envelope | Clock-Aware Temporal Validity Window ($[t_{\text{start}}, t_{\text{end}}]$) | `Delegation expired at 2026-09-10T08:05:39.148Z` | **NEUTRALIZED** |
| **9** | **Cross-Tenant Impersonation** | Agent in Tenant A attempts action in Tenant B | Cryptographic Multi-Tenant Isolation Boundary | `Cross-tenant violation: delegation tenant does not match request` | **NEUTRALIZED** |
| **10** | **Cross-Task Cumulative Abuse** | Agent switches tasks to reset cumulative limits | Global Per-Delegation Lifetime Spend Tracking | `Cross-task cumulative limit ($10,450 > $10,000) strictly blocked` | **NEUTRALIZED** |
| **11** | **Consumed Nonce Double-Spend** | Replaying consumed single-use grant token | Nonce Consumption Cache & Single-Use Enforcement | `Grant replay blocked: nonce already consumed` | **NEUTRALIZED** |
| **12** | **Resource Traversal Abuse** | Accessing out-of-scope production cluster | Delegation Resource Pattern Glob Boundary | `Resource 'k8s:prod-cluster' does not match patterns: [cust:*]` | **NEUTRALIZED** |
| **13** | **Circular Delegation Abuse** | Agent delegating to parent to create loop | Delegation Hierarchy DAG Lookup Guard | `Circular delegation rejected: Parent delegation not found` | **NEUTRALIZED** |
| **14** | **Runaway Agent Loop Burst** | Degenerate LLM loop firing 15 calls in 5 seconds | Stateful Burst Rate-Limiter & Loop Circuit Breaker | `Tool abuse burst detected: 15 rapid calls in 30s window` | **NEUTRALIZED** |

---

## 12. Empirical Performance & Latency Benchmarks

Performance evaluated on Node.js v24 ([`benchmarks/benchmark.ts`](file:///d:/CHRONICLE/benchmarks/benchmark.ts)):

```text
================================================================
       CHRONICLE AACT PERFORMANCE & LATENCY BENCHMARK
================================================================

1. Canonical Parameter Hashing (TOCTOU Defense Engine)
  Iterations:  50,000
  Throughput:  244,976.39 ops/sec
  Avg Latency: 4.08 μs

2. Ed25519 Cryptographic Signing & Verification
  Signatures Created:     5,000
  Signing Throughput:     10,427.90 ops/sec (avg 0.10 ms)
  Signatures Verified:    5,000
  Verify Throughput:      8,846.62 ops/sec (avg 0.11 ms)

3. Full End-to-End AACT Authorization Pipeline
   (Delegation Chain -> Sequence Invariant -> Policy Risk -> Ed25519 Grant -> Merkle Receipt)
  Actions Processed:      2,000
  Total Throughput:       747.17 - 1,307.75 decisions/sec
  Mean Latency:           0.76 - 1.34 ms
  p50 (Median):           0.71 - 1.26 ms
  p90:                    1.10 - 2.29 ms
  p99:                    1.61 - 3.39 ms (Target: < 3.00 ms)

4. Merkle-Chained Ledger Cryptographic Audit Verification
  Receipt Blocks Audited: 2,000 blocks
  Cryptographic Verdict:  VALID (100% Unbroken Merkle Chain)
  Full Audit Duration:    243.13 ms (8,226.03 blocks/sec)

================================================================
 CHRONICLE PERFORMANCE BENCHMARK COMPLETE - ZERO HOTSPOTS DETECTED
================================================================
```

---

## 13. Quickstart & Local Deployment Guide

### Prerequisites
- Node.js `v22.6.0+` or `v24+` (native TypeScript execution via `--experimental-strip-types`)

### 1. Execute Test Matrix (150 Tests / 100% Pass)
```bash
# Core Integration Suite (22/22)
npm test

# Adversarial Attack Simulation Suite (14/14)
npm run test:attacks

# Declarative Policy DSL & Shadow Comparator (27/27)
npm run test:dsl

# Persistence, Migrations, OIDC, & Observation (33/33)
npm run test:persistence

# Formal Workflow State Machine (14/14)
npm run test:workflows

# Statistical Behavioral Baselining (13/13)
npm run test:behavior

# Unified CLI & Client SDK (13/13)
npm run test:cli
```

### 2. Launch Services Locally
```bash
# Start Control Plane Server & Dashboard on port 3000
npm run start:control-plane

# Start MCP Security Gateway on port 3001
npm run start:mcp-gateway

# Start Mock Enterprise Backend Services on port 3002
npm run start:mock-tools
```

Navigate to **`http://localhost:3000/`** to interact with the **Chronicle Enterprise Web Console**.

---

## 14. Production Deployment & Kubernetes Configuration

For production enterprise deployments, Chronicle is packaged as lightweight, multi-stage container images:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: chronicle-control-plane
  namespace: security-kernel
spec:
  replicas: 3
  selector:
    matchLabels:
      app: chronicle-control-plane
  template:
    metadata:
      labels:
        app: chronicle-control-plane
    spec:
      containers:
      - name: control-plane
        image: chronicle/control-plane:1.0.0
        ports:
        - containerPort: 3000
        env:
        - name: NODE_ENV
          value: "production"
        - name: PERSISTENCE_MODE
          value: "postgresql"
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: chronicle-db-credentials
              key: connection-string
        - name: CONTROL_PLANE_PRIVATE_KEY
          valueFrom:
            secretKeyRef:
              name: chronicle-crypto-keys
              key: ed25519-private-key
        resources:
          limits:
            cpu: "2"
            memory: "2Gi"
          requests:
            cpu: "500m"
            memory: "512Mi"
```

---

## 15. Contributing to Chronicle: Community RFCs & Pull Requests

We welcome contributions from systems engineers, cryptographers, AI researchers, and cybersecurity architects!

### High-Priority Contribution Areas (Good First Issues & RFCs)
- [ ] **Hardware Security Modules (HSM)**: Cloud KMS (AWS KMS, GCP Cloud KMS, Azure Key Vault) and PKCS#11 hardware signers for Ring 0 root keys.
- [ ] **eBPF System Call Interceptors**: Kernel-level probes to monitor container processes spawned by local coding agents.
- [ ] **OpenTelemetry Distributed Tracing**: Native OTel trace and span propagation for authorization decisions.
- [ ] **Pre-built MCP Adapters**: Defense profiles for Snowflake, GitHub, GitLab, Salesforce, and Datadog MCP servers.
- [ ] **Wasm Policy Engine**: Compiling declarative DSL policies down to WebAssembly for sub-50-microsecond edge evaluation.

Refer to [`CONTRIBUTING.md`](CONTRIBUTING.md) for full pull request submission guidelines and developer workflows.

---

## 16. Security Vulnerability Disclosure Policy

If you discover a security vulnerability or bypass in Chronicle's zero-trust kernel, please **do not open a public GitHub issue**.

Directly contact our security architecture team:
- **Security Contact**: **Swaraj** ([swaraj@chronicle.security](mailto:swaraj@chronicle.security))
- **Response SLA**: Acknowledgment within 24 hours; patch coordinated within 72 hours.

---

## 17. Frequently Asked Questions (FAQ)

<details>
<summary><b>Why not use standard AWS IAM or OAuth 2.0 scopes?</b></summary>
<br/>
Static scopes answer whether an agent <i>can</i> call a tool, not whether it <i>should</i> call it given current state, cumulative spend, prior actions, and task intent. Chronicle provides real-time behavior-aware, sequence-aware runtime gating that static IAM cannot deliver.
</details>

<details>
<summary><b>Does Chronicle add latency to agent interactions?</b></summary>
<br/>
No. Chronicle evaluates actions in <b>0.71 ms to 1.34 ms</b>. Compared to LLM token generation latencies (500 ms - 4,000 ms), Chronicle's overhead is undetectable.
</details>

<details>
<summary><b>Does Chronicle require an LLM in the authorization loop?</b></summary>
<br/>
No. Chronicle’s Ring 1 authorization gates are purely deterministic mathematical algorithms, lattice checks, DFAs, and cryptographic verifiers. Placing an LLM in the loop would introduce non-determinism, hallucinations, and high latency.
</details>

<details>
<summary><b>How does Chronicle prevent Time-of-Check to Time-of-Use (TOCTOU) attacks?</b></summary>
<br/>
Chronicle uses RFC 8785 JSON Canonicalization Scheme (JCS) to hash parameters deterministically and bind that hash inside an Ed25519-signed ephemeral grant token. Downstream tools recompute the hash from the HTTP body and reject execution if any parameter has been altered.
</details>

---

## 18. License & Attribution

- **Founder & Principal Systems Architect:** **Swaraj**  
- **Project:** Chronicle Autonomous Action Control Plane (AACT)  
- **License:** Apache License 2.0  
- **Core Mission:** *Empower AI agents with meaningful autonomy while mathematically bounding their real-world blast radius.*

<div align="center">
<br/>
<sub>Chronicle AACT is maintained with pride by <b>Swaraj</b> and the open-source cybersecurity community.</sub>
</div>
