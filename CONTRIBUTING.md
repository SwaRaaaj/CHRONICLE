# Contributing to Chronicle (AACT)

Thank you for your interest in contributing to **Chronicle: Autonomous Action Control Plane (AACT)**! 

Chronicle is an open-source, zero-trust runtime security kernel designed to give AI agents meaningful autonomy while mathematically bounding their real-world blast radius. We welcome contributions from systems engineers, cryptographers, AI researchers, and cybersecurity architects.

---

## Code of Conduct

We are committed to providing a welcoming, inclusive, and harassment-free experience for everyone. Please be respectful, constructive, and collaborative in all discussions, issues, and pull requests.

---

## How to Get Involved

### High-Priority Contribution Areas (RFCs & Good First Issues)

We are actively seeking contributions in the following domains:

1. **Hardware Security Modules (HSM) & KMS Signers**:
   - Cloud KMS (AWS KMS, GCP Cloud KMS, Azure Key Vault).
   - PKCS#11 hardware security module integration for Ring 0 root keys.
2. **eBPF System Call Interceptors**:
   - Kernel-level probes to monitor processes and network sockets spawned by local autonomous coding agents.
3. **OpenTelemetry (OTel) Distributed Tracing**:
   - OTel trace and span exporters for every authorization gate, risk scoring calculation, and Merkle ledger commit.
4. **Pre-configured MCP Tool Adapters**:
   - Zero-trust defense profiles for Model Context Protocol (MCP) servers including Snowflake, GitHub, GitLab, Salesforce, and Datadog.
5. **WebAssembly (Wasm) Policy Evaluation Engine**:
   - Compiling declarative DSL policy ASTs to Wasm for sub-50-microsecond edge proxy evaluation.

---

## Development Setup

### Prerequisites
- **Node.js**: `v22.6.0` or higher (we leverage native `--experimental-strip-types` for fast TypeScript execution without build steps).
- **Git**: Configured with your GPG or SSH signing key.

### Quickstart
```bash
# 1. Clone your fork of the repository
git clone https://github.com/<your-username>/CHRONICLE.git
cd CHRONICLE

# 2. Verify all test suites pass out of the box
npm test
npm run test:attacks
npm run test:dsl
npm run test:persistence
npm run test:workflows
npm run test:behavior
npm run test:cli
```

---

## Pull Request Workflow

We follow standard GitHub Flow:

### 1. Create a Topic Branch
```bash
git checkout -b feat/my-security-enhancement
# or for bug fixes:
git checkout -b fix/lattice-narrowing-edge-case
```

### 2. Follow Core Architectural Principles
When adding or modifying code in Chronicle:
- **Zero LLMs in Synchronous Blocking Path**: The authorization pipeline must remain sub-millisecond, deterministic, and verifiable. Do not introduce probabilistic model calls into Ring 1 gates.
- **RFC Conformance**:
  - RFC 8785: Parameter hashing must use the canonical JSON stringifier (`canonicalJsonStringify`) to prevent TOCTOU hash mismatches.
  - RFC 8032: Cryptographic tokens must be signed using Ed25519 keypairs.
  - RFC 6962: Ledger receipts must be hash-chained into the Merkle structure.
- **Monotonic Narrowing Invariant**: Sub-agent delegations must strictly narrow permissions ($D_c \sqsubseteq D_p$). Never allow a child envelope to expand tools, ceilings, or resource patterns.

### 3. Add Comprehensive Tests
Every new feature, policy operator, or defense mechanism must be accompanied by automated tests:
- Place core integration tests in `tests/`.
- Add adversarial attack simulations in `tests/attack-scenarios/attack_suite.ts`.
- Ensure 100% of existing tests continue to pass.

### 4. Commit Messages (Conventional Commits)
Use clear, semantic commit messages:
- `feat(crypto): add support for Ed25519-ph pre-hashed signatures`
- `fix(dsl): correct precedence for nested NOT operators`
- `docs: update mathematical proof in README`
- `perf(hash): optimize JCS canonicalization throughput`

### 5. Open a Pull Request (PR)
- Push your topic branch to your fork.
- Open a PR against `main` on [`https://github.com/SwaRaaaj/CHRONICLE`](https://github.com/SwaRaaaj/CHRONICLE).
- Complete the PR checklist below in your description.

---

## Pull Request Checklist

When opening a PR, include this checklist in your description:

```markdown
### Description of Changes
<!-- Provide a clear summary of what this PR introduces and why -->

### Related Issue / RFC
<!-- Link to any relevant issue or RFC discussion (e.g. Closes #12) -->

### Checklist
- [ ] My code adheres to the project's architectural invariants (zero-trust, deterministic gates).
- [ ] New and existing automated tests pass locally (`npm test`, `npm run test:attacks`).
- [ ] I have added tests that prove my fix is effective or that my feature works.
- [ ] Documentation / README has been updated if applicable.
- [ ] Any mathematical formulas adhere to KaTeX syntax (no raw underscores in text mode).
```

---

## Security Vulnerability Reporting

If you discover a security vulnerability or bypass in Chronicle's zero-trust kernel, please **do not open a public GitHub issue**. Instead, email our security team directly:

- **Security Contact:** **Swaraj** (reach out via [GitHub Security Advisories](https://github.com/SwaRaaaj/CHRONICLE/security/advisories))
- Please provide a minimal reproducible script demonstrating the bypass. We will acknowledge receipt within 24 hours and coordinate responsible disclosure.

---

## Attribution & Acknowledgments

Chronicle was created and architected by **Swaraj** ([@SwaRaaaj](https://github.com/SwaRaaaj)). We thank all open-source contributors and security researchers helping make autonomous AI safe, predictable, and trustworthy!
