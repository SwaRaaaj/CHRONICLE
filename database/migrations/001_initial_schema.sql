-- ====================================================================
-- CHRONICLE AUTONOMOUS ACTION CONTROL PLANE (AACT)
-- Master Relational Database Schema Migration (§71, §73, §74, §78)
-- PostgreSQL 15+ Compatible DDL with Multi-Tenant Isolation & Append-Only Receipts
-- ====================================================================

-- Enable UUID extension for cryptographically strong random IDs
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- --------------------------------------------------------------------
-- 1. Multi-Tenancy & Human Identity Layer (§71, §73)
-- --------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tenants (
    tenant_id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    environment VARCHAR(32) NOT NULL DEFAULT 'production',
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    settings JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS users (
    user_id VARCHAR(64) NOT NULL,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    role VARCHAR(64) NOT NULL,
    department VARCHAR(64) NOT NULL,
    public_key TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, user_id)
);

-- --------------------------------------------------------------------
-- 2. Agent Identity & Lifecycle Layer (§7, §89, §90, §91, §92)
-- --------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS agents (
    agent_id VARCHAR(64) NOT NULL,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    agent_type VARCHAR(64) NOT NULL,
    agent_version VARCHAR(32) NOT NULL,
    model_provider VARCHAR(128) NOT NULL,
    owner_id VARCHAR(64) NOT NULL,
    sponsor_id VARCHAR(64) NOT NULL,
    parent_agent_id VARCHAR(64),
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE', -- REGISTERED, ACTIVE, SUSPENDED, QUARANTINED, REVOKED
    environment VARCHAR(32) NOT NULL DEFAULT 'production',
    risk_class VARCHAR(16) NOT NULL DEFAULT 'MEDIUM',
    allowed_capabilities JSONB NOT NULL DEFAULT '[]',
    public_key TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, agent_id)
);

CREATE TABLE IF NOT EXISTS agent_versions (
    version_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id VARCHAR(64) NOT NULL,
    agent_id VARCHAR(64) NOT NULL,
    version VARCHAR(32) NOT NULL,
    changelog TEXT,
    system_prompt_hash VARCHAR(64),
    deployed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deployed_by VARCHAR(64) NOT NULL
);

-- --------------------------------------------------------------------
-- 3. Delegations & Monotonic Narrowing Hierarchy (§8, §9, §36)
-- --------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS delegations (
    delegation_id VARCHAR(64) NOT NULL,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    parent_delegation_id VARCHAR(64),
    delegator_type VARCHAR(16) NOT NULL, -- 'HUMAN' | 'AGENT'
    delegator_id VARCHAR(64) NOT NULL,
    delegatee_id VARCHAR(64) NOT NULL,
    task_id VARCHAR(64) NOT NULL,
    purpose TEXT NOT NULL,
    allowed_tools JSONB NOT NULL DEFAULT '[]',
    resource_patterns JSONB NOT NULL DEFAULT '[]',
    max_transaction_value NUMERIC(14, 2),
    cumulative_value_limit NUMERIC(14, 2),
    require_approval_above NUMERIC(14, 2),
    not_before TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at TIMESTAMPTZ,
    revoked_reason TEXT,
    signature TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, delegation_id)
);

-- --------------------------------------------------------------------
-- 4. Tasks, Intents & Context (§13, §14, §42)
-- --------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tasks (
    task_id VARCHAR(64) NOT NULL,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    sponsor_id VARCHAR(64) NOT NULL,
    declared_purpose TEXT NOT NULL,
    intended_capabilities JSONB NOT NULL DEFAULT '[]',
    expected_tools JSONB NOT NULL DEFAULT '[]',
    target_customer_id VARCHAR(64),
    target_resource_id VARCHAR(64),
    max_allowed_value NUMERIC(14, 2),
    workflow_state VARCHAR(64) NOT NULL DEFAULT 'INIT',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, task_id)
);

CREATE TABLE IF NOT EXISTS sessions (
    session_id VARCHAR(64) NOT NULL,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    agent_id VARCHAR(64) NOT NULL,
    task_id VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ended_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, session_id)
);

-- --------------------------------------------------------------------
-- 5. Actions, Sequences & Tools Registry (§10, §15, §93, §94)
-- --------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tools (
    tool_id VARCHAR(64) NOT NULL,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    tool_name VARCHAR(64) NOT NULL,
    risk_class VARCHAR(16) NOT NULL DEFAULT 'MEDIUM',
    schema JSONB NOT NULL DEFAULT '{}',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, tool_id)
);

CREATE TABLE IF NOT EXISTS resources (
    resource_id VARCHAR(128) NOT NULL,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    type VARCHAR(64) NOT NULL,
    owner_id VARCHAR(64),
    sensitivity VARCHAR(32) NOT NULL DEFAULT 'INTERNAL',
    environment VARCHAR(32) NOT NULL DEFAULT 'production',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, resource_id)
);

CREATE TABLE IF NOT EXISTS actions (
    action_id VARCHAR(64) NOT NULL,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    session_id VARCHAR(64) NOT NULL,
    task_id VARCHAR(64) NOT NULL,
    agent_id VARCHAR(64) NOT NULL,
    delegation_id VARCHAR(64) NOT NULL,
    action_type VARCHAR(64) NOT NULL,
    tool VARCHAR(64) NOT NULL,
    resource_id VARCHAR(128) NOT NULL,
    parameters JSONB NOT NULL,
    parameters_hash VARCHAR(64) NOT NULL,
    decision VARCHAR(16) NOT NULL, -- ALLOW, DENY, HOLD, ESCALATE
    risk_score INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, action_id)
);

-- --------------------------------------------------------------------
-- 6. Cryptographic Grants & Append-Only Merkle Receipts (§24, §25, §65)
-- --------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS authorization_grants (
    grant_id VARCHAR(64) NOT NULL,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    action_id VARCHAR(64) NOT NULL,
    agent_id VARCHAR(64) NOT NULL,
    tool VARCHAR(64) NOT NULL,
    resource_id VARCHAR(128) NOT NULL,
    parameters_hash VARCHAR(64) NOT NULL,
    delegation_id VARCHAR(64) NOT NULL,
    nonce VARCHAR(64) NOT NULL UNIQUE,
    not_before BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    consumed BOOLEAN NOT NULL DEFAULT FALSE,
    signature TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, grant_id)
);

-- IMMUTABLE APPEND-ONLY RECEIPT LEDGER (§25, §65)
CREATE TABLE IF NOT EXISTS authorization_receipts (
    receipt_id VARCHAR(64) NOT NULL,
    tenant_id VARCHAR(64) NOT NULL,
    block_index BIGSERIAL,
    action_id VARCHAR(64) NOT NULL,
    grant_id VARCHAR(64),
    agent_id VARCHAR(64) NOT NULL,
    sponsor_id VARCHAR(64) NOT NULL,
    decision VARCHAR(16) NOT NULL,
    action_type VARCHAR(64) NOT NULL,
    resource_id VARCHAR(128) NOT NULL,
    policy_version VARCHAR(32) NOT NULL,
    risk_score INTEGER NOT NULL,
    reason_codes JSONB NOT NULL DEFAULT '[]',
    explanation TEXT NOT NULL,
    parameters_hash VARCHAR(64) NOT NULL,
    previous_receipt_hash VARCHAR(71) NOT NULL,
    receipt_hash VARCHAR(71) NOT NULL UNIQUE,
    signature TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, receipt_id)
);

-- --------------------------------------------------------------------
-- 7. Human Approvals & Step-Up Queue (§19, §20, §34, §35)
-- --------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS approvals (
    approval_id VARCHAR(64) NOT NULL,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    action_id VARCHAR(64) NOT NULL,
    agent_id VARCHAR(64) NOT NULL,
    task_id VARCHAR(64) NOT NULL,
    action_type VARCHAR(64) NOT NULL,
    resource_id VARCHAR(128) NOT NULL,
    parameters JSONB NOT NULL,
    risk_score INTEGER NOT NULL,
    required_role VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'PENDING', -- PENDING, APPROVED, REJECTED, EXPIRED
    decided_by VARCHAR(64),
    decided_at TIMESTAMPTZ,
    decision_notes TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, approval_id)
);

-- --------------------------------------------------------------------
-- 8. Workflow State Machines & Business Invariants (§41, §42, §43, §44)
-- --------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS workflow_definitions (
    workflow_id VARCHAR(64) NOT NULL,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    definition JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, workflow_id)
);

CREATE TABLE IF NOT EXISTS workflow_instances (
    instance_id VARCHAR(64) NOT NULL,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    workflow_id VARCHAR(64) NOT NULL,
    task_id VARCHAR(64) NOT NULL,
    current_state VARCHAR(64) NOT NULL,
    history JSONB NOT NULL DEFAULT '[]',
    emitted_events JSONB NOT NULL DEFAULT '[]',
    context_data JSONB NOT NULL DEFAULT '{}',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, instance_id)
);

CREATE TABLE IF NOT EXISTS business_invariants (
    invariant_id VARCHAR(64) NOT NULL,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    target_action_type VARCHAR(64) NOT NULL,
    rule_expression TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, invariant_id)
);

-- --------------------------------------------------------------------
-- 9. Behavioral Baselines & Anomaly Profiles (§17, §18, §31)
-- --------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS behavior_profiles (
    agent_id VARCHAR(64) NOT NULL,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    sample_count INTEGER NOT NULL DEFAULT 0,
    tool_distributions JSONB NOT NULL DEFAULT '{}',
    typical_sequences JSONB NOT NULL DEFAULT '[]',
    typical_operating_hours JSONB NOT NULL DEFAULT '{"startHourUTC": 8, "endHourUTC": 20}',
    last_updated TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, agent_id)
);

-- --------------------------------------------------------------------
-- 10. Audit Events & Idempotent Event Log (§64, §65, §74)
-- --------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_events (
    event_id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    event_type VARCHAR(64) NOT NULL,
    producer VARCHAR(64) NOT NULL,
    correlation_id VARCHAR(64) NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- --------------------------------------------------------------------
-- Performance B-Tree & GIN Indexes (§75)
-- --------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_actions_agent ON actions(tenant_id, agent_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_actions_task ON actions(tenant_id, task_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_receipts_agent ON authorization_receipts(tenant_id, agent_id);
CREATE INDEX IF NOT EXISTS idx_receipts_hash ON authorization_receipts(receipt_hash);
CREATE INDEX IF NOT EXISTS idx_delegations_delegatee ON delegations(tenant_id, delegatee_id);
CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_audit_events_correlation ON audit_events(correlation_id);
