-- ============================================================================
-- CHRONICLE AUTONOMOUS ACTION CONTROL PLANE (AACT)
-- Migration 002: Behavioral Baselines, Workflows, Invariants & Observation Mode
-- Version: 2.0.0
-- Standards: PCI-DSS 4.0, SOC 2 Type II, ISO 27001 (§73, §74)
-- ============================================================================

-- 1. Statistical Behavior Baseline Profiles (§17, §18, §31, §63)
CREATE TABLE IF NOT EXISTS behavior_profiles (
    profile_id VARCHAR(64) PRIMARY KEY,
    agent_id VARCHAR(64) NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    total_observations INT NOT NULL DEFAULT 0,
    tool_distributions JSONB NOT NULL DEFAULT '{}'::jsonb,
    volumetric_distribution JSONB NOT NULL DEFAULT '{}'::jsonb,
    temporal_distribution JSONB NOT NULL DEFAULT '{}'::jsonb,
    error_frequency_rate NUMERIC(5, 4) NOT NULL DEFAULT 0.0000,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_agent_behavior_profile UNIQUE(agent_id, tenant_id)
);

CREATE INDEX IF NOT EXISTS idx_behavior_profiles_tenant_agent ON behavior_profiles(tenant_id, agent_id);

-- 2. Formal Workflow State Machine Definitions (§41, §42, §43, §44)
CREATE TABLE IF NOT EXISTS workflow_definitions (
    workflow_id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    initial_state VARCHAR(64) NOT NULL,
    allowed_states JSONB NOT NULL,
    transitions JSONB NOT NULL,
    prerequisite_events JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_workflow_definitions_tenant ON workflow_definitions(tenant_id);

-- 3. Workflow Instances (Per-task state tracking) (§43)
CREATE TABLE IF NOT EXISTS workflow_instances (
    instance_id VARCHAR(64) PRIMARY KEY,
    workflow_id VARCHAR(64) NOT NULL REFERENCES workflow_definitions(workflow_id) ON DELETE RESTRICT,
    task_id VARCHAR(64) NOT NULL,
    agent_id VARCHAR(64) NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    current_state VARCHAR(64) NOT NULL,
    emitted_events JSONB NOT NULL DEFAULT '[]'::jsonb,
    context_data JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_task_workflow_instance UNIQUE(task_id, workflow_id)
);

CREATE INDEX IF NOT EXISTS idx_workflow_instances_lookup ON workflow_instances(tenant_id, task_id, current_state);

-- 4. Business Invariants (§41)
CREATE TABLE IF NOT EXISTS invariants (
    invariant_id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    target_tools JSONB NOT NULL DEFAULT '["*"]'::jsonb,
    assertion_type VARCHAR(64) NOT NULL, -- 'MAX_VALUE', 'EQUAL', 'NOT_NULL', 'RELATIONAL'
    parameters JSONB NOT NULL DEFAULT '{}'::jsonb,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_invariants_tenant_active ON invariants(tenant_id, active);

-- 5. Policy Shadow Run Results (§29, §30, §51, §52, §61)
CREATE TABLE IF NOT EXISTS policy_shadow_runs (
    run_id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    current_policy_id VARCHAR(64) NOT NULL,
    proposed_policy_id VARCHAR(64) NOT NULL,
    total_actions_evaluated INT NOT NULL,
    concordance_rate NUMERIC(5, 2) NOT NULL,
    divergence_count INT NOT NULL,
    newly_allowed_count INT NOT NULL,
    newly_denied_count INT NOT NULL,
    newly_held_count INT NOT NULL,
    high_risk_expansions INT NOT NULL,
    recommendation VARCHAR(64) NOT NULL, -- 'SAFE_TO_DEPLOY', 'REVIEW_REQUIRED', 'DANGEROUS_EXPANSION'
    divergence_details JSONB NOT NULL DEFAULT '[]'::jsonb,
    executed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_shadow_runs_tenant ON policy_shadow_runs(tenant_id, executed_at DESC);

-- 6. Observation Mode Shadow Events (§3)
CREATE TABLE IF NOT EXISTS observation_events (
    event_id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    action_id VARCHAR(64) NOT NULL,
    agent_id VARCHAR(64) NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    tool VARCHAR(128) NOT NULL,
    resource_id VARCHAR(255) NOT NULL,
    actual_decision VARCHAR(16) NOT NULL, -- Always 'ALLOW' in observation mode
    shadow_decision VARCHAR(16) NOT NULL, -- 'DENY' or 'HOLD'
    shadow_reason_codes JSONB NOT NULL,
    shadow_explanation TEXT NOT NULL,
    suppressed_violation BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_observation_events_tenant_time ON observation_events(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_observation_events_agent ON observation_events(agent_id, shadow_decision);
