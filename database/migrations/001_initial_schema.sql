-- ============================================================================
-- 001_initial_schema.sql
-- AI-Powered Unified Cloud and Application Security Platform
-- Database: PostgreSQL 16+ (Relational + JSONB)
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. Organizations (Multi-Tenant Isolation)
CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(150) NOT NULL,
    slug VARCHAR(100) UNIQUE NOT NULL,
    subscription_tier VARCHAR(50) DEFAULT 'ENTERPRISE',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 2. Users & RBAC (Module 1)
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    full_name VARCHAR(150) NOT NULL,
    role VARCHAR(50) NOT NULL CHECK (role IN ('ADMIN', 'ANALYST', 'AUDITOR')),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    failed_login_attempts INT NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ NULL,
    last_login_at TIMESTAMPTZ NULL,
    last_login_ip VARCHAR(64) NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_org ON users(organization_id);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- 3. Refresh Tokens & Session Management (Module 1)
CREATE TABLE IF NOT EXISTS user_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_token_hash TEXT NOT NULL,
    ip_address VARCHAR(64),
    user_agent TEXT,
    is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON user_sessions(user_id);

-- 4. Immutable Audit Logs (Module 1)
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID NULL REFERENCES users(id) ON DELETE SET NULL,
    actor_email VARCHAR(255),
    actor_role VARCHAR(50),
    action VARCHAR(120) NOT NULL,
    resource_type VARCHAR(80) NOT NULL,
    resource_id VARCHAR(255),
    ip_address VARCHAR(64),
    user_agent TEXT,
    status VARCHAR(30) NOT NULL DEFAULT 'SUCCESS',
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_org_created ON audit_logs(organization_id, created_at DESC);

-- 5. Connected Cloud Accounts (Module 2)
CREATE TABLE IF NOT EXISTS cloud_accounts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    provider VARCHAR(30) NOT NULL CHECK (provider IN ('AWS', 'AZURE', 'GCP')),
    account_name VARCHAR(150) NOT NULL,
    account_identifier VARCHAR(150) NOT NULL,
    auth_method VARCHAR(50) NOT NULL,
    encrypted_credentials TEXT NOT NULL,
    regions JSONB NOT NULL DEFAULT '["us-east-1"]'::jsonb,
    connection_mode VARCHAR(30) NOT NULL DEFAULT 'LIVE' CHECK (connection_mode IN ('LIVE', 'DEMO_SIMULATION')),
    status VARCHAR(40) NOT NULL DEFAULT 'CONNECTED',
    last_scanned_at TIMESTAMPTZ NULL,
    security_score INT NOT NULL DEFAULT 100,
    created_by UUID NULL REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cloud_accounts_org ON cloud_accounts(organization_id);

-- 6. Discovered Cloud Resources (Module 2)
CREATE TABLE IF NOT EXISTS cloud_resources (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    cloud_account_id UUID NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    provider VARCHAR(30) NOT NULL,
    service_type VARCHAR(80) NOT NULL,
    resource_type VARCHAR(80) NOT NULL,
    resource_id VARCHAR(255) NOT NULL,
    resource_name VARCHAR(255) NOT NULL,
    region VARCHAR(64) NOT NULL,
    is_public BOOLEAN NOT NULL DEFAULT FALSE,
    encryption_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    tags JSONB NOT NULL DEFAULT '{}'::jsonb,
    configuration JSONB NOT NULL DEFAULT '{}'::jsonb,
    discovered_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cloud_resources_account ON cloud_resources(cloud_account_id);

-- 7. Monitored Web, API & AI Targets (Module 3 & Module 7)
CREATE TABLE IF NOT EXISTS scan_targets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(150) NOT NULL,
    target_type VARCHAR(40) NOT NULL CHECK (target_type IN ('WEBSITE', 'REST_API', 'AI_APPLICATION', 'DEPENDENCY_MANIFEST')),
    target_url VARCHAR(500) NOT NULL,
    verification_token VARCHAR(120) NOT NULL,
    verification_method VARCHAR(40) NOT NULL DEFAULT 'DNS_TXT',
    is_verified BOOLEAN NOT NULL DEFAULT FALSE,
    verified_at TIMESTAMPTZ NULL,
    environment VARCHAR(40) NOT NULL DEFAULT 'PRODUCTION',
    last_scanned_at TIMESTAMPTZ NULL,
    security_score INT NOT NULL DEFAULT 100,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scan_targets_org ON scan_targets(organization_id);

-- 8. Scan Jobs History (Module 2 & Module 3)
CREATE TABLE IF NOT EXISTS scan_jobs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    scan_category VARCHAR(50) NOT NULL CHECK (scan_category IN ('CLOUD_CSPM', 'WEB_PASSIVE', 'WEB_ACTIVE', 'PORT_SCAN', 'DEPENDENCY_CVE')),
    target_id UUID NULL REFERENCES scan_targets(id) ON DELETE CASCADE,
    cloud_account_id UUID NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    status VARCHAR(30) NOT NULL DEFAULT 'QUEUED' CHECK (status IN ('QUEUED', 'RUNNING', 'COMPLETED', 'FAILED')),
    progress INT NOT NULL DEFAULT 0,
    findings_count INT NOT NULL DEFAULT 0,
    summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    error_message TEXT NULL,
    triggered_by UUID NULL REFERENCES users(id) ON DELETE SET NULL,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ NULL
);

CREATE INDEX IF NOT EXISTS idx_scan_jobs_org ON scan_jobs(organization_id, started_at DESC);

-- 9. Unified Vulnerabilities & Cloud Findings (Module 2, Module 3, Module 6)
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    scan_job_id UUID NULL REFERENCES scan_jobs(id) ON DELETE SET NULL,
    cloud_account_id UUID NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    target_id UUID NULL REFERENCES scan_targets(id) ON DELETE CASCADE,
    source_type VARCHAR(40) NOT NULL CHECK (source_type IN ('CLOUD_CSPM', 'WEB_SCAN', 'PORT_SCAN', 'SSL_TLS', 'HTTP_HEADERS', 'DEPENDENCY_CVE', 'API_SECURITY')),
    rule_id VARCHAR(100) NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    category VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
    cvss_score NUMERIC(4,1) NOT NULL DEFAULT 5.0,
    cve_id VARCHAR(60) NULL,
    cwe_id VARCHAR(60) NULL,
    affected_asset VARCHAR(500) NOT NULL,
    status VARCHAR(30) NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'IN_PROGRESS', 'RESOLVED', 'FALSE_POSITIVE', 'RISK_ACCEPTED')),
    evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
    remediation_summary TEXT NOT NULL,
    ai_analysis JSONB NULL,
    compliance_controls JSONB NOT NULL DEFAULT '[]'::jsonb,
    first_detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ NULL
);

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_org_sev ON vulnerabilities(organization_id, severity, status);

-- 10. Threat Detection & Security Events (Module 4)
CREATE TABLE IF NOT EXISTS threat_alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    threat_type VARCHAR(80) NOT NULL,
    detection_method VARCHAR(40) NOT NULL CHECK (detection_method IN ('SIGNATURE', 'RULE_THRESHOLD', 'ML_ANOMALY', 'THREAT_INTEL')),
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
    confidence_score NUMERIC(4,2) NOT NULL DEFAULT 0.85,
    source_ip VARCHAR(64) NOT NULL,
    country_code VARCHAR(10) DEFAULT 'UN',
    targeted_endpoint VARCHAR(500) NOT NULL,
    event_count INT NOT NULL DEFAULT 1,
    status VARCHAR(30) NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'INVESTIGATING', 'CONTAINED', 'DISMISSED')),
    description TEXT NOT NULL,
    raw_events JSONB NOT NULL DEFAULT '[]'::jsonb,
    ai_explanation JSONB NULL,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_threat_alerts_org ON threat_alerts(organization_id, last_seen_at DESC);

-- 11. Attack Prevention & Automated Response Actions (Module 5)
CREATE TABLE IF NOT EXISTS prevention_actions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    threat_alert_id UUID NULL REFERENCES threat_alerts(id) ON DELETE SET NULL,
    action_type VARCHAR(60) NOT NULL CHECK (action_type IN ('BLOCK_IP_WAF', 'BLOCK_IP_FIREWALL', 'RATE_LIMIT_IP', 'DISABLE_IAM_KEY', 'REVOKE_USER_SESSION')),
    target_identifier VARCHAR(255) NOT NULL,
    enforcement_layer VARCHAR(60) NOT NULL DEFAULT 'PLATFORM_WAF_AND_CLOUD',
    requires_approval BOOLEAN NOT NULL DEFAULT TRUE,
    status VARCHAR(40) NOT NULL DEFAULT 'PENDING_APPROVAL' CHECK (status IN ('PENDING_APPROVAL', 'EXECUTED', 'ROLLED_BACK', 'REJECTED', 'EXPIRED', 'FAILED')),
    reason TEXT NOT NULL,
    rollback_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    requested_by UUID NULL REFERENCES users(id) ON DELETE SET NULL,
    approved_by UUID NULL REFERENCES users(id) ON DELETE SET NULL,
    expires_at TIMESTAMPTZ NULL,
    executed_at TIMESTAMPTZ NULL,
    rolled_back_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_prevention_org_status ON prevention_actions(organization_id, status);

-- 12. Protected IP Safelist (Module 5 Safety Gate)
CREATE TABLE IF NOT EXISTS ip_safelist (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    ip_cidr VARCHAR(64) NOT NULL,
    label VARCHAR(150) NOT NULL,
    created_by UUID NULL REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 13. AI Application Security Logs & Guardrail Inspections (Module 7)
CREATE TABLE IF NOT EXISTS ai_security_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    application_name VARCHAR(150) NOT NULL,
    inspection_stage VARCHAR(30) NOT NULL CHECK (inspection_stage IN ('PROMPT_INPUT', 'LLM_OUTPUT', 'FULL_INTERACTION')),
    verdict VARCHAR(30) NOT NULL CHECK (verdict IN ('ALLOWED', 'REDACTED', 'BLOCKED', 'FLAGGED')),
    risk_score NUMERIC(4,2) NOT NULL DEFAULT 0.0,
    owasp_llm_categories JSONB NOT NULL DEFAULT '[]'::jsonb,
    detected_violations JSONB NOT NULL DEFAULT '[]'::jsonb,
    sanitized_prompt TEXT NOT NULL,
    sanitized_response TEXT NULL,
    latency_ms INT NOT NULL DEFAULT 0,
    source_ip VARCHAR(64) NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ai_sec_logs_org ON ai_security_logs(organization_id, created_at DESC);

-- 14. Compliance Controls & Evidence Tracking (Module 8: ISO 27001 & SOC 2)
CREATE TABLE IF NOT EXISTS compliance_controls (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    framework VARCHAR(40) NOT NULL CHECK (framework IN ('ISO_27001', 'SOC_2')),
    control_code VARCHAR(50) NOT NULL,
    category VARCHAR(120) NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    evaluation_type VARCHAR(30) NOT NULL DEFAULT 'AUTOMATED' CHECK (evaluation_type IN ('AUTOMATED', 'HYBRID', 'MANUAL')),
    mapped_rule_categories JSONB NOT NULL DEFAULT '[]'::jsonb,
    status VARCHAR(30) NOT NULL DEFAULT 'PASSING' CHECK (status IN ('PASSING', 'FAILING', 'PARTIAL', 'NOT_ASSESSED')),
    failing_assets_count INT NOT NULL DEFAULT 0,
    evidence_notes TEXT NULL,
    evidence_artifacts JSONB NOT NULL DEFAULT '[]'::jsonb,
    last_evaluated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(organization_id, framework, control_code)
);

CREATE INDEX IF NOT EXISTS idx_compliance_org_fw ON compliance_controls(organization_id, framework);
