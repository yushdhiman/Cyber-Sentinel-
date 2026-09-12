-- Cyber Sentinel Production PostgreSQL Schema
-- Manages Users, Incidents, Firewall Containment Rules, Audit Logs, Scans, Sessions, and Enrolled Devices.

CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(64) PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    role VARCHAR(32) NOT NULL DEFAULT 'ANALYST',
    status VARCHAR(32) NOT NULL DEFAULT 'active',
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    totp_secret VARCHAR(128),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS incidents (
    id VARCHAR(64) PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    severity VARCHAR(32) NOT NULL DEFAULT 'HIGH',
    category VARCHAR(64) NOT NULL DEFAULT 'THREAT_DETECTION',
    status VARCHAR(32) NOT NULL DEFAULT 'NEW',
    description TEXT,
    assignee VARCHAR(255) DEFAULT 'Unassigned',
    related_ips JSONB DEFAULT '[]'::jsonb,
    related_alerts JSONB DEFAULT '[]'::jsonb,
    mitre_techniques JSONB DEFAULT '[]'::jsonb,
    evidence JSONB DEFAULT '{}'::jsonb,
    evidence_hash VARCHAR(64),
    timeline JSONB DEFAULT '[]'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS firewall_rules (
    ip VARCHAR(64) PRIMARY KEY,
    reason TEXT,
    blocked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    blocked_by VARCHAR(255) NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    unblocked_at TIMESTAMP WITH TIME ZONE
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id VARCHAR(64) PRIMARY KEY,
    actor VARCHAR(255) NOT NULL,
    actor_role VARCHAR(64) NOT NULL,
    action VARCHAR(64) NOT NULL,
    target VARCHAR(255),
    result VARCHAR(32) NOT NULL DEFAULT 'SUCCESS',
    source_ip VARCHAR(64),
    details JSONB DEFAULT '{}'::jsonb,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS malware_scans (
    id VARCHAR(64) PRIMARY KEY,
    filename VARCHAR(255) NOT NULL,
    sha256 VARCHAR(64) NOT NULL,
    score INTEGER NOT NULL,
    severity VARCHAR(32) NOT NULL,
    details JSONB DEFAULT '{}'::jsonb,
    analyzed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sessions (
    id VARCHAR(64) PRIMARY KEY,
    user_email VARCHAR(255) NOT NULL,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    ip VARCHAR(64),
    user_agent TEXT,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMP WITH TIME ZONE
);

CREATE TABLE IF NOT EXISTS devices (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255),
    device_token_hash VARCHAR(64) NOT NULL UNIQUE,
    platform VARCHAR(128),
    hostname VARCHAR(255),
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    agent_version VARCHAR(32),
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for high-frequency queries
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents (status);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents (severity);
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions (token_hash);
CREATE INDEX IF NOT EXISTS idx_firewall_rules_active ON firewall_rules (active);
