-- Reconstructed Schema based on codebase usage

-- Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users (Auth)
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'user',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Tenants (Multi-tenancy)
CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    api_key VARCHAR(255) UNIQUE,
    plan VARCHAR(50) DEFAULT 'free',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Request Logs
CREATE TABLE IF NOT EXISTS request_logs (
    id VARCHAR(36) PRIMARY KEY, -- Stored as string in some places, UUID in others. Using VARCHAR for safety.
    timestamp BIGINT NOT NULL,
    client_ip VARCHAR(45),
    method VARCHAR(10),
    uri TEXT,
    status SMALLINT,
    action VARCHAR(20),
    reason TEXT,
    country VARCHAR(2),
    user_agent TEXT,
    ml_score REAL,
    ml_features JSONB,
    headers JSONB,
    body TEXT,
    tenant_id UUID REFERENCES tenants(id),
    processed_duration_ms INT
);

-- Rules
CREATE TABLE IF NOT EXISTS rules (
    id INT PRIMARY KEY,
    name VARCHAR(255),
    pattern TEXT,
    operator VARCHAR(50),
    action VARCHAR(50),
    is_enabled BOOLEAN DEFAULT true,
    risk_score INT,
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Virtual Patches
CREATE TABLE IF NOT EXISTS virtual_patches (
    id VARCHAR(36) PRIMARY KEY,
    cve_id VARCHAR(20),
    title VARCHAR(255),
    description TEXT,
    severity VARCHAR(20),
    rule TEXT, -- serialized rule logic or reference
    status VARCHAR(20),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    blocks_count BIGINT DEFAULT 0,
    affected_paths JSONB
);

-- Bot Detection (Fingerprints)
CREATE TABLE IF NOT EXISTS bot_fingerprints (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    fingerprint_hash VARCHAR(64) UNIQUE,
    first_seen TIMESTAMPTZ DEFAULT NOW(),
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    reputation_score INT,
    is_human BOOLEAN
);

-- ML Models / Feedback
CREATE TABLE IF NOT EXISTS ml_feedback (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    request_id VARCHAR(36),
    actual_label VARCHAR(50), -- 'attack', 'benign'
    features JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
