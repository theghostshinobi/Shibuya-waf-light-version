-- migrations/010_sessions.sql

CREATE TABLE IF NOT EXISTS conditional_access_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(200) NOT NULL,
    enabled BOOLEAN DEFAULT true,
    priority INT NOT NULL,
    conditions JSONB NOT NULL,
    actions JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_policies_tenant ON conditional_access_policies (tenant_id, priority);

-- Note: Actual session data is stored in Redis for performance and TTL management,
-- but we keep this table for historical auditing and manual revocation if needed.
CREATE TABLE IF NOT EXISTS session_audit (
    session_id VARCHAR(64) PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    terminated_at TIMESTAMP WITH TIME ZONE,
    ip_address INET NOT NULL,
    user_agent TEXT,
    fingerprint VARCHAR(64),
    mfa_verified BOOLEAN DEFAULT false,
    metadata JSONB
);

CREATE INDEX IF NOT EXISTS idx_session_audit_user ON session_audit(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_session_audit_tenant ON session_audit(tenant_id);
