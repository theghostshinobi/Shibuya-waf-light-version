-- migrations/009_mfa.sql

CREATE TABLE IF NOT EXISTS mfa_devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_type VARCHAR(50) NOT NULL,  -- 'totp', 'webauthn', 'sms'
    device_name VARCHAR(100),
    secret TEXT,                        -- Encrypted TOTP secret or WebAuthn credential
    backup_codes TEXT[],
    verified BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE,
    
    UNIQUE(user_id, device_type, device_name)
);

CREATE INDEX IF NOT EXISTS idx_mfa_devices_user ON mfa_devices(user_id);
CREATE INDEX IF NOT EXISTS idx_mfa_devices_tenant ON mfa_devices(tenant_id);

-- Add mfa_enabled to users table
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN DEFAULT false;
