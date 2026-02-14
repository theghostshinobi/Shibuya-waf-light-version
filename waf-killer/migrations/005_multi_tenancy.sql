-- migrations/005_multi_tenancy.sql

-- Tenants table
CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(200) NOT NULL,
    plan VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'trial',
    settings JSONB NOT NULL DEFAULT '{}',
    quotas JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    
    CHECK (slug ~ '^[a-z0-9-]+$')
);

CREATE INDEX IF NOT EXISTS idx_tenants_slug ON tenants(slug);
CREATE INDEX IF NOT EXISTS idx_tenants_status ON tenants(status);

-- Helper to safely add tenant_id column
DO $$ 
BEGIN 
    -- request_logs
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'request_logs' AND column_name = 'tenant_id') THEN
        ALTER TABLE request_logs ADD COLUMN tenant_id UUID REFERENCES tenants(id);
    END IF;

    -- rules
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'rules' AND column_name = 'tenant_id') THEN
        ALTER TABLE rules ADD COLUMN tenant_id UUID REFERENCES tenants(id);
    END IF;

    -- virtual_patches
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'virtual_patches' AND column_name = 'tenant_id') THEN
        ALTER TABLE virtual_patches ADD COLUMN tenant_id UUID REFERENCES tenants(id);
    END IF;

    -- shadow_diffs
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'shadow_diffs' AND column_name = 'tenant_id') THEN
        ALTER TABLE shadow_diffs ADD COLUMN tenant_id UUID REFERENCES tenants(id);
    END IF;

    -- traffic_snapshots (from previous context)
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'traffic_snapshots') THEN
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'traffic_snapshots' AND column_name = 'tenant_id') THEN
            ALTER TABLE traffic_snapshots ADD COLUMN tenant_id UUID REFERENCES tenants(id);
        END IF;
    END IF;

    -- api_endpoints (from previous context)
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'api_endpoints') THEN
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'api_endpoints' AND column_name = 'tenant_id') THEN
            ALTER TABLE api_endpoints ADD COLUMN tenant_id UUID REFERENCES tenants(id);
        END IF;
    END IF;

    -- api_schemas (from previous context)
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'api_schemas') THEN
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'api_schemas' AND column_name = 'tenant_id') THEN
            ALTER TABLE api_schemas ADD COLUMN tenant_id UUID REFERENCES tenants(id);
        END IF;
    END IF;
END $$;

-- Enable Row-Level Security on all relevant tables
ALTER TABLE request_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE virtual_patches ENABLE ROW LEVEL SECURITY;
ALTER TABLE shadow_diffs ENABLE ROW LEVEL SECURITY;
-- Optional: enable for others if they exist
DO $$ BEGIN
    EXECUTE 'ALTER TABLE traffic_snapshots ENABLE ROW LEVEL SECURITY';
EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN
    EXECUTE 'ALTER TABLE api_endpoints ENABLE ROW LEVEL SECURITY';
EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN
    EXECUTE 'ALTER TABLE api_schemas ENABLE ROW LEVEL SECURITY';
EXCEPTION WHEN OTHERS THEN NULL; END $$;


-- Policies
DO $$ BEGIN
    DROP POLICY IF EXISTS tenant_isolation_policy ON request_logs;
    CREATE POLICY tenant_isolation_policy ON request_logs
        USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
END $$;

DO $$ BEGIN
    DROP POLICY IF EXISTS tenant_isolation_policy ON rules;
    CREATE POLICY tenant_isolation_policy ON rules
        USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
END $$;

DO $$ BEGIN
    DROP POLICY IF EXISTS tenant_isolation_policy ON virtual_patches;
    CREATE POLICY tenant_isolation_policy ON virtual_patches
        USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
END $$;

DO $$ BEGIN
    DROP POLICY IF EXISTS tenant_isolation_policy ON shadow_diffs;
    CREATE POLICY tenant_isolation_policy ON shadow_diffs
        USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
END $$;

-- Indexes
CREATE INDEX IF NOT EXISTS idx_request_logs_tenant ON request_logs(tenant_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_rules_tenant ON rules(tenant_id, enabled);
CREATE INDEX IF NOT EXISTS idx_patches_tenant ON virtual_patches(tenant_id, active);
