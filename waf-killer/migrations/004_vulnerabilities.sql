CREATE TABLE vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title VARCHAR(500) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    confidence VARCHAR(20),
    scanner_type VARCHAR(50) NOT NULL,
    cve_id VARCHAR(50),
    path VARCHAR(1000) NOT NULL,
    method VARCHAR(10),
    evidence JSONB,
    description TEXT,
    solution TEXT,
    discovered_at TIMESTAMP NOT NULL DEFAULT NOW(),
    patched BOOLEAN DEFAULT false
);

CREATE INDEX idx_vulns_severity ON vulnerabilities (severity);
CREATE INDEX idx_vulns_cve ON vulnerabilities (cve_id);
CREATE INDEX idx_vulns_discovered ON vulnerabilities (discovered_at);

CREATE TABLE virtual_patches (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id VARCHAR(50),
    vulnerability_id UUID REFERENCES vulnerabilities(id),
    rules JSONB NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP,
    verified BOOLEAN DEFAULT false,
    active BOOLEAN DEFAULT true
);

CREATE INDEX idx_patches_cve ON virtual_patches (cve_id);
CREATE INDEX idx_patches_active ON virtual_patches (active, expires_at);

CREATE TABLE patch_verifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    patch_id UUID REFERENCES virtual_patches(id),
    verified_at TIMESTAMP NOT NULL DEFAULT NOW(),
    blocks_attack BOOLEAN NOT NULL,
    allows_legitimate BOOLEAN NOT NULL,
    test_output TEXT
);
