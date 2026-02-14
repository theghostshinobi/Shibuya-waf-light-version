-- SQL Schema for Vulnerabilities Manager

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title VARCHAR(255) NOT NULL,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
    status VARCHAR(20) NOT NULL CHECK (status IN ('OPEN', 'FIXED', 'FALSE_POSITIVE')),
    cve_id VARCHAR(50),
    description TEXT,
    affected_path VARCHAR(255),
    discovered_at TIMESTAMPTZ DEFAULT NOW(),
    remediated_at TIMESTAMPTZ
);

CREATE INDEX idx_vuln_severity ON vulnerabilities(severity);
CREATE INDEX idx_vuln_status ON vulnerabilities(status);
