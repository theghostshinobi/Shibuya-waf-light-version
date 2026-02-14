-- migrations/002_traffic_capture.sql

CREATE TABLE IF NOT EXISTS traffic_snapshots (
    id BIGSERIAL PRIMARY KEY,
    request_id VARCHAR(36) NOT NULL,
    snapshot_data JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_snapshots_created_at ON traffic_snapshots (created_at);
CREATE INDEX IF NOT EXISTS idx_snapshots_request_id ON traffic_snapshots (request_id);

CREATE TABLE IF NOT EXISTS shadow_diffs (
    id BIGSERIAL PRIMARY KEY,
    request_id VARCHAR(36) NOT NULL,
    production_action VARCHAR(20) NOT NULL,
    shadow_action VARCHAR(20) NOT NULL,
    production_score INT NOT NULL,
    shadow_score INT NOT NULL,
    diff_data JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_diffs_created_at ON shadow_diffs (created_at);
CREATE INDEX IF NOT EXISTS idx_diffs_actions ON shadow_diffs (production_action, shadow_action);
