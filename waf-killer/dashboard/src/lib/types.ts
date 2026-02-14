export interface Stats { // Renamed or aliased for consistency
    total_requests: number;
    blocked_requests: number;
    allowed_requests: number;
    avg_latency_ms: number;
    rules_triggered: number;
    ml_detections: number;
    threat_intel_blocks: number;
    ebpf_drops: number;
    // ML-specific stats (from backend DashboardStats)
    avg_inference_latency_us?: number;
    last_confidence_score?: number;
    ml_total_inferences?: number;       // Totale inferenze ML eseguite
    active_connections?: number;
    // Extended stats for store (optional or included)
    ml_detection_rate?: number;
    block_rate?: number;
    requests_per_sec?: number;
    timeline?: any[];
    attackTypes?: any[];
    topBlockedIPs?: any[];
    // API Protection stats (nuovi)
    api_validations?: number;
    openapi_blocks?: number;
    graphql_depth_blocks?: number;
    graphql_complexity_blocks?: number;
}

export interface DashboardStats extends Stats {
    // Explicitly include ML fields as optional for clarity
    avg_inference_latency_us?: number;
    last_confidence_score?: number;
    ml_total_inferences?: number;
    // API Protection stats
    api_validations?: number;
    openapi_blocks?: number;
    graphql_depth_blocks?: number;
    graphql_complexity_blocks?: number;
}


export interface DiscoveredEndpoint {
    method: string;
    path: string;
    first_seen: string;
    last_seen: string;
    hit_count: number;
    avg_latency_ms: number;
}

// Full configuration structure matching backend Rust struct
export interface WafConfig {
    server?: {
        listen_addr: string;
        http_port: number;
        https_port: number;
    };
    upstream: {
        backend_url: string;
        pool_size: number;
        connect_timeout: string; // "5s"
        request_timeout: string; // "30s"
        idle_timeout: string; // "90s"
        health_check: {
            enabled: boolean;
            path: string;
            interval: string;
        };
    };
    detection: {
        mode: string; // "blocking", "detection", "off"
        blocking_threshold: number;
        challenge_threshold: number;
        crs: {
            enabled: boolean;
            paranoia_level: number;
            inbound_threshold: number;
            outbound_threshold: number;
        };
        rate_limiting: {
            enabled: boolean;
            requests_per_second: number;
            burst_size: number;
            ban_duration_secs: number;
        };
    };
    ml: {
        enabled: boolean;
        threshold: number;
        ml_weight: number;
        shadow_mode: boolean;
        model_path?: string; // Optional in frontend view
    };
    security: {
        blocked_user_agents: string[];
        allowed_methods: string[];
    };
    api_protection?: {
        enabled: boolean;
        graphql: {
            max_depth: number;
            max_complexity: number;
            max_batch_size: number;
            introspection_enabled: boolean;
        };
    };
}

export type ConfigUpdate = Partial<WafConfig>;

// Additional types needed for existing UI compatibility
export interface HealthStatus {
    status: string;
    uptime_human: string;
    components: {
        proxy: string;
        rule_engine: string;
        ebpf: string;
        wasm_plugins: string;
    };
}

export interface RequestLog {
    id: string;
    timestamp: number; // Seconds
    client_ip: string;
    method: string;
    uri: string; // Backend uses uri, frontend table expects url? 
    // mapped to url in table or use uri
    url?: string; // Optional alias if needed
    status: number;
    action: string;
    reason: string;
    country: string;
    // Extended fields (optional as backend might not send them yet)
    latency_ms?: number;
    crs_score?: number;
    ml_score?: number;
    ml_features?: string; // Added for Audit Logs
    headers?: [string, string][]; // Added for Audit Logs
    body?: string; // Added for Audit Logs
}

export type RequestSummary = RequestLog; // Alias for compatibility

export interface RuleInfo {
    id: string;
    description: string;
    enabled: boolean;
    content?: string;
    details?: any; // Full Rule struct from backend
}

export interface AnalyticsData { // Backward compatibility
    total_requests: number;
    blocked_requests: number;
    block_rate: number;
    active_rules: number;
}

export interface Vulnerability {
    id: string;
    title: string;
    severity: string;
    status: string;
    cve_id?: string;
    cve?: string; // Legacy/Alias
    description: string;
    affected_path?: string;
    discovered_at: string;
}

export interface VirtualPatch {
    id: string;
    cve_id: string;
    title: string;
    description: string;
    severity: string;
    rule: string;
    status: string;
    created_at: string;
    blocks_count: number;
    affected_paths: string[];
}

export interface TrafficTimeSeries {
    timestamp: number;
    total_requests: number;
    blocked_requests: number;
    bytes_processed: number;
    avg_latency: number;
}

// Missing types for charts
export interface TimePoint {
    time: string;
    value: number;
}

export interface PieSlice {
    label: string;
    value: number;
    color?: string;
}

export interface BarItem {
    label: string;
    value: number;
}

// ========================================
// Enhancement #5: New Types for API Completeness
// ========================================

export interface ConfigBackup {
    timestamp: string;        // ISO 8601 or similar ID
    filename: string;
    size_bytes: number;
    description?: string;
}

export interface ThreatIntelStats {
    total_feeds: number;
    active_feeds: number;
    total_ips: number;
    last_refresh: string;      // ISO 8601 timestamp
    lookups_24h: number;
    hits_24h: number;
    cache_hit_rate: number;    // 0.0-1.0
}

export interface VulnerabilityImport {
    title: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    url: string;
    description: string;
    cve_id?: string;
}

export interface RequestDetail {
    id: string;
    timestamp: string;
    method: string;
    url: string;
    headers: Record<string, string>;
    body?: string;
    response_status: number;
    response_time_ms: number;
    rules_triggered: string[];
    blocked: boolean;
    ml_score?: number;
    threat_intel_hit?: boolean;
}

export interface RuleCount {
    rule_id: string;
    count: number;
}

export interface IpCount {
    ip: string;
    count: number;
}

export interface ShadowReport {
    total_analyzed: number;
    simulated_blocks: number;
    top_rules: RuleCount[];
    top_ips: IpCount[];
}

export interface ShadowApiEndpoint {
    method: string;
    path: string;
    risk_score: number;
    discovered_at: string;
}

export interface ThreatFeed {
    name: string;
    count: number;
    status: string;
    last_updated?: string;
}

// ========================================
// Enhancement #6: Bot Detection & Replay (Fixing Integrations)
// ========================================

export interface BotStatsSnapshot {
    total_requests_analyzed: number;
    bots_detected: number;
    bots_blocked: number;
    fingerprint_matches: number;
    behavior_score_blocks: number;
}

export interface BotDetectionConfig {
    enabled: boolean;
    fingerprint_check: boolean;
    behavior_analysis: boolean;
    block_threshold: number;
}

export interface RequestSnapshot {
    request_id: string;
    timestamp: string; // DateTime<Utc> serialized
    method: string;
    uri: string;
    headers: Record<string, string[]>;
    query_params: Record<string, string[]>;
    body?: number[]; // Option<Vec<u8>>
    client_ip: string;
    action: string; // InspectionAction enum serialized
    crs_score: number;
    ml_score: number;
}

export interface ReplayReport {
    total_requests: number;
    unchanged: number;
    new_blocks: number;
    new_allows: number;
    new_blocks_examples: RequestSnapshot[];
    new_allows_examples: RequestSnapshot[];
}
