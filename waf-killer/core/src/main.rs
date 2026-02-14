// ============================================
// File: core/src/main.rs
// ============================================
// Episode 1 + 7: Entry Point with Admin API
// ============================================

use std::sync::Arc;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use clap::Parser;
use log::{error, info, warn};
use pingora::server::Server;
use pingora::server::configuration::Opt;
use axum::Router;
use tower_http::cors::CorsLayer;

use waf_killer_core::config::{Config, DetectionMode};
use waf_killer_core::proxy::WafProxy;
use waf_killer_core::rules::loader::RuleSet;
use waf_killer_core::rules::seed::generate_owasp_rules;
use waf_killer_core::rules::engine::{RuleEngine, EngineConfig, EngineMode};
use waf_killer_core::admin_api::create_admin_router;
use waf_killer_core::state::{SharedState, WafState};
use waf_killer_core::traffic_stats::TrafficStatsTracker;
use waf_killer_core::api::virtual_patches::{VirtualPatchStore, virtual_patches_router};
use waf_killer_core::api::shadow_api::{EndpointDiscovery, shadow_api_router};
use waf_killer_core::vulnerabilities::VulnerabilityManager;
// API Protection
use waf_killer_core::api_protection::openapi::{OpenAPIValidator, OpenApiSpec};
use waf_killer_core::api_protection::graphql::{
    GraphQLParser, DepthAnalyzer, ComplexityScorer, FieldAuthorizer, GraphQLRateLimiter,
};


#[derive(Parser, Debug)]
#[command(name = "waf-killer")]
#[command(author = "WAF Killer Team")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "Production-grade WAF with Rules-based detection (Pingora)")]
struct Args {
    /// Path to configuration file
    #[arg(short, long, default_value = "config/waf.yaml")]
    config: String,

    /// Check configuration syntax and exit
    #[arg(long)]
    check_config: bool,

    /// Admin API port (default: 9090)
    #[arg(long, default_value = "9090")]
    admin_port: u16,
}

fn main() -> Result<()> {
    // 1. Initialize Logger
    env_logger::init(); 

    // 2. Parse Args
    let args = Args::parse();
    
    // 3. Load Config
    let rt = tokio::runtime::Runtime::new()?;
    let config = rt.block_on(async {
        Config::load(&args.config).await
    }).context("Failed to load configuration")?;

    if args.check_config {
        info!("✅ Configuration syntax is valid.");
        return Ok(());
    }

    // Git Sync Initialization
    let (_git_sync, reload_rx) = if let Some(_repo) = &config.policy.source.repo {
        if config.policy.source.type_ == waf_killer_core::config::SourceType::Git {
            info!("🔄 Git policy sync enabled");
            let source_config = config.policy.source.clone();
            
            let (sync, rx) = rt.block_on(async {
                 waf_killer_core::config::git_sync::GitPolicySync::new(source_config).await
            })?;
            
            let sync = Arc::new(sync);
            let sync_bg = sync.clone();
            rt.spawn(async move {
                sync_bg.start_polling().await;
            });
            
            (Some(sync), Some(rx))
        } else {
            (None, None)
        }
    } else {
        (None, None)
    };
    
    info!(
        "🚀 WAF Killer starting up (Pingora Engine)... Version: {}, Config: {}",
        env!("CARGO_PKG_VERSION"),
        args.config
    );

    let config_swap = Arc::new(ArcSwap::from_pointee(config.clone()));

    // 4. Load Rules (with ArcSwap for hot-reload)
    let rules_path = Path::new(&config.detection.crs.rules_path);
    let rule_set = RuleSet::load_from_dir(rules_path)
        .context("Failed to load generic rules")?;
        
    let engine_config = EngineConfig {
        paranoia_level: config.detection.crs.paranoia_level,
        inbound_threshold: config.detection.blocking_threshold,
        outbound_threshold: config.detection.crs.outbound_threshold,
        enabled: config.detection.mode != DetectionMode::Off,
        mode: match config.detection.mode {
             DetectionMode::Blocking => EngineMode::Blocking,
             DetectionMode::Detection => EngineMode::Detection,
             DetectionMode::Off => EngineMode::Off,
        },
    };
    
    let crs_count = rule_set.rules.len();
    let mut all_rules = rule_set.rules;
    let seed_rules = generate_owasp_rules();
    let seed_count = seed_rules.len();
    all_rules.extend(seed_rules);
    info!("🛡️  Injected {} seed OWASP rules (CRS: {}, Total: {})", seed_count, crs_count, all_rules.len());
    
    let rules_count = all_rules.len();
    let rule_engine = Arc::new(ArcSwap::from_pointee(RuleEngine::new(all_rules, engine_config)));
    info!("🛡️  Rule Engine initialized ({} rules)", rules_count);
    
    // 5. Initialize Extra Modules
    let bot_stats = Arc::new(waf_killer_core::botdetection::BotDetectionStats::default());
    let bot_config = Arc::new(tokio::sync::RwLock::new(config.detection.bot_detection.clone()));
    
    let bot_detector = Arc::new(waf_killer_core::botdetection::BotDetector::with_stats(bot_stats.clone()));
    info!("🤖 Bot Detector initialized");

    let rate_limiter = rt.block_on(async {
        let redis_url = std::env::var("REDIS_URL").ok().or(Some("redis://127.0.0.1:6379".to_string()));
        waf_killer_core::ratelimit::distributed::RateLimiter::new(redis_url).await
    });
    let rate_limiter = Arc::new(rate_limiter);
    info!("⏳ Rate Limiter initialized");

    // ML Engine
    let ml_engine = if config.ml.enabled {
        match waf_killer_core::ml::inference::MLInferenceEngine::new(
            &config.ml.model_path.to_string_lossy(),
            &config.ml.scaler_path.to_string_lossy(),
            config.ml.threshold,
        ) {
            Ok(engine) => {
                info!("🤖 ML Engine initialized");
                Some(Arc::new(engine))
            },
            Err(e) => {
                log::warn!("ML Engine init failed (non-fatal): {}", e);
                None
            }
        }
    } else {
        None
    };

    // Threat Classifier (smartcore Random Forest — always available)
    let classifier_path = config.ml.classifier_model_path.clone();
    let threat_classifier = {
        let classifier = waf_killer_core::ml::classification::ThreatClassifier::load(&classifier_path);
        info!("🧠 Threat Classifier initialized (10 classes, 100 trees)");
        Some(Arc::new(classifier))
    };

    // Explainability Engine
    let explainability_engine = Some(Arc::new(waf_killer_core::ml::explainability::ExplainabilityEngine::new()));
    info!("🔍 Explainability Engine initialized");



    // WASM Manager
    let wasm_plugins_path = config.wasm.plugins_dir.to_string_lossy();
    let wasm_manager = waf_killer_core::wasm::WasmPluginManager::new(&wasm_plugins_path)
        .context("Failed to initialize WASM Manager")?;
    info!("🔌 WASM Manager initialized at {}", wasm_plugins_path);

    // Threat Intel
    let threat_client = if config.threat_intel.enabled {
        let client = Arc::new(waf_killer_core::threat_intel::client::ThreatIntelClient::new(config.threat_intel.clone()));
        
        let client_bg = client.clone();
        rt.block_on(async move {
            info!("Loading threat intelligence feeds...");
            match client_bg.load_feeds().await {
                Ok(count) => info!("Loaded {} IPs from threat feeds", count),
                Err(e) => error!("Failed to load threat feeds: {}", e),
            }
        });
        
        let client_bg = client.clone();
        rt.spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
            loop {
                interval.tick().await;
                info!("Refreshing threat intelligence feeds...");
                match client_bg.load_feeds().await {
                    Ok(count) => info!("Refreshed {} IPs from threat feeds", count),
                    Err(e) => error!("Failed to refresh threat feeds: {}", e),
                }
            }
        });
        
        Some(client)
    } else {
        None
    };
    
    // Traffic Stats Tracker & New Stores
    let traffic_tracker = TrafficStatsTracker::new();
    let virtual_patch_store = VirtualPatchStore::new();
    let endpoint_discovery = EndpointDiscovery::new();
    
    // Initialize SQLite persistence
    let waf_db = rt.block_on(async {
        match waf_killer_core::persistence::WafDatabase::init("data/waf.db").await {
            Ok(db) => {
                info!("💾 SQLite persistence enabled (data/waf.db)");
                Some(db)
            }
            Err(e) => {
                error!("⚠️  SQLite init failed (falling back to in-memory): {}", e);
                None
            }
        }
    });
    let shared_state = Arc::new(rt.block_on(SharedState::new_with_db(waf_db)));
    
    // Sync initial config to RuntimeController
    shared_state.controller.bot_detection_enabled.store(config.detection.bot_detection.enabled, std::sync::atomic::Ordering::Relaxed);
    shared_state.controller.ml_enabled.store(config.ml.enabled, std::sync::atomic::Ordering::Relaxed);


    // Database & Feedback Manager
    let (feedback_manager, db_pool) = rt.block_on(async {
        let db_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/waf_killer".to_string());
        match sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .connect(&db_url).await 
        {
            Ok(pool) => {
                info!("📦 Database connected: {}", db_url);
                let mgr = waf_killer_core::ml::feedback::FeedbackManager::new(pool.clone());
                // Try init DB
                if let Err(e) = mgr.init_db().await {
                   error!("❌ Failed to initialize Feedback DB: {}", e);
                }
                (Some(Arc::new(mgr)), Some(pool))
            },
            Err(e) => {
                error!("❌ Database connection failed: {}", e);
                (None, None)
            }
        }
    });

    // 7. WafState
    let vuln_manager = Arc::new(VulnerabilityManager::new());
    let api_protection_state = Arc::new(waf_killer_core::api_protection::state::ApiProtectionState::default());
    let tenant_store = Arc::new(waf_killer_core::tenancy::store::TenantStore::new());
    let waf_state = Arc::new(WafState::new(
        config_swap.clone(),  
        PathBuf::from(&args.config), // Pass config path
        rule_engine.clone(), 
        shared_state.clone(), 
        Some(wasm_manager.clone()),
        threat_client.clone(),
        ml_engine.clone(),
        threat_classifier.clone(),
        vuln_manager.clone(),
        api_protection_state.clone(),
        tenant_store.clone(),
        bot_stats.clone(),
        bot_config.clone(),
        feedback_manager.clone(), // ADDED
        Arc::new(endpoint_discovery.clone()), // ADDED: Wrap in Arc
        virtual_patch_store.clone(), // ADDED
        db_pool.clone() // ADDED
    ));

    // Start Traffic Statistics Snapshot Task (Every 1s)
    let stats_state = waf_state.clone();
    rt.spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            interval.tick().await;
            stats_state.shared.snapshot_stats();
        }
    });

    // Handle Config Reloads
    if let Some(mut rx) = reload_rx {
        let waf_state_reload = waf_state.clone();
        rt.spawn(async move {
            info!("👂 Listening for config reload requests...");
            while let Some(req) = rx.recv().await {
                info!("🔄 RELOAD triggered by commit: {}", &req.commit_hash);
                
                // 1. Load new config
                match Config::load(&req.config_path).await {
                    Ok(new_config) => {
                         info!("   ✅ New config validated. Applying...");
                         
                         // 2. Update shared config
                         waf_state_reload.config.store(Arc::new(new_config.clone()));
                         
                         // 3. Reload Rules
                         let rules_path = Path::new(&new_config.detection.crs.rules_path); // Use new path
                         match RuleSet::load_from_dir(rules_path) {
                             Ok(new_rule_set) => {
                                 let engine_config = EngineConfig {
                                     paranoia_level: new_config.detection.crs.paranoia_level,
                                     inbound_threshold: 5,
                                     outbound_threshold: 4,
                                     enabled: new_config.detection.mode != DetectionMode::Off,
                                     mode: match new_config.detection.mode {
                                         DetectionMode::Blocking => EngineMode::Blocking,
                                         DetectionMode::Detection => EngineMode::Detection,
                                         DetectionMode::Off => EngineMode::Off,
                                     },
                                 };
                                 let mut new_rules = new_rule_set.rules;
                                 let seed_rules = generate_owasp_rules();
                                 new_rules.extend(seed_rules);
                                 let new_engine = RuleEngine::new(new_rules, engine_config);
                                 waf_state_reload.rule_engine.store(Arc::new(new_engine));
                                 info!("   ✅ Rule Engine reloaded");
                             }
                             Err(e) => {
                                 error!("   ❌ Failed to reload rules: {}", e);
                                 // Rollback config? Or just keep old rules with new config?
                                 // Safest is to NOT apply config if rules fail, but we already applied config.
                                 // In future, do all-or-nothing with a transaction or verify rules first.
                             }
                         }
                         
                         // 4. Update other components if needed (Wasm, ML, etc)
                         // For now, rules are the main thing.
                    }
                    Err(e) => {
                        error!("   ❌ Failed to load new config: {}", e);
                    }
                }
            }
        });
    }
    
    // 8. Admin API Router & Server
    let admin_port = args.admin_port;
    
    // Build API router
    let api_router = Router::new()
        .merge(create_admin_router(waf_state.clone()))
        .layer(CorsLayer::permissive());

    rt.spawn(async move {
        let addr = std::net::SocketAddr::from(([0, 0, 0, 0], admin_port));
        info!("🛠️  Admin API starting on http://{}", addr);
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        axum::serve(listener, api_router).await.unwrap();
    });
    
    // 9. Server Bootstrap
    let mut server = Server::new(Some(Opt::default())).unwrap();
    server.bootstrap();
    
    // 10. Proxy Service
    let socket_addr = config.http_addr(); 
    info!("📡 Proxy listening on {}", socket_addr);
    
    let rule_engine_snapshot = rule_engine.load_full();
    
    // 11. API Protection Initialization
    let api_config = &config.api_protection;
    
    // Log API Protection status
    info!("═══════════════════════════════════════════════════════════════════════");
    info!("🛡️  API Protection: {}", if api_config.enabled { "ENABLED" } else { "DISABLED" });
    
    let openapi_validator = if api_config.enabled && api_config.openapi_validation_enabled {
        let mut validator = None;
        info!("   OpenAPI Validation: ENABLED");
        info!("   OpenAPI Specs to load: {}", api_config.openapi_specs.len());
        
        if api_config.openapi_specs.is_empty() {
            warn!("   ⚠️  API Protection enabled but no OpenAPI specs configured");
        }
        
        // Load first spec found
        for (idx, spec_path) in api_config.openapi_specs.iter().enumerate() {
            match OpenApiSpec::load_from_file(spec_path.to_str().unwrap_or("")) {
                Ok(spec) => {
                    info!("   ✅ [{}] Loaded OpenAPI spec: {:?}", idx + 1, spec_path);
                    if validator.is_none() {
                        validator = Some(Arc::new(OpenAPIValidator::new(spec)));
                    }
                }
                Err(e) => {
                    if api_config.strict_mode {
                        error!("   ❌ [{}] Failed to load OpenAPI spec {:?}: {}", idx + 1, spec_path, e);
                        return Err(anyhow::anyhow!("Strict mode: OpenAPI spec load failed: {}", e));
                    } else {
                        warn!("   ❌ [{}] Failed to load OpenAPI spec {:?}: {}", idx + 1, spec_path, e);
                    }
                }
            }
        }
        validator
    } else {
        if api_config.enabled {
            info!("   OpenAPI Validation: DISABLED");
        }
        None
    };
    
    // GraphQL Protection Logging
    let graphql_config = &api_config.graphql;
    if api_config.enabled {
        info!("   GraphQL Protection:");
        info!("     Endpoint: {}", graphql_config.endpoint);
        info!("     Max Depth: {}", graphql_config.max_depth);
        info!("     Max Complexity: {}", graphql_config.max_complexity);
        info!("     Max Batch Size: {}", graphql_config.max_batch_size);
        info!("     Max Aliases: {}", graphql_config.max_aliases);
        info!("     Introspection: {}", if graphql_config.introspection_enabled { "ALLOWED" } else { "BLOCKED" });
        
        if !graphql_config.auth_rules.is_empty() {
            info!("     Authorization Rules: {} configured", graphql_config.auth_rules.len());
        } else {
            warn!("     ⚠️  No GraphQL authorization rules configured - all fields accessible");
        }
        
        if graphql_config.rate_limits.is_some() {
            info!("     Rate Limits: CONFIGURED");
        }
        
        if graphql_config.field_costs.is_some() {
            info!("     Field Costs: CONFIGURED");
        }
    }
    info!("═══════════════════════════════════════════════════════════════════════");
    
    // Initialize GraphQL components
    let graphql_parser = Some(Arc::new(GraphQLParser::new()));
    let graphql_depth_analyzer = Some(Arc::new(DepthAnalyzer::new(graphql_config.max_depth)));
    let graphql_complexity_scorer = Some(Arc::new(ComplexityScorer::new(graphql_config.max_complexity)));
    
    // Convert auth_rules to HashMap format expected by FieldAuthorizer
    let auth_rules_map: Option<std::collections::HashMap<String, Vec<String>>> = if graphql_config.auth_rules.is_empty() {
        None
    } else {
        Some(graphql_config.auth_rules.iter()
            .map(|r| (r.field_path.clone(), r.required_roles.clone()))
            .collect())
    };
    let graphql_authorizer = Some(Arc::new(FieldAuthorizer::new(auth_rules_map)));
    
    // Convert rate_limits to simple HashMap<String, u32> format
    let rate_limits_map: Option<std::collections::HashMap<String, u32>> = graphql_config.rate_limits.as_ref().map(|limits| {
        limits.iter()
            .map(|(k, v)| (k.clone(), v.requests_per_minute))
            .collect()
    });
    let graphql_rate_limiter = Some(Arc::new(GraphQLRateLimiter::new(rate_limits_map)));
    
    let proxy_logic = WafProxy {
        config: config_swap.clone(),
        rule_engine: rule_engine_snapshot,
        bot_detector: bot_detector.clone(),
        rate_limiter: rate_limiter.clone(),
        wasm_manager: wasm_manager.clone(),
        shared: shared_state.clone(),
        ml_engine: ml_engine.clone(),

        threat_client: threat_client.clone(),
        feedback_manager: waf_state.feedback_manager.clone(),
        traffic_tracker,
        endpoint_discovery: Arc::new(endpoint_discovery),
        
        // API Protection
        openapi_validator,
        graphql_parser,
        graphql_depth_analyzer,
        graphql_complexity_scorer,
        graphql_authorizer,
        graphql_rate_limiter,
        graphql_schema: None,
        api_protection_enabled: api_config.enabled,
        threat_classifier: threat_classifier.clone(),
        explainability_engine: explainability_engine.clone(),
    };

    
    // Wait, I need to wrap endpoint_discovery in Arc?
    // In `main.rs`, `endpoint_discovery` is `EndpointDiscovery`.
    // In `proxy/mod.rs`, I defined field as `Arc<EndpointDiscovery>`.
    // It's better to just use `EndpointDiscovery` directly in `WafProxy` if it's cheap to clone (it is).
    // Or I wrap it here.
    // I'll wrap it here to match `proxy/mod.rs`.
    
    // Correction: I can't wrap `EndpointDiscovery` in `Arc` because `shadow_api_router` took ownership or clone?
    // `shadow_api_router(endpoint_discovery.clone())`
    
    // Let's use `Arc::new(endpoint_discovery)` in `WafProxy` struct init.
    // Wait, if I used `endpoint_discovery` in `shadow_api_router(endpoint_discovery.clone())`, I still have ownership of `endpoint_discovery`?
    // Yes, because I called clone().
    
    // So:
    // endpoint_discovery: Arc::new(endpoint_discovery),
    
    let mut proxy_service = pingora::proxy::http_proxy_service(
        &server.configuration,
        proxy_logic
    );
    
    proxy_service.add_tcp(&socket_addr.to_string());
    
    let tls = &config.server.tls;
    if tls.enabled {
         proxy_service.add_tls(
             &socket_addr.to_string(), 
             tls.cert_path.to_str().unwrap(), 
             tls.key_path.to_str().unwrap()
         ).context("Failed to add TLS listener")?;
         info!("🔐 TLS enabled");
    }

    server.add_service(proxy_service);

    info!("🚀 Running Server...");
    server.run_forever(); 
}
