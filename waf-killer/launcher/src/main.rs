use anyhow::{Context, Result};
use clap::Parser;
use pingora::server::Server;
use pingora::server::configuration::Opt;
use std::sync::Arc;
use tracing::{info, warn};
use arc_swap::ArcSwap;

use waf_killer_core::config::Config;
use waf_killer_core::proxy::WafProxy;
use waf_killer_core::telemetry::Telemetry;
use waf_killer_core::rules::engine::{RuleEngine, EngineConfig, EngineMode};
use waf_killer_core::rules::loader::RuleSet;
use waf_killer_core::botdetection::BotDetector;
use waf_killer_core::ratelimit::distributed::RateLimiter;
use waf_killer_core::wasm::WasmPluginManager;
use waf_killer_core::state::SharedState;
use waf_killer_core::admin_api::{WafState, start_admin_server};
use waf_killer_core::ml::inference::MLInferenceEngine;
use waf_killer_core::threat_intel::client::ThreatIntelClient;
use waf_killer_core::api::shadow_api::EndpointDiscovery;
use waf_killer_core::vulnerabilities::VulnerabilityManager;
use std::path::Path;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value = "config/waf.yaml")]
    config: String,

    /// Admin API port (default: 9090)
    #[arg(long, default_value = "9090")]
    admin_port: u16,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Create a temporary runtime for initialization tasks
    let rt = tokio::runtime::Runtime::new().context("Failed to create init runtime")?;

    // 2. Load Config
    let config = rt.block_on(async {
        Config::load(&args.config).await
            .unwrap_or_else(|e| {
                eprintln!("Failed to load config: {}. Using defaults.", e);
                Config::default()
            })
    });

    // 3. Initialize Telemetry
    let log_format_str = match config.telemetry.log_format {
        waf_killer_core::config::LogFormat::Json => "json",
        waf_killer_core::config::LogFormat::Pretty => "pretty",
        waf_killer_core::config::LogFormat::Compact => "compact",
    };
    Telemetry::init(&config.telemetry.log_level, log_format_str)
        .context("Failed to initialize telemetry")?;

    info!("Starting WAF Killer v{}", env!("CARGO_PKG_VERSION"));
    
    // 4. Initialize Pingora Server
    let mut server = Server::new(Some(Opt::default())).context("Failed to create Pingora server")?;
    server.bootstrap();
    
    // 5. Setup Rule Engine
    let ruleset = RuleSet::load_from_dir(Path::new(&config.detection.crs.rules_path))
        .unwrap_or_else(|e| {
            warn!("Failed to load CRS rules: {}. Using empty ruleset.", e);
            RuleSet { rules: vec![] }
        });
    
    let mode = match config.detection.mode {
        waf_killer_core::config::DetectionMode::Blocking => EngineMode::Blocking,
        waf_killer_core::config::DetectionMode::Detection => EngineMode::Detection,
        waf_killer_core::config::DetectionMode::Off => EngineMode::Off,
    };
    
    let engine_config = EngineConfig {
        enabled: config.detection.enabled,
        mode,
        paranoia_level: config.detection.crs.paranoia_level,
        inbound_threshold: config.detection.crs.inbound_threshold,
        outbound_threshold: config.detection.crs.outbound_threshold,
    };
    
    // Use ArcSwap for hot-reloading capability in Admin API
    let initial_engine = RuleEngine::new(ruleset.rules, engine_config);
    let rule_engine = Arc::new(ArcSwap::from_pointee(initial_engine));

    // 6. Setup Bot Detector
    let bot_detector = Arc::new(BotDetector::new());
    
    // 7. Setup Rate Limiter (async)
    let redis_url = std::env::var("REDIS_URL").ok();
    let rate_limiter = rt.block_on(async {
        RateLimiter::new(redis_url).await
    });
    let rate_limiter = Arc::new(rate_limiter);
    
    // 8. Setup WASM Plugin Manager
    let plugins_dir = config.wasm.plugins_dir.to_string_lossy().to_string();
    let wasm_manager = WasmPluginManager::new(&plugins_dir)
        .unwrap_or_else(|e| {
            warn!("Failed to init WASM manager: {}. Using stub.", e);
            Arc::new(WasmPluginManager::stub())
        });

    // 9. Setup Threat Intel Client
    let threat_client = Arc::new(ThreatIntelClient::new(config.threat_intel.clone()));
    
    // 10. Setup ML Engine
    let ml_engine = if config.ml.enabled {
        let model_path = config.ml.model_path.to_string_lossy();
        let scaler_path = config.ml.scaler_path.to_string_lossy();
        
        match MLInferenceEngine::new(&model_path, &scaler_path, config.ml.threshold) {
             Ok(engine) => Some(Arc::new(engine)),
             Err(e) => {
                 warn!("Failed to init ML Engine: {}. ML features disabled.", e);
                 None
             }
        }
    } else {
        None
    };

    // Threat Classifier (always available)
    let threat_classifier = {
        let classifier = waf_killer_core::ml::classification::ThreatClassifier::load(&config.ml.classifier_model_path);
        Some(Arc::new(classifier))
    };
    let explainability_engine = Some(Arc::new(waf_killer_core::ml::explainability::ExplainabilityEngine::new()));

    // 11. Setup Shared State and Admin API
    let shared_state = Arc::new(SharedState::new());
    let config_arc = Arc::new(config.clone());
    let config_swap = Arc::new(ArcSwap::new(config_arc.clone()));
    let vuln_manager = Arc::new(VulnerabilityManager::new());
    
    // 11. Setup Shared State and Admin API
    let shared_state = Arc::new(SharedState::new());
    let config_arc = Arc::new(config.clone());
    let config_swap = Arc::new(ArcSwap::new(config_arc.clone()));
    let vuln_manager = Arc::new(VulnerabilityManager::new());
    
    // API Protection & Enterprise State
    let api_protection_state = Arc::new(waf_killer_core::api_protection::state::ApiProtectionState::default());
    let tenant_store = Arc::new(waf_killer_core::tenancy::store::TenantStore::new());
    let bot_stats = Arc::new(waf_killer_core::botdetection::BotDetectionStats::default());
    let bot_config = Arc::new(tokio::sync::RwLock::new(waf_killer_core::botdetection::BotDetectionConfig::default()));

    // 12. Setup Shared Components
    let endpoint_discovery = Arc::new(EndpointDiscovery::new());
    let virtual_patch_store = waf_killer_core::api::virtual_patches::VirtualPatchStore::new();

    let waf_state = Arc::new(WafState::new(
        config_swap.clone(),
        Path::new(&args.config).to_path_buf(),
        rule_engine.clone(),
        shared_state.clone(),
        Some(wasm_manager.clone()),
        Some(threat_client.clone()),
        ml_engine.clone(),
        threat_classifier.clone(),
        vuln_manager.clone(),
        api_protection_state.clone(),
        tenant_store.clone(),
        bot_stats.clone(),
        bot_config.clone(),
        None, // Feedback manager
        endpoint_discovery.clone(),
        virtual_patch_store.clone(),
        None, // db_pool
    ));

    let admin_port = args.admin_port;
    
    // Spawn Admin API in a dedicated thread to avoid runtime conflicts with Pingora
    std::thread::spawn(move || {
        let admin_rt = tokio::runtime::Runtime::new().unwrap();
        admin_rt.block_on(start_admin_server(waf_state, admin_port));
    });
    info!("🛠️  Admin API spawned on port {}", admin_port);
    
    // Drop the init runtime to free resources and avoid interference
    drop(rt);

    // 10. Setup Proxy Service
    let rule_engine_snapshot = rule_engine.load_full();

    let mut waf_proxy = pingora::proxy::http_proxy_service(
        &server.configuration,
        WafProxy {
            config: config_swap,
            rule_engine: rule_engine_snapshot,
            bot_detector: bot_detector.clone(),
            rate_limiter,
            wasm_manager,
            shared: shared_state.clone(),
            ml_engine: ml_engine.clone(),

            threat_client: Some(threat_client.clone()),
            feedback_manager: None,
            traffic_tracker: waf_killer_core::traffic_stats::TrafficStatsTracker::new(),
            endpoint_discovery: endpoint_discovery.clone(),
            // Missing Fields
            openapi_validator: None,
            graphql_parser: None,
            graphql_depth_analyzer: None,
            graphql_complexity_scorer: None,
            graphql_authorizer: None,
            graphql_rate_limiter: None,
            graphql_schema: None,
            api_protection_enabled: config.api_protection.enabled,
            threat_classifier: threat_classifier.clone(),
            explainability_engine: explainability_engine.clone(),
        },
    );
    
    // Configure Listener
    let addr = format!("0.0.0.0:{}", config.server.http_port);
    info!("Listening on {} (HTTP)", addr);
    waf_proxy.add_tcp(&addr);
    
    server.add_service(waf_proxy);
    
    info!("WAF Killer started successfully!");
    info!("Backend URL: {}", config.upstream.backend_url);
    info!("Admin API: http://0.0.0.0:{}", admin_port);
    
    server.run_forever();
}
