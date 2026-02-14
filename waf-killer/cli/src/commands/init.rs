use anyhow::Result;
use colored::Colorize;
use dialoguer::{Input, Select, Confirm};
use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;
use crate::config::templates::*;

pub async fn run(non_interactive: bool) -> Result<()> {
    println!("{}", "🔥 WAF Killer - Interactive Setup".bold().cyan());
    println!();
    
    if non_interactive {
        println!("Running in non-interactive mode. Using defaults.");
        let config = WafConfig {
            server: ServerConfig {
                listen: ListenConfig { host: "0.0.0.0".to_string(), port: 8443 },
                tls: TlsConfig { enabled: true, cert_path: "certs/server.crt".to_string(), key_path: "certs/server.key".to_string() },
                shutdown_timeout: "20s".to_string(),
            },
            upstream: UpstreamConfig {
                host: "localhost".to_string(), port: 8080, scheme: "http".to_string(),
                pool: PoolConfig { min_connections: 10, max_connections: 100, idle_timeout: "90s".to_string(), connection_timeout: "5s".to_string() },
                health_check: HealthCheckConfig { enabled: true, path: "/health".to_string(), interval: "10s".to_string(), timeout: "5s".to_string(), unhealthy_threshold: 3 },
            },
            telemetry: TelemetryConfig { log_level: "info".to_string(), log_format: "text".to_string(), metrics_enabled: true, metrics_port: 9090 },
            rule_engine: RuleEngineConfig {
                enabled: true, mode: "blocking".to_string(), crs_path: "rules/coreruleset".to_string(), custom_rules_path: "rules/custom".to_string(),
                paranoia_level: 1, inbound_threshold: 5, outbound_threshold: 100,
            },
            ml: MlConfig {
                 enabled: true,
                 anomaly_detection: AnomalyDetectionConfig { model_path: "ml/models/anomaly_v1.onnx".to_string(), threshold: 0.8, score_contribution: ScoreContributionConfig::default() },
                 classification: ClassificationConfig { enabled: true, model_path: "ml/models/classifier_v1.onnx".to_string(), confidence_threshold: 0.9, score_contribution: ScoreContributionConfig::default(), severity_multiplier: SeverityMultiplierConfig::default() },
                 ..Default::default()
            },
        };
        
        std::fs::create_dir_all("config")?;
        let yaml = serde_yaml::to_string(&config)?;
        std::fs::write("config/waf.yaml", yaml)?;
        println!("✓ Configuration saved to config/waf.yaml");
        return Ok(()); 
    }
    
    // Step 1: Basic config
    println!("{}", "Step 1: Basic Configuration".bold());
    
    let listen_port: u16 = Input::new()
        .with_prompt("Listen port for WAF")
        .default(8443)
        .interact()?;
    
    let upstream_host: String = Input::new()
        .with_prompt("Upstream backend host")
        .default("localhost".to_string())
        .interact()?;
    
    let upstream_port: u16 = Input::new()
        .with_prompt("Upstream backend port")
        .default(8080)
        .interact()?;
        
    let upstream_scheme = Select::new()
        .with_prompt("Upstream protocol")
        .items(&["http", "https"])
        .default(0)
        .interact()?;
        
    let scheme = if upstream_scheme == 0 { "http" } else { "https" };

    // Step 2: TLS setup
    println!();
    println!("{}", "Step 2: TLS Certificate".bold());
    
    let tls_options = vec![
        "Generate self-signed certificate (dev only)",
        "Use existing certificate",
        "Disable TLS (HTTP only)",
    ];
    
    let tls_choice = Select::new()
        .with_prompt("TLS certificate source")
        .items(&tls_options)
        .default(0)
        .interact()?;
    
    let (tls_enabled, cert_path, key_path) = match tls_choice {
        0 => (true, "certs/server.crt".to_string(), "certs/server.key".to_string()),
        1 => {
            let certa: String = Input::new().with_prompt("Path to certificate").interact()?;
            let keya: String = Input::new().with_prompt("Path to private key").interact()?;
            (true, certa, keya)
        },
        2 => (false, "".to_string(), "".to_string()),
        _ => unreachable!(),
    };
    
    // Step 3: Rule engine config
    println!();
    println!("{}", "Step 3: Rule Engine".bold());
    
    let enable_crs = Confirm::new()
        .with_prompt("Enable OWASP Core Rule Set?")
        .default(true)
        .interact()?;
    
    let paranoia_level: u8 = if enable_crs {
        Select::new()
            .with_prompt("Paranoia level")
            .items(&["1 (recommended)", "2 (strict)", "3 (paranoid)", "4 (extreme)"])
            .default(0)
            .interact()? as u8 + 1
    } else {
        1
    };
    
    let anomaly_threshold: i32 = Input::new()
        .with_prompt("Anomaly score threshold (5 recommended)")
        .default(5)
        .interact()?;
        
    let engine_mode = Select::new()
        .with_prompt("Engine Mode")
        .items(&["blocking", "detection"])
        .default(0)
        .interact()?;
    let mode_str = if engine_mode == 0 { "blocking" } else { "detection" };

    // Step 4: ML config (Simplified for this stub)
    println!();
    println!("{}", "Step 4: Machine Learning".bold());
    let enable_ml = Confirm::new()
        .with_prompt("Enable ML-based detection?")
        .default(true)
        .interact()?;

    // Step 6: Generate config (Writing)
    println!();
    println!("{}", "Step 5: Generating Configuration".bold());
    
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.cyan} {msg}")
            .unwrap()
    );
    spinner.set_message("Generating config...");
    spinner.enable_steady_tick(Duration::from_millis(100));
    
    // Construct config object
    let config = WafConfig {
        server: ServerConfig {
            listen: ListenConfig {
                host: "0.0.0.0".to_string(),
                port: listen_port,
            },
            tls: TlsConfig {
                enabled: tls_enabled,
                cert_path,
                key_path,
            },
            shutdown_timeout: "20s".to_string(),
        },
        upstream: UpstreamConfig {
            host: upstream_host,
            port: upstream_port,
            scheme: scheme.to_string(),
            pool: PoolConfig {
                min_connections: 10,
                max_connections: 100,
                idle_timeout: "90s".to_string(),
                connection_timeout: "5s".to_string(),
            },
            health_check: HealthCheckConfig {
                enabled: true,
                path: "/health".to_string(),
                interval: "10s".to_string(),
                timeout: "5s".to_string(),
                unhealthy_threshold: 3,
            },
        },
        telemetry: TelemetryConfig {
            log_level: "info".to_string(),
            log_format: "text".to_string(),
            metrics_enabled: true,
            metrics_port: 9090, // Separate metrics port
        },
        rule_engine: RuleEngineConfig {
            enabled: enable_crs,
            mode: mode_str.to_string(),
            crs_path: "rules/coreruleset".to_string(), // Default location
            custom_rules_path: "rules/custom".to_string(),
            paranoia_level,
            inbound_threshold: anomaly_threshold,
            outbound_threshold: 100,
        },
        ml: MlConfig {
            enabled: enable_ml,
            anomaly_detection: AnomalyDetectionConfig {
                model_path: "ml/models/anomaly_v1.onnx".to_string(),
                threshold: 0.8,
                score_contribution: ScoreContributionConfig { high: 5, medium: 3, low: 1 },
            },
            classification: ClassificationConfig {
                enabled: true,
                model_path: "ml/models/classifier_v1.onnx".to_string(),
                confidence_threshold: 0.9,
                score_contribution: ScoreContributionConfig { high: 10, medium: 5, low: 1 },
                severity_multiplier: SeverityMultiplierConfig { critical: 2.0, error: 1.5, warning: 1.0 },
            },
            ..Default::default() // use other defaults
        }
    };
    
    // Write config
    let config_path = "/etc/waf/waf.yaml";
    // Check if we have permission or just write to local config/waf.yaml for dev
    let local_path = "config/waf.yaml";
    std::fs::create_dir_all("config")?;
    
    let yaml = serde_yaml::to_string(&config)?;
    std::fs::write("config/waf.yaml", yaml)?;
    
    // Also try writing to /etc/waf/waf.yaml if sudo, but fail gracefully
    // ...
    
    spinner.finish_with_message("✓ Configuration saved to config/waf.yaml".green().to_string());
    
    if tls_choice == 0 {
        // Generate self-signed certs
        // Assuming openssl is installed or using rustls implementation
        // For now, stub it.
        println!("⚠️  Self-signed cert generation skipped in this prototype.");
    }

    Ok(())
}
