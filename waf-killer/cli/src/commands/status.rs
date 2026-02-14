// ============================================
// File: cli/src/commands/status.rs
// ============================================
//! Episode 7: WAF Status Command
//!
//! Calls GET /health on Admin API and displays status with colors.

use anyhow::{Context, Result};
use colored::Colorize;
use serde::Deserialize;

const ADMIN_API_URL: &str = "http://127.0.0.1:9090";

#[derive(Deserialize)]
struct HealthResponse {
    status: String,
    version: String,
    uptime_seconds: u64,
    uptime_human: String,
    components: ComponentHealth,
}

#[derive(Deserialize)]
struct ComponentHealth {
    proxy: String,
    rule_engine: String,
    rate_limiter: String,
    bot_detector: String,
    wasm_plugins: String,
}

pub async fn run() -> Result<()> {
    println!();
    println!("{}", "╔═══════════════════════════════════════════════════╗".bright_red().bold());
    println!("{}", "║         🔥 WAF KILLER - STATUS CHECK 🔥           ║".bright_red().bold());
    println!("{}", "╚═══════════════════════════════════════════════════╝".bright_red().bold());
    println!();

    let url = format!("{}/health", ADMIN_API_URL);
    
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;

    match client.get(&url).send().await {
        Ok(response) => {
            if response.status().is_success() {
                let health: HealthResponse = response.json().await
                    .context("Failed to parse health response")?;
                
                print_health(&health);
            } else {
                println!("  {} WAF responded with error: {}", 
                    "✗".red().bold(), 
                    response.status().to_string().red()
                );
            }
        }
        Err(e) => {
            println!("  {} {}", "STATUS:".bright_white().bold(), "OFFLINE".red().bold());
            println!();
            println!("  {} Could not connect to WAF Admin API", "⚠".yellow().bold());
            println!("    URL: {}", url.dimmed());
            println!("    Error: {}", e.to_string().dimmed());
            println!();
            println!("  {} {}", "TIP:".yellow(), "Make sure waf-killer-core is running");
            println!("       Start with: cargo run -p waf-killer-core");
        }
    }

    println!();
    Ok(())
}

fn print_health(health: &HealthResponse) {
    // Status
    let status_color = if health.status.contains("OPERATIONAL") {
        "🟢 OPERATIONAL".green().bold()
    } else {
        "🔴 DEGRADED".red().bold()
    };
    
    println!("  {} {}", "STATUS:".bright_white().bold(), status_color);
    println!("  {} {}", "VERSION:".bright_white().bold(), health.version.cyan());
    println!("  {} {}", "UPTIME:".bright_white().bold(), health.uptime_human.yellow());
    println!();
    
    // Components
    println!("  {}", "COMPONENTS:".bright_white().bold());
    print_component("  Proxy", &health.components.proxy);
    print_component("  Rule Engine", &health.components.rule_engine);
    print_component("  Rate Limiter", &health.components.rate_limiter);
    print_component("  Bot Detector", &health.components.bot_detector);
    print_component("  WASM Plugins", &health.components.wasm_plugins);
}

fn print_component(name: &str, status: &str) {
    let indicator = if status.contains("✓") || status.contains("ACTIVE") || status.contains("LOADED") || status.contains("READY") {
        "●".green()
    } else {
        "●".red()
    };
    
    println!("    {} {} {}", indicator, name.bright_white(), status.dimmed());
}
