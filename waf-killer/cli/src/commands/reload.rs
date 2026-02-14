// ============================================
// File: cli/src/commands/reload.rs
// ============================================
//! Episode 7: Rules Reload Command
//!
//! Triggers hot-reload of WAF rules via POST /rules/reload

use anyhow::{Context, Result};
use colored::Colorize;
use serde::Deserialize;

const ADMIN_API_URL: &str = "http://127.0.0.1:9090";

#[derive(Deserialize)]
struct ReloadResponse {
    success: bool,
    message: String,
    rules_loaded: usize,
}

pub async fn run() -> Result<()> {
    println!();
    println!("{}", "╔═══════════════════════════════════════════════════╗".bright_yellow().bold());
    println!("{}", "║         🔄 WAF KILLER - RULES RELOAD 🔄           ║".bright_yellow().bold());
    println!("{}", "╚═══════════════════════════════════════════════════╝".bright_yellow().bold());
    println!();

    let url = format!("{}/rules/reload", ADMIN_API_URL);
    
    println!("  {} Requesting rules reload...", "⏳".yellow());
    
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    match client.post(&url).send().await {
        Ok(response) => {
            if response.status().is_success() {
                let reload: ReloadResponse = response.json().await
                    .context("Failed to parse reload response")?;
                
                if reload.success {
                    println!();
                    println!("  {} {}", "✓".green().bold(), "Rules reloaded successfully!".green().bold());
                    println!();
                    println!("  {} {}", "RULES LOADED:".bright_white().bold(), 
                        reload.rules_loaded.to_string().cyan().bold());
                    println!("  {} {}", "MESSAGE:".bright_white().bold(), 
                        reload.message.dimmed());
                } else {
                    println!();
                    println!("  {} {}", "✗".red().bold(), "Reload failed!".red().bold());
                    println!("  {} {}", "ERROR:".bright_white().bold(), 
                        reload.message.red());
                }
            } else {
                println!("  {} WAF responded with error: {}", 
                    "✗".red().bold(), 
                    response.status().to_string().red()
                );
            }
        }
        Err(e) => {
            println!();
            println!("  {} {}", "✗".red().bold(), "Connection failed!".red().bold());
            println!();
            println!("  {} Could not connect to WAF Admin API", "⚠".yellow().bold());
            println!("    URL: {}", url.dimmed());
            println!("    Error: {}", e.to_string().dimmed());
            println!();
            println!("  {} {}", "TIP:".yellow(), "Make sure waf-killer-core is running");
        }
    }

    println!();
    Ok(())
}
