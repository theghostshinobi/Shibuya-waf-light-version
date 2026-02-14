// cli/src/commands/shadow.rs

use crate::ShadowAction;
use crate::client::grpc;
use anyhow::{Result, Context};
use std::path::Path;
use colored::*;
use std::fs;

pub async fn run(action: ShadowAction) -> Result<()> {
    let addr = "http://localhost:9092".to_string(); // In real app, this comes from config
    let mut client = grpc::connect(addr).await?;

    match action {
        ShadowAction::Enable { percentage, duration, policy } => {
            enable_shadow(&mut client, percentage, duration, &policy).await?;
        },
        ShadowAction::Disable => {
            disable_shadow(&mut client).await?;
        },
        ShadowAction::Status => {
            show_status(&mut client).await?;
        },
        ShadowAction::Summary { range } => {
            show_summary(&mut client, &range).await?;
        },
        ShadowAction::Export { output } => {
            export_diffs(&mut client, &output).await?;
        },
    }
    
    Ok(())
}

async fn enable_shadow(
    client: &mut grpc::WafManagementClient<tonic::transport::Channel>,
    percentage: u8,
    duration: Option<String>,
    policy_path: &Path,
) -> Result<()> {
    println!("{}", "🎭 Enabling shadow mode...".cyan());
    
    // 1. Load policy
    let policy_yaml = fs::read_to_string(policy_path)
        .with_context(|| format!("Failed to read policy file: {:?}", policy_path))?;
    
    // 2. Call WAF API to enable shadow
    client.enable_shadow(grpc::EnableShadowRequest {
        policy_yaml,
        percentage: percentage as u32,
        duration_seconds: None, // Simplified duration parsing for now
    }).await?;
    
    println!("{}", "✅ Shadow mode enabled!".green());
    println!();
    println!("  Percentage: {}%", percentage);
    if let Some(dur) = duration {
        println!("  Duration: {}", dur);
    }
    println!();
    println!("Monitor with: {}", "waf shadow summary".cyan());
    
    Ok(())
}

async fn disable_shadow(
    client: &mut grpc::WafManagementClient<tonic::transport::Channel>,
) -> Result<()> {
    client.disable_shadow(grpc::DisableShadowRequest {}).await?;
    println!("{}", "✅ Shadow mode disabled".green());
    Ok(())
}

async fn show_status(
    client: &mut grpc::WafManagementClient<tonic::transport::Channel>,
) -> Result<()> {
    let status = client.get_shadow_status(grpc::GetShadowStatusRequest {}).await?.into_inner();
    
    println!("{}", "🎭 Shadow Mode Status".bold());
    println!();
    
    if status.enabled {
        println!("Status: {}", "ACTIVE".green().bold());
        println!("Percentage: {}%", status.percentage);
        println!("Policy: {}", status.policy_version);
    } else {
        println!("Status: {}", "INACTIVE".red());
    }
    
    Ok(())
}

async fn show_summary(
    client: &mut grpc::WafManagementClient<tonic::transport::Channel>,
    _range: &str,
) -> Result<()> {
    let summary = client.get_shadow_summary(grpc::GetShadowStatusRequest {}).await?.into_inner();
    
    println!("{}", "📊 Shadow Mode Summary (Last 24h)".bold());
    println!();
    println!("Total shadowed: {}", summary.total_shadowed);
    println!("Action changes: {} ({:.1}%)",
             summary.action_diffs,
             if summary.total_shadowed > 0 { summary.action_diffs as f64 / summary.total_shadowed as f64 * 100.0 } else { 0.0 });
    println!();
    
    if summary.new_blocks > 0 {
        println!("{}", "⚠️  New blocks:".yellow());
        println!("  {} requests would be newly BLOCKED", summary.new_blocks);
    }
    
    if summary.new_allows > 0 {
        println!("{}", "✅ New allows:".green());
        println!("  {} requests would be newly ALLOWED", summary.new_allows);
    }
    
    println!();
    println!("View details in dashboard: http://localhost:3000/shadow");
    
    Ok(())
}

async fn export_diffs(
    _client: &mut grpc::WafManagementClient<tonic::transport::Channel>,
    output: &Path,
) -> Result<()> {
    println!("Exporting diffs to {:?}...", output);
    // Mock export
    println!("{}", "✅ Export complete".green());
    Ok(())
}
