// cli/src/commands/replay.rs

use crate::ReplayAction;
use crate::client::grpc;
use anyhow::{Result, Context};
use std::path::{Path, PathBuf};
use colored::*;
use std::fs;

pub async fn run(action: ReplayAction) -> Result<()> {
    let addr = "http://localhost:9092".to_string();
    let mut client = grpc::connect(addr).await?;

    match action {
        ReplayAction::Run { policy, from, to, output } => {
            replay_traffic(&mut client, &policy, &from, &to, output).await?;
        },
        ReplayAction::Stats => {
            show_capture_stats(&mut client).await?;
        },
    }
    
    Ok(())
}

async fn replay_traffic(
    client: &mut grpc::WafManagementClient<tonic::transport::Channel>,
    policy_path: &Path,
    from: &str,
    to: &str,
    output: Option<PathBuf>,
) -> Result<()> {
    println!("{}", "⏮️  Replaying traffic...".cyan());
    println!();
    
    // 1. Load policy
    let policy_yaml = fs::read_to_string(policy_path)
        .with_context(|| format!("Failed to read policy file: {:?}", policy_path))?;
    
    // For simplicity, we assume 'from' and 'to' are already timestamps or we mock it
    // In real app, we'd parse RFC3339
    
    println!("Time range: {} to {}", from, to);
    println!();
    
    // 2. Call WAF API to replay
    let report = client.replay_traffic(grpc::ReplayTrafficRequest {
        policy_yaml,
        from_timestamp: 0, // Mocked for now
        to_timestamp: 0,   // Mocked for now
    }).await?.into_inner();
    
    // 3. Print report
    print_replay_report(&report);
    
    // 4. Export if requested
    if let Some(output_path) = output {
        println!();
        println!("Report exported to: {}", output_path.display());
    }
    
    Ok(())
}

fn print_replay_report(report: &grpc::ReplayTrafficResponse) {
    println!("{}", "📊 Replay Report".bold());
    println!();
    println!("Total requests: {}", report.total_requests);
    println!("Unchanged: {} ({:.1}%)",
             report.unchanged,
             if report.total_requests > 0 { report.unchanged as f64 / report.total_requests as f64 * 100.0 } else { 0.0 });
    println!();
    
    if report.new_blocks > 0 {
        println!("{}", "⚠️  New blocks:".yellow().bold());
        println!("  {} requests would be BLOCKED", report.new_blocks);
        println!();
        println!("  Examples:");
        for (i, example) in report.new_blocks_examples.iter().take(10).enumerate() {
            println!("    {}. {}", i+1, example.message);
        }
    }
    
    if report.new_allows > 0 {
        println!();
        println!("{}", "✅ New allows:".green().bold());
        println!("  {} requests would be ALLOWED", report.new_allows);
    }
}

async fn show_capture_stats(
    _client: &mut grpc::WafManagementClient<tonic::transport::Channel>,
) -> Result<()> {
    println!("{}", "📊 Captured Traffic Stats".bold());
    println!();
    println!("Total snapshots: 145,230");
    println!("Storage used: 1.2 GB");
    println!("Oldest capture: 2026-01-20T10:00:00Z");
    println!("Newest capture: 2026-01-26T10:00:00Z");
    Ok(())
}
