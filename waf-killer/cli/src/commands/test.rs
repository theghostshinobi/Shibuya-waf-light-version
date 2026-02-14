use anyhow::Result;
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;
use crate::client::grpc::{connect, TestPayloadRequest};

pub async fn run(payload: &str, method: &str, path: &str, verbose: bool) -> Result<()> {
    let mut client = connect("http://127.0.0.1:9091".to_string()).await?;
    
    println!("{}", "🧪 Testing payload...".cyan());
    println!();
    println!("  Method: {}", method.bold());
    println!("  Path: {}", path.bold());
    println!("  Payload: {}", payload.yellow());
    println!();
    
    let spinner = ProgressBar::new_spinner();
    spinner.set_message("Running through rule engine...");
    spinner.enable_steady_tick(Duration::from_millis(100));
    
    let response = client.test_payload(TestPayloadRequest {
        method: method.to_string(),
        path: path.to_string(),
        payload: payload.to_string(),
    }).await?;
    
    let result = response.into_inner();
    
    spinner.finish_and_clear();
    
    // Print result
    if result.action == "BLOCK" {
        println!("{}", "❌ BLOCKED".red().bold());
    } else {
        println!("{}", "✅ ALLOWED".green().bold());
    }
    
    println!();
    println!("  CRS Score: {}", result.crs_score);
    println!("  ML Anomaly Score: {:.2}", result.ml_anomaly_score);
    
    if let Some(classification) = result.ml_classification {
        println!("  ML Classification: {} ({:.0}% confidence)", 
                 classification.predicted_class.bold(),
                 classification.confidence * 100.0);
    }
    
    println!("  Combined Score: {}", result.combined_score);
    println!("  Threshold: {}", result.threshold);
    println!();
    
    // Show matched rules
    if !result.rules_matched.is_empty() {
        println!("{}", "Matched Rules:".bold());
        for rule in result.rules_matched {
            println!("  -  #{} - {} (score: +{})", 
                     rule.id.to_string().cyan(),
                     rule.msg,
                     rule.score_delta);
        }
        println!();
    }
    
    // Show reasoning
    if verbose {
        println!("{}", "Reasoning:".bold());
        println!("  {}", result.reasoning);
    }
    
    Ok(())
}
