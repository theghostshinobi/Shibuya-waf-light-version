use anyhow::{Result, Context};
use clap::Subcommand;
use std::path::PathBuf;
use colored::*;
use indicatif::ProgressBar;
use std::time::Duration;

use crate::client::grpc::connect;
use crate::client::grpc::proto::waf_management_client::WafManagementClient; 
use crate::client::grpc::proto::{ApplyPolicyRequest, SimulatePolicyRequest};
use tonic::transport::Channel;

use waf_killer_core::config::policy_schema::Policy;
use waf_killer_core::policy::validator::{validate_against_schema, validate_semantic};

#[derive(Subcommand, Debug)]
pub enum PolicyCommands {
    /// Validate policy file locally
    Validate {
        /// Path to policy.yaml
        #[arg(short, long, default_value = "policy.yaml")]
        file: PathBuf,
    },
    
    /// Simulate policy on historical traffic
    Simulate {
        /// Path to policy.yaml
        #[arg(short, long)]
        file: PathBuf,
        
        /// Time range (e.g., "24h", "7d")
        #[arg(long, default_value = "24h")]
        range: String,
    },
    
    /// Apply policy (deploy to WAF)
    Apply {
        /// Path to policy.yaml
        #[arg(short, long)]
        file: PathBuf,
        
        /// Dry-run (validate + simulate only)
        #[arg(long)]
        dry_run: bool,
    },
    
    /// Show current active policy (Not implemented in this episode)
    Show,
}

pub async fn handle_policy_command(cmd: PolicyCommands, client_addr: String) -> Result<()> {
    match cmd {
        PolicyCommands::Validate { file } => {
            validate_command(&file).await?;
        },
        PolicyCommands::Simulate { file, range } => {
            simulate_command(&file, &range, client_addr).await?;
        },
        PolicyCommands::Apply { file, dry_run } => {
            apply_command(&file, dry_run, client_addr).await?;
        },
        PolicyCommands::Show => {
            println!("Show policy not implemented yet.");
        }
    }
    Ok(())
}

async fn validate_command(file: &PathBuf) -> Result<()> {
    println!("{}", "🔍 Validating policy...".cyan());
    
    // Load policy
    let content = std::fs::read_to_string(file)
        .context(format!("Failed to read policy file: {:?}", file))?;
        
    let policy: Policy = serde_yaml::from_str(&content)
        .context("Failed to parse YAML")?;
    
    // Validate
    if let Err(e) = validate_against_schema(&policy) {
        eprintln!("{}", "❌ JSON Schema Validation failed".red());
        eprintln!("{}", e);
        std::process::exit(1);
    }
    
    if let Err(e) = validate_semantic(&policy) {
        eprintln!("{}", "❌ Semantic Validation failed".red());
        eprintln!("{}", e);
        std::process::exit(1);
    }
    
    println!("{}", "✅ Policy is valid!".green().bold());
    println!("  Name: {}", policy.metadata.name);
    println!("  Version: {}", policy.version);
    println!("  Environment: {}", policy.metadata.environment);
    
    Ok(())
}

async fn simulate_command(file: &PathBuf, range: &str, client_addr: String) -> Result<()> {
    println!("{}", "🎭 Simulating policy on historical traffic...".cyan());
    
    let content = std::fs::read_to_string(file)?;
    
    // Validate locally first
    let policy: Policy = serde_yaml::from_str(&content)?;
    validate_against_schema(&policy)?;
    
    // Connect to client
    let mut client: WafManagementClient<Channel> = connect(client_addr).await?;
    
    let pb = ProgressBar::new_spinner();
    pb.enable_steady_tick(Duration::from_millis(120));
    pb.set_message("Running simulation on WAF...");
    
    let request = tonic::Request::new(SimulatePolicyRequest {
        policy_yaml: content,
        time_range: range.to_string(),
    });
    
    let response = client.simulate_policy(request).await?.into_inner();
    
    pb.finish_and_clear();
    
    println!("{}", "📊 Simulation Results".bold());
    println!("Total Requests: {}", response.total_requests);
    println!("True Positives: {}", response.true_positives.to_string().green());
    println!("True Negatives: {}", response.true_negatives);
    println!("New Blocks: {}", response.new_blocks.to_string().yellow());
    println!("New Allows: {}", response.new_allows.to_string().blue());
    
    // Warn on blocks
    if response.new_blocks > 0 {
         println!("\n{}", "⚠️  Warning: New policy would block previously allowed requests!".yellow());
    }
    
    Ok(())
}

async fn apply_command(file: &PathBuf, dry_run: bool, client_addr: String) -> Result<()> {
    let action = if dry_run { "Dry-run Applying" } else { "Applying" };
    println!("{} policy...", action.cyan());
    
    let content = std::fs::read_to_string(file)?;
    
    // Connect
    let mut client: WafManagementClient<Channel> = connect(client_addr).await?;
    
    let request = tonic::Request::new(ApplyPolicyRequest {
        policy_yaml: content,
        dry_run,
    });
    
    let response = client.apply_policy(request).await?.into_inner();
    
    if response.success {
        println!("{}", response.message.green().bold());
        if !response.version.is_empty() {
            println!("Applied Version: {}", response.version);
        }
    } else {
        println!("{}", "❌ Failed to apply policy".red().bold());
        println!("Message: {}", response.message);
        for error in response.validation_errors {
            println!("  - {}", error);
        }
        std::process::exit(1);
    }
    
    Ok(())
}
