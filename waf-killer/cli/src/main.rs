use clap::{Parser, Subcommand};
use std::path::PathBuf;
use anyhow::Result;

pub mod commands;
pub mod client;
pub mod config;
pub mod ui;

#[derive(Parser)]
#[command(name = "waf")]
#[command(about = "WAF Killer - The modern Web Application Firewall", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    
    /// Config file path
    #[arg(short, long, default_value = "/etc/waf/waf.yaml")]
    config: PathBuf,
    
    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize WAF (interactive setup wizard)
    Init {
        /// Skip interactive prompts, use defaults
        #[arg(long)]
        non_interactive: bool,
    },
    
    /// Start WAF daemon
    Start {
        /// Run in foreground (don't daemonize)
        #[arg(short, long)]
        foreground: bool,
    },
    
    /// Stop WAF daemon
    Stop,
    
    /// Show WAF status
    Status,
    
    /// Tail WAF logs
    Logs {
        /// Follow logs in real-time
        #[arg(short, long)]
        follow: bool,
        
        /// Filter by level (info/warn/error)
        #[arg(long)]
        level: Option<String>,
        
        /// Filter by request ID
        #[arg(long)]
        request_id: Option<String>,
        
        /// Number of lines to show
        #[arg(short, long, default_value = "100")]
        lines: usize,
    },
    
    /// Manage rules
    Rules {
        #[command(subcommand)]
        action: RuleAction,
    },
    
    /// Test a payload against rules
    Test {
        /// Payload to test
        payload: String,
        
        /// HTTP method
        #[arg(short, long, default_value = "GET")]
        method: String,
        
        /// URL path
        #[arg(short, long, default_value = "/")]
        path: String,
        
        /// Show matched rules
        #[arg(long)]
        verbose: bool,
    },
    
    /// Deploy WAF to cloud
    Deploy {
        #[command(subcommand)]
        platform: DeployPlatform,
    },
    
    /// Manage shadow mode
    Shadow {
        #[command(subcommand)]
        action: ShadowAction,
    },
    
    /// Replay captured traffic with new policy
    Replay {
        #[command(subcommand)]
        action: ReplayAction,
    },
    
    /*
    /// Show statistics
    Stats {
        /// Time range (1h, 24h, 7d)
        #[arg(long, default_value = "1h")]
        range: String,
        
        /// Refresh interval
        #[arg(long)]
        watch: bool,
    },
    */
    
    /// Generate shell completions
    Completions {
        /// Shell (bash/zsh/fish)
        shell: String,
    },
    
    /*
    /// Manage policies (git-based configuration)
    Policy {
        #[command(subcommand)]
        command: commands::policy::PolicyCommands,
    },
    */
    
    /// Manage API protection
    Api {
        #[command(subcommand)]
        command: commands::api::ApiCommands,
    },
    
    /// Manage GraphQL protection
    GraphQl {
        #[command(subcommand)]
        command: commands::graphql::GraphQlCommands,
    },
    
    /// Manage team members
    Team(commands::team::TeamArgs),
    
    /// Manage tenant settings
    Tenant(commands::tenant::TenantArgs),

    /// Integrated security scanning
    Scan {
        #[command(subcommand)]
        action: commands::scan::ScanAction,
    },

    /// Virtual patching management
    Patch {
        #[command(subcommand)]
        action: commands::patch::PatchAction,
    },

    /// Reload WAF rules (hot-reload)
    Reload,

    /// Check eBPF support status
    CheckEbpf,
}

#[derive(Subcommand)]
pub enum RuleAction {
    /// List all rules
    List {
        /// Filter by category
        #[arg(long)]
        category: Option<String>,
        
        /// Show disabled rules
        #[arg(long)]
        all: bool,
    },
    
    /// Show rule details
    Show {
        /// Rule ID
        id: u32,
    },
    
    /// Test a rule
    Test {
        /// Rule ID
        id: u32,
        
        /// Payload to test
        payload: String,
    },
    
    /// Enable a rule
    Enable {
        /// Rule ID(s)
        ids: Vec<u32>,
    },
    
    /// Disable a rule
    Disable {
        /// Rule ID(s)
        ids: Vec<u32>,
    },
}

#[derive(Subcommand)]
pub enum DeployPlatform {
    /// Deploy to Fly.io
    Fly,
    
    /// Deploy to Railway
    Railway,
    
    /// Deploy to Cloudflare Workers (ironic)
    CloudflareWorkers,
}

#[derive(Subcommand)]
pub enum ShadowAction {
    /// Enable shadow mode
    Enable {
        /// Percentage of traffic to shadow (1-100)
        #[arg(long, default_value = "10")]
        percentage: u8,
        
        /// Duration (e.g., "24h", "7d")
        #[arg(long)]
        duration: Option<String>,
        
        /// Policy file to shadow
        #[arg(long)]
        policy: PathBuf,
    },
    
    /// Disable shadow mode
    Disable,
    
    /// Show shadow mode status
    Status,
    
    /// Show shadow mode diff summary
    Summary {
        /// Time range
        #[arg(long, default_value = "24h")]
        range: String,
    },
    
    /// Export shadow diffs to CSV
    Export {
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Subcommand)]
pub enum ReplayAction {
    /// Replay captured traffic with new policy
    Run {
        /// Policy file to test
        #[arg(long)]
        policy: PathBuf,
        
        /// Start time (e.g., "2026-01-24T00:00:00Z")
        #[arg(long)]
        from: String,
        
        /// End time
        #[arg(long)]
        to: String,
        
        /// Export report to file
        #[arg(long)]
        output: Option<PathBuf>,
    },
    
    /// Show captured traffic stats
    Stats,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    // Setup logging usually happens here, but maybe we assume simple stdout for CLI tool
    
    match cli.command {
        Commands::Init { non_interactive } => {
            commands::init::run(non_interactive).await?;
        },
        Commands::Start { foreground } => {
            commands::start::run(foreground, &cli.config).await?;
        },
        Commands::Stop => {
            commands::stop::run().await?;
        },
        Commands::Status => {
            commands::status::run().await?;
        },
        Commands::Logs { follow, level, request_id, lines } => {
            commands::logs::run(follow, level, request_id, lines).await?;
        },
        Commands::Rules { action } => {
            commands::rules::run(action).await?;
        },
        Commands::Test { payload, method, path, verbose } => {
            commands::test::run(&payload, &method, &path, verbose).await?;
        },
        Commands::Deploy { platform } => {
            commands::deploy::run(platform).await?;
        },
        Commands::Shadow { action } => {
            commands::shadow::run(action).await?;
        },
        Commands::Replay { action } => {
            commands::replay::run(action).await?;
        },
        /*
        Commands::Stats { range, watch } => {
            commands::stats::run(&range, watch).await?;
        },
        */
        Commands::Completions { shell } => {
            commands::completions::run(&shell)?;
        },
        /*
        Commands::Policy { command } => {
            // Default address for now, should be Config
            let addr = "http://127.0.0.1:9091".to_string(); 
            commands::policy::handle_policy_command(command, addr).await?;
        },
        */
        Commands::Api { command } => {
            commands::api::handle_command(commands::api::ApiArgs { command }).await?;
        },
        Commands::GraphQl { command } => {
            commands::graphql::handle_command(commands::graphql::GraphQlArgs { command }).await?;
        },
        Commands::Team(args) => {
            let client = commands::api::ApiClient::new("http://127.0.0.1:9091".to_string());
            commands::team::handle_team_command(&client, args).await?;
        },
        Commands::Tenant(args) => {
            let client = commands::api::ApiClient::new("http://127.0.0.1:9091".to_string());
            commands::tenant::handle_tenant_command(&client, args).await?;
        },
        Commands::Scan { action } => {
            commands::scan::run(action).await?;
        },
        Commands::Patch { action } => {
            commands::patch::run(action).await?;
        },
        Commands::Reload => {
            commands::reload::run().await?;
        },
        Commands::CheckEbpf => {
            let os = std::env::consts::OS;
            println!("  Operating System: {}", os);
            
            if os == "linux" {
                println!("  eBPF Platform Support: ✅ YES");
                println!("  Kernel Version: (Check via 'uname -r')");
                println!("  Status: Userspace fallback acts as backup.");
            } else {
                println!("  eBPF Platform Support: ❌ NO (Linux only)");
                println!("  Status: Using userspace active protection (Full Security).");
                println!("  Note: eBPF is an optional performance optimization.");
            }
        },
    }
    
    Ok(())
}
