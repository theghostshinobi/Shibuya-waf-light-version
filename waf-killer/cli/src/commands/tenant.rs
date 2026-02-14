// cli/src/commands/tenant.rs

use clap::{Args, Subcommand};
use anyhow::Result;
use comfy_table::Table;
use crate::commands::api::ApiClient;

#[derive(Args)]
pub struct TenantArgs {
    #[command(subcommand)]
    pub command: TenantSubcommand,
}

#[derive(Subcommand)]
pub enum TenantSubcommand {
    /// List available tenants
    List,
    /// Get current tenant information
    Status,
    /// Create a new tenant
    Create {
        #[arg(long)]
        slug: String,
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "Free")]
        plan: String,
    },
}

pub async fn handle_tenant_command(client: &ApiClient, args: TenantArgs) -> Result<()> {
    match args.command {
        TenantSubcommand::List => {
            // Placeholder for listing tenants
            println!("Feature coming soon: Cross-tenant management.");
        }
        TenantSubcommand::Status => {
            let tenant: serde_json::Value = client.get("/api/tenant").await?;
            let mut table = Table::new();
            table.set_header(vec!["Property", "Value"]);
            table.add_row(vec!["ID", tenant["id"].as_str().unwrap_or("N/A")]);
            table.add_row(vec!["Slug", tenant["slug"].as_str().unwrap_or("N/A")]);
            table.add_row(vec!["Name", tenant["name"].as_str().unwrap_or("N/A")]);
            table.add_row(vec!["Plan", tenant["plan"].as_str().unwrap_or("N/A")]);
            println!("{}", table);
        }
        TenantSubcommand::Create { slug: _, name: _, plan: _ } => {
            println!("Tenant creation is currently restricted to the system admin.");
        }
    }
    Ok(())
}
