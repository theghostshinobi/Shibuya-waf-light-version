// cli/src/commands/team.rs

use clap::{Args, Subcommand};
use anyhow::Result;
use comfy_table::Table;
use crate::commands::api::ApiClient;

#[derive(Args)]
pub struct TeamArgs {
    #[command(subcommand)]
    pub command: TeamSubcommand,
}

#[derive(Subcommand)]
pub enum TeamSubcommand {
    /// List team members
    List,
    /// Invite a new member
    Invite {
        #[arg(long)]
        email: String,
        #[arg(long, default_value = "Viewer")]
        role: String,
    },
    /// Remove a team member
    Remove {
        #[arg(long)]
        id: String,
    },
}

pub async fn handle_team_command(client: &ApiClient, args: TeamArgs) -> Result<()> {
    match args.command {
        TeamSubcommand::List => {
            let members: Vec<serde_json::Value> = client.get("/api/team").await?;
            let mut table = Table::new();
            table.set_header(vec!["ID", "Name", "Email", "Role"]);
            for m in members {
                table.add_row(vec![
                    m["id"].as_str().unwrap_or("N/A"),
                    m["name"].as_str().unwrap_or("N/A"),
                    m["email"].as_str().unwrap_or("N/A"),
                    m["role"].as_str().unwrap_or("N/A"),
                ]);
            }
            println!("{}", table);
        }
        TeamSubcommand::Invite { email, role } => {
            let payload = serde_json::json!({ "email": email, "role": role });
            let _: serde_json::Value = client.post("/api/team/invite", payload).await?;
            println!("Invitation sent to {} with role {}.", email, role);
        }
        TeamSubcommand::Remove { id } => {
            client.delete(&format!("/api/team/{}", id)).await?;
            println!("Member {} removed.", id);
        }
    }
    Ok(())
}
