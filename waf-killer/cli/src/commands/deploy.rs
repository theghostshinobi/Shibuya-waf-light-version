use crate::DeployPlatform;
use anyhow::Result;

pub async fn run(_platform: DeployPlatform) -> Result<()> {
    println!("Deploy command (stub)");
    Ok(())
}
