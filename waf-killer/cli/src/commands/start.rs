use anyhow::Result;
use std::path::PathBuf;

pub async fn run(_foreground: bool, _config: &PathBuf) -> Result<()> {
    println!("Start command (stub)");
    Ok(())
}
