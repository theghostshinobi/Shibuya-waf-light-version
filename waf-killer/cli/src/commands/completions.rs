use anyhow::Result;
use clap::CommandFactory;
use clap_complete::{generate, shells::{Bash, Zsh, Fish}};
use colored::Colorize;

pub fn run(shell: &str) -> Result<()> {
    let mut app = crate::Cli::command();
    
    match shell.to_lowercase().as_str() {
        "bash" => {
            generate(Bash, &mut app, "waf", &mut std::io::stdout());
        },
        "zsh" => {
            generate(Zsh, &mut app, "waf", &mut std::io::stdout());
        },
        "fish" => {
            generate(Fish, &mut app, "waf", &mut std::io::stdout());
        },
        _ => {
            eprintln!("{}", "Unsupported shell. Use: bash, zsh, or fish".red());
            std::process::exit(1);
        }
    }
    
    // We print instructions to stderr so stdout is clean for piping
    eprintln!();
    eprintln!("{}", "Installation instructions:".bold());
    match shell {
        "bash" => {
            eprintln!("  waf completions bash > /etc/bash_completion.d/waf");
        },
        "zsh" => {
            eprintln!("  waf completions zsh > ~/.zsh/completions/_waf");
        },
        "fish" => {
            eprintln!("  waf completions fish > ~/.config/fish/completions/waf.fish");
        },
        _ => {}
    }
    
    Ok(())
}
