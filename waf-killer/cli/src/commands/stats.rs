// ============================================
// File: cli/src/commands/stats.rs
// ============================================
//! Episode 7: WAF Statistics Command
//!
//! Calls GET /metrics on Admin API and displays stats with colors.
//! Falls back to HTTP if gRPC is unavailable.

use anyhow::{Context, Result};
use colored::Colorize;
use crate::client::grpc::{connect, GetStatsRequest};
use ratatui::{
    backend::CrosstermBackend,
    widgets::{Block, Borders, Chart, Axis, Dataset, GraphType},
    layout::{Layout, Constraint, Direction},
    style::{Color, Style, Modifier},
    symbols,
    Terminal,
};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use std::time::Duration;

const ADMIN_API_URL: &str = "http://127.0.0.1:9090";

pub async fn run(range: &str, watch: bool) -> Result<()> {
    if watch {
        // Real-time dashboard (gRPC based)
        run_dashboard(range).await?;
    } else {
        // Try HTTP Admin API first, fall back to gRPC
        if let Err(_) = print_stats_http().await {
            // Fall back to gRPC
            match connect("http://127.0.0.1:9091".to_string()).await {
                Ok(mut client) => {
                    print_stats_grpc(&mut client, range).await?;
                }
                Err(_) => {
                    print_stats_offline();
                }
            }
        }
    }
    
    Ok(())
}

/// Print stats via HTTP Admin API
async fn print_stats_http() -> Result<()> {
    let url = format!("{}/metrics", ADMIN_API_URL);
    
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;

    let response = client.get(&url).send().await?;
    
    if !response.status().is_success() {
        anyhow::bail!("Admin API returned error");
    }

    let metrics_text = response.text().await?;
    
    println!();
    println!("{}", "╔═══════════════════════════════════════════════════╗".cyan().bold());
    println!("{}", "║         📊 WAF KILLER - STATISTICS 📊             ║".cyan().bold());
    println!("{}", "╚═══════════════════════════════════════════════════╝".cyan().bold());
    println!();
    
    // Parse Prometheus metrics
    let mut total_requests = 0u64;
    let mut blocked_requests = 0u64;
    let mut challenged_requests = 0u64;
    let mut backend_errors = 0u64;
    
    for line in metrics_text.lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        
        if line.starts_with("waf_requests_total") {
            if let Some(val) = extract_metric_value(line) {
                total_requests = val as u64;
            }
        } else if line.starts_with("waf_requests_blocked") {
            if let Some(val) = extract_metric_value(line) {
                blocked_requests = val as u64;
            }
        } else if line.starts_with("waf_requests_challenged") {
            if let Some(val) = extract_metric_value(line) {
                challenged_requests = val as u64;
            }
        } else if line.starts_with("waf_backend_errors_total") {
            if let Some(val) = extract_metric_value(line) {
                backend_errors = val as u64;
            }
        }
    }
    
    let allowed_requests = total_requests.saturating_sub(blocked_requests + challenged_requests);
    let block_rate = if total_requests > 0 {
        (blocked_requests as f64 / total_requests as f64) * 100.0
    } else {
        0.0
    };
    
    // Display
    println!("  {}", "TRAFFIC SUMMARY:".bright_white().bold());
    println!("    {} {}", "Total Requests:".bright_white(), 
        total_requests.to_string().cyan().bold());
    println!("    {} {}", "Allowed:".bright_white(), 
        allowed_requests.to_string().green().bold());
    println!("    {} {}", "Blocked:".bright_white(), 
        blocked_requests.to_string().red().bold());
    println!("    {} {}", "Challenged:".bright_white(), 
        challenged_requests.to_string().yellow().bold());
    println!();
    
    println!("  {}", "SECURITY METRICS:".bright_white().bold());
    let block_rate_str = format!("{:.2}%", block_rate);
    let block_rate_colored = if block_rate > 50.0 {
        block_rate_str.red().bold()
    } else if block_rate > 10.0 {
        block_rate_str.yellow().bold()
    } else {
        block_rate_str.green().bold()
    };
    println!("    {} {}", "Block Rate:".bright_white(), block_rate_colored);
    println!("    {} {}", "Backend Errors:".bright_white(), 
        backend_errors.to_string().red());
    println!();
    
    // ASCII art threat gauge
    print_threat_gauge(block_rate);
    
    println!();
    Ok(())
}

fn extract_metric_value(line: &str) -> Option<f64> {
    // Line format: "metric_name{labels} value" or "metric_name value"
    let parts: Vec<&str> = line.split_whitespace().collect();
    if let Some(val_str) = parts.last() {
        val_str.parse::<f64>().ok()
    } else {
        None
    }
}

fn print_threat_gauge(block_rate: f64) {
    println!("  {}", "THREAT LEVEL:".bright_white().bold());
    
    let gauge_width = 30;
    let filled = ((block_rate / 100.0) * gauge_width as f64) as usize;
    let empty = gauge_width.saturating_sub(filled);
    
    let bar = format!("{}{}",
        "█".repeat(filled),
        "░".repeat(empty)
    );
    
    let (bar_colored, level) = if block_rate > 50.0 {
        (bar.red().bold(), "🔴 CRITICAL".red().bold())
    } else if block_rate > 25.0 {
        (bar.yellow().bold(), "🟡 ELEVATED".yellow().bold())
    } else if block_rate > 10.0 {
        (bar.bright_yellow(), "🟢 MODERATE".bright_yellow())
    } else {
        (bar.green().bold(), "🟢 LOW".green().bold())
    };
    
    println!("    [{}] {}", bar_colored, level);
}

fn print_stats_offline() {
    println!();
    println!("{}", "╔═══════════════════════════════════════════════════╗".red().bold());
    println!("{}", "║         📊 WAF KILLER - STATISTICS 📊             ║".red().bold());
    println!("{}", "╚═══════════════════════════════════════════════════╝".red().bold());
    println!();
    println!("  {} {}", "⚠".yellow().bold(), "WAF is offline or unreachable".yellow());
    println!();
    println!("  {} Make sure waf-killer-core is running:", "TIP:".bright_white());
    println!("      cargo run -p waf-killer-core");
    println!();
}

async fn print_stats_grpc(client: &mut crate::client::grpc::WafManagementClient<tonic::transport::Channel>, range: &str) -> Result<()> {
    let stats = client.get_stats(GetStatsRequest {
        range: range.to_string(),
    }).await?.into_inner();
    
    println!();
    println!("{}", "╔═══════════════════════════════════════════════════╗".cyan().bold());
    println!("{}", "║         📊 WAF KILLER - STATISTICS 📊             ║".cyan().bold());
    println!("{}", "╚═══════════════════════════════════════════════════╝".cyan().bold());
    println!();
    
    // Requests
    println!("  {}", "TRAFFIC SUMMARY:".bright_white().bold());
    println!("    {} {}", "Total:".bright_white(), stats.total_requests.to_string().cyan().bold());
    println!("    {} {}", "Allowed:".bright_white(), stats.allowed_requests.to_string().green().bold());
    println!("    {} {}", "Blocked:".bright_white(), stats.blocked_requests.to_string().red().bold());
    println!();
    
    // Performance
    println!("  {}", "PERFORMANCE:".bright_white().bold());
    println!("    {} {}ms", "Avg Latency:".bright_white(), stats.avg_latency_ms);
    println!("    {} {}ms", "P95 Latency:".bright_white(), stats.p95_latency_ms);
    println!();
    
    Ok(())
}

async fn run_dashboard(range: &str) -> Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let res = run_app(&mut terminal, range).await;

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        println!("{:?}", err)
    }

    Ok(())
}

async fn run_app<B: ratatui::backend::Backend>(terminal: &mut Terminal<B>, range: &str) -> Result<()> {
    let mut client = connect("http://127.0.0.1:9091".to_string()).await?;
    let range = range.to_string();
    
    loop {
        let stats = client.get_stats(GetStatsRequest {
            range: range.clone(),
        }).await?.into_inner();
        
        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Length(10),
                    Constraint::Min(0),
                ])
                .split(f.area());
            
            // Header
            let header = Block::default()
                .title("🔥 WAF Killer - Live Stats 🔥")
                .borders(Borders::ALL)
                .style(Style::default().fg(Color::Red));
            f.render_widget(header, chunks[0]);
            
            // Requests chart (simplified logic)
            let requests_data: Vec<(f64, f64)> = stats.timeline
                .iter()
                .enumerate()
                .map(|(i, v)| (i as f64, *v as f64))
                .collect();
            
            let dataset = Dataset::default()
                .name("Requests/sec")
                .marker(symbols::Marker::Braille)
                .style(Style::default().fg(Color::Cyan))
                .graph_type(GraphType::Line)
                .data(&requests_data);
            
            let chart = Chart::new(vec![dataset])
                .block(Block::default().title("Traffic").borders(Borders::ALL))
                .x_axis(Axis::default().bounds([0.0, 60.0])) // 60 data points assumed
                .y_axis(Axis::default().bounds([0.0, stats.max_rps as f64 + 1.0]));
            
            f.render_widget(chart, chunks[1]);
            
            // Stats block
            let stats_text = format!(
                "Total: {}\nAllowed: {}\nBlocked: {}\nAvg Latency: {}ms",
                stats.total_requests,
                stats.allowed_requests,
                stats.blocked_requests,
                stats.avg_latency_ms
            );
            
            let stats_block = ratatui::widgets::Paragraph::new(stats_text)
                .block(Block::default().title("Details").borders(Borders::ALL));
            
            f.render_widget(stats_block, chunks[2]);
            
        })?;
        
        // Handle input
        if event::poll(Duration::from_millis(500))? {
             if let Event::Key(key) = event::read()? {
                if key.code == KeyCode::Char('q') {
                    return Ok(());
                }
            }
        }
    }
}
