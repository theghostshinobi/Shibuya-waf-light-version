use anyhow::Result;
use colored::Colorize;
use crate::client::grpc::{connect, StreamLogsRequest, LogEntry};

pub async fn run(follow: bool, level: Option<String>, request_id: Option<String>, lines: usize) -> Result<()> {
    // TODO: Get port from config or default to 9091
    let mut client = connect("http://127.0.0.1:9091".to_string()).await?;
    
    if follow {
        println!("{}", "📜 Following WAF logs (Ctrl+C to stop)...".cyan());
        println!();
        
        let request = tonic::Request::new(StreamLogsRequest {
            level_filter: level,
            request_id_filter: request_id,
        });
        
        let mut stream = client.stream_logs(request).await?.into_inner();
        
        while let Some(log_entry) = stream.message().await? {
            print_log_entry(&log_entry);
        }
    } else {
        // Implementation for getting last N lines (GetLogs RPC needed if supported, current proto has GetLogs stub)
        // For now, if get_logs assumes stored logs, we might just print a message or use the stub.
        // The proto definition has GetLogs.
        
        let request = tonic::Request::new(crate::client::grpc::GetLogsRequest {
             lines: lines as u32,
             level_filter: level,
             request_id_filter: request_id,
        });
        
        let response = client.get_logs(request).await?.into_inner();
        for log_entry in response.entries {
            print_log_entry(&log_entry);
        }
    }
    
    Ok(())
}

fn print_log_entry(entry: &LogEntry) {
    let timestamp = &entry.timestamp;
    // timestamp usually includes T, split it
    let timestamp_short = timestamp.split('T').nth(1).unwrap_or(timestamp);
    
    let level_str = match entry.level.as_str() {
        "ERROR" => "ERROR".red().bold(),
        "WARN" => "WARN".yellow().bold(),
        "INFO" => "INFO".green(),
        "DEBUG" => "DEBUG".blue(),
        _ => entry.level.normal(),
    };
    
    println!("{} {} {}", timestamp_short.dimmed(), level_str, entry.message);
}
