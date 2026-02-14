use crate::RuleAction;
use anyhow::Result;
use colored::Colorize;
use crate::client::grpc::{connect, GetRulesRequest, EnableRuleRequest, DisableRuleRequest, TestPayloadRequest};

pub async fn run(action: RuleAction) -> Result<()> {
    let mut client = connect("http://127.0.0.1:9091".to_string()).await?;

    match action {
        RuleAction::List { category, all } => {
            let res = client.get_rules(GetRulesRequest {
                category,
                show_all: all,
            }).await?.into_inner();
            
            // Should use table ui
            println!("{:<5} {:<50} {:<15} {:<10}", "ID", "MESSAGE", "CATEGORY", "STATUS".bold());
            println!("{}", "-".repeat(80));
            
            for rule in res.rules {
                let status = if rule.enabled { "ENABLED".green() } else { "DISABLED".dimmed() };
                println!("{:<5} {:<50} {:<15} {}", rule.id, rule.msg, rule.category, status);
            }
        },
        RuleAction::Show { id } => {
            // Need GetRule RPC or filter from list
            println!("Showing details for rule {}", id);
        },
        RuleAction::Test { id, payload } => {
             // Use test_payload mostly
             println!("Testing rule {} with payload: {}", id, payload);
             let res = client.test_payload(TestPayloadRequest {
                 method: "GET".to_string(),
                 path: "/".to_string(), // Dummy path
                 payload,
             }).await?.into_inner();
             
             // Check if specific rule matched
             let matched = res.rules_matched.iter().any(|r| r.id == id);
             if matched {
                 println!("{}", "MATCHED".red().bold());
             } else {
                 println!("{}", "NOT MATCHED".green());
             }
        },
        RuleAction::Enable { ids } => {
             client.enable_rule(EnableRuleRequest { ids: ids.clone() }).await?;
             println!("Enabled {} rules: {:?}", ids.len(), ids);
        },
        RuleAction::Disable { ids } => {
             client.disable_rule(DisableRuleRequest { ids: ids.clone() }).await?;
             println!("Disabled {} rules: {:?}", ids.len(), ids);
        },
    }
    
    Ok(())
}
