
use std::fs;
use std::path::Path;

fn main() {
    let path = "rules/crs/REQUEST-942-APPLICATION-ATTACK-SQLI.conf";
    println!("Testing parser on: {}", path);

    let content = fs::read_to_string(path).expect("Failed to read file");
    println!("File size: {} bytes", content.len());

    let mut count = 0;
    let mut current_rule = String::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("#") || trimmed.is_empty() {
            continue;
        }

        if trimmed.ends_with('\\') {
            current_rule.push_str(&trimmed[..trimmed.len() - 1]);
            current_rule.push(' ');
        } else {
            if !current_rule.is_empty() {
                current_rule.push_str(trimmed);
                // Simulate parse_rule
                if current_rule.starts_with("SecRule") {
                    println!("Parsed rule (combined): {:.50}...", current_rule);
                    count += 1;
                } else {
                    println!("Ignored (combined): {:.50}...", current_rule);
                }
                current_rule.clear();
            } else {
                 if trimmed.starts_with("SecRule") {
                    println!("Parsed rule (single): {:.50}...", trimmed);
                    count += 1;
                } else {
                    println!("Ignored (single): {:.50}...", trimmed);
                }
            }
        }
    }
    
    // Check lingering
    if !current_rule.is_empty() {
         if current_rule.starts_with("SecRule") {
             count += 1;
         }
    }

    println!("Total heuristic rules found: {}", count);
}
