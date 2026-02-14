use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use crate::scanner::ScannerFinding;
use chrono::Utc;

#[derive(Deserialize, Debug)]
struct SarifLog {
    runs: Vec<Run>,
}

#[derive(Deserialize, Debug)]
struct Run {
    tool: Tool,
    results: Option<Vec<ResultItem>>,
}

#[derive(Deserialize, Debug)]
struct Tool {
    driver: Driver,
}

#[derive(Deserialize, Debug)]
struct Driver {
    name: String,
}

#[derive(Deserialize, Debug)]
struct ResultItem {
    rule_id: Option<String>,
    level: Option<String>,
    message: Message,
    locations: Option<Vec<Location>>,
}

#[derive(Deserialize, Debug)]
struct Message {
    text: String,
}

#[derive(Deserialize, Debug)]
struct Location {
    physical_location: Option<PhysicalLocation>,
}

#[derive(Deserialize, Debug)]
struct PhysicalLocation {
    artifact_location: Option<ArtifactLocation>,
}

#[derive(Deserialize, Debug)]
struct ArtifactLocation {
    uri: Option<String>,
}

pub fn parse_sarif_file(path: &Path) -> Result<Vec<ScannerFinding>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let sarif: SarifLog = serde_json::from_reader(reader)?;
    
    let mut findings = Vec::new();
    
    for run in sarif.runs {
        let scanner_name = run.tool.driver.name;
        
        if let Some(results) = run.results {
            for (i, result) in results.into_iter().enumerate() {
                 let path = result.locations.as_ref()
                    .and_then(|l| l.first())
                    .and_then(|l| l.physical_location.as_ref())
                    .and_then(|l| l.artifact_location.as_ref())
                    .and_then(|l| l.uri.clone())
                    .unwrap_or_default();

                findings.push(ScannerFinding {
                    id: format!("{}-{}", scanner_name, i),
                    title: result.message.text.chars().take(100).collect(),
                    severity: result.level.unwrap_or_else(|| "unknown".to_string()),
                    confidence: "Unknown".to_string(), // SARIF standard doesn't strictly define confidence in result item usually
                    scanner_type: scanner_name.clone(),
                    path,
                    method: None,
                    evidence: None,
                    description: Some(result.message.text),
                    solution: None,
                    cve_id: result.rule_id, // Often rule_id is the CVE or Check ID
                    discovered_at: Utc::now(),
                });
            }
        }
    }
    
    Ok(findings)
}
