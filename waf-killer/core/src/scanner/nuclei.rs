use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use crate::scanner::{ScannerFinding, ScannerEvidence};
use chrono::Utc;

pub struct NucleiClient {
    nuclei_path: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NucleiFinding {
    pub template_id: String,
    pub info: NucleiInfo,
    pub matched_at: Option<String>,
    pub extracted_results: Option<Vec<String>>,
    pub curl_command: Option<String>,
    // Nuclei JSON can vary, using Option for safety
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NucleiInfo {
    pub name: String,
    pub severity: String,
    pub description: Option<String>,
    pub tags: Option<Vec<String>>,
    pub remediation: Option<String>,
    pub reference: Option<Vec<String>>, 
    // classification: ...
}

impl NucleiClient {
    pub fn new(nuclei_path: PathBuf) -> Self {
        Self { nuclei_path }
    }

    pub async fn scan_with_templates(
        &self,
        target: &str,
        templates: Vec<String>,
    ) -> Result<Vec<ScannerFinding>> {
        let mut cmd = tokio::process::Command::new(&self.nuclei_path);
        
        cmd.arg("-target")
            .arg(target)
            .arg("-json")
            .arg("-silent");
        
        // Add template paths
        for template in templates {
            cmd.arg("-t").arg(template);
        }
        
        let output = cmd.output().await?;
        
        if !output.status.success() {
            return Err(anyhow!("Nuclei scan failed"));
        }
        
        // Parse JSONL output
        let findings_list: Vec<NucleiFinding> = output.stdout
            .split(|&b| b == b'\n')
            .filter(|line| !line.is_empty())
            .filter_map(|line| serde_json::from_slice(line).ok())
            .collect();
            
        let findings = findings_list.into_iter().enumerate().map(|(i, f)| {
            ScannerFinding {
                id: format!("NUCLEI-{}", i), // In reality, maybe hash matched_at + template_id
                title: f.info.name.clone(),
                severity: f.info.severity.clone(),
                confidence: "High".to_string(), // Nuclei templates are usually high confidence if they match
                scanner_type: "nuclei".to_string(),
                path: f.matched_at.clone().unwrap_or_default(),
                method: None,
                evidence: Some(ScannerEvidence {
                    request: f.curl_command.clone(),
                    response: f.extracted_results.as_ref().map(|v| v.join("\n")),
                    other: None,
                }),
                description: f.info.description.clone(),
                solution: f.info.remediation.clone(),
                cve_id: f.info.tags.as_ref().and_then(|tags| {
                   tags.iter().find(|t| t.to_lowercase().starts_with("cve-")).cloned()
                }), 
                discovered_at: Utc::now(),
            }
        }).collect();
        
        Ok(findings)
    }
    
    pub async fn scan_for_cve(&self, target: &str, cve_id: &str) -> Result<Option<ScannerFinding>> {
        let template = format!("cves/{}.yaml", cve_id.to_lowercase());
        
        let findings = self.scan_with_templates(target, vec![template]).await?;
        
        Ok(findings.into_iter().next())
    }
}
