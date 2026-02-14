use anyhow::{Result, anyhow};
use reqwest::Client;
use serde::Deserialize;
use std::time::Duration;
use crate::scanner::{ScannerFinding, ScannerEvidence};
use chrono::Utc;

pub struct ZAPClient {
    base_url: String,
    api_key: String,
    client: Client,
}

#[derive(Deserialize)]
pub struct ZAPAlert {
    pub alert: String,
    pub risk: String,
    pub confidence: String,
    pub url: String,
    pub method: String,
    pub param: String,
    pub attack: String,
    pub evidence: String,
    pub description: String,
    pub solution: String,
}

impl ZAPClient {
    pub fn new(base_url: String, api_key: String) -> Self {
        Self {
            base_url,
            api_key,
            client: Client::new(),
        }
    }

    pub async fn active_scan(&self, target_url: &str) -> Result<String> {
        let url = format!(
            "{}/JSON/ascan/action/scan/?url={}&apikey={}",
            self.base_url,
            urlencoding::encode(target_url),
            self.api_key
        );
        
        let response = self.client.get(&url).send().await?;
        if !response.status().is_success() {
             return Err(anyhow!("Failed to start active scan: {}", response.status()));
        }

        let result: serde_json::Value = response.json().await?;
        
        let scan_id = result["scan"].as_str()
            .ok_or_else(|| anyhow!("No scan ID in response"))?;
        
        Ok(scan_id.to_string())
    }
    
    pub async fn get_findings(&self, _scan_id: &str) -> Result<Vec<ScannerFinding>> {
         // Note: ZAP API usually returns all alerts or filtered by other params, not strictly by scan_id in the simple view
         // But for this implementation we'll fetch all alerts, or we could filter if ZAP API supports it easily.
         // core/view/alerts/ returns all.
         
        let url = format!(
            "{}/JSON/core/view/alerts/?apikey={}",
            self.base_url,
            self.api_key
        );
        
        let response = self.client.get(&url).send().await?;
        if !response.status().is_success() {
             return Err(anyhow!("Failed to fetch alerts: {}", response.status()));
        }

        let result: serde_json::Value = response.json().await?;
        let alerts: Vec<ZAPAlert> = serde_json::from_value(result["alerts"].clone())?;
        
        let findings = alerts.into_iter().enumerate().map(|(i, alert)| {
            ScannerFinding {
                id: format!("ZAP-{}", i), // In reality use ZAP's alertId
                title: alert.alert,
                severity: alert.risk,
                confidence: alert.confidence,
                scanner_type: "zap".to_string(),
                path: alert.url,
                method: Some(alert.method),
                evidence: Some(ScannerEvidence {
                    request: None, // ZAP alerts often don't include full request/response strings directly in this view
                    response: None,
                    other: Some(format!("Attack: {}, Param: {}, Evidence: {}", alert.attack, alert.param, alert.evidence)),
                }),
                description: Some(alert.description),
                solution: Some(alert.solution),
                cve_id: None, // ZAP provides WASC/CWE but typically not CVE directly in basic alerts
                discovered_at: Utc::now(),
            }
        }).collect();
        
        Ok(findings)
    }
    
    pub async fn spider(&self, target_url: &str) -> Result<Vec<String>> {
        // Start spider
        let spider_url = format!(
            "{}/JSON/spider/action/scan/?url={}&apikey={}",
            self.base_url,
            urlencoding::encode(target_url),
            self.api_key
        );
        
        self.client.get(&spider_url).send().await?;
        
        // Wait for completion (simplified polling)
        // In a real async job we might return a job ID and let the caller poll.
        // For this episode's snippet we'll busy-wait a bit or just kick it off.
        // The prompt implementation suggested polling loop.
        
        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;
            
            let status_url = format!(
                "{}/JSON/spider/view/status/?apikey={}",
                self.base_url,
                self.api_key
            );
            
            let response = self.client.get(&status_url).send().await?;
            let result: serde_json::Value = response.json().await?;
            
            let status = result["status"].as_str().unwrap_or("0");
            if status == "100" {
                break;
            }
        }
        
        // Get discovered URLs
        let urls_url = format!(
            "{}/JSON/spider/view/results/?apikey={}",
            self.base_url,
            self.api_key
        );
        
        let response = self.client.get(&urls_url).send().await?;
        let result: serde_json::Value = response.json().await?;
        
        let urls: Vec<String> = result["results"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
        
        Ok(urls)
    }
}
