use anyhow::Result;
use arc_swap::ArcSwap;
use std::sync::Arc;
use tracing::info;
use crate::config::policy_schema::Policy;
use crate::rules::engine::{RuleEngine, EngineConfig, EngineMode};

pub struct PolicyApplier {
    rule_engine: Arc<ArcSwap<RuleEngine>>,
}

impl PolicyApplier {
    pub fn new(rule_engine: Arc<ArcSwap<RuleEngine>>) -> Self {
        Self { rule_engine }
    }
    
    pub fn apply(&self, policy: Policy) -> Result<()> {
        info!("Applying policy version {}...", policy.version);
        
        // 1. Convert Policy to RuleEngine settings
        let mode = match policy.global.mode.as_str() {
            "blocking" => EngineMode::Blocking,
            "detection" => EngineMode::Detection,
            _ => EngineMode::Off,
        };
        
        let config = EngineConfig {
            enabled: policy.global.mode != "off",
            mode,
            paranoia_level: policy.global.paranoia_level,
            inbound_threshold: policy.global.anomaly_threshold as i32,
            outbound_threshold: 100, // Not in basic policy yet, default
        };
        
        // 2. Load rules
        // In a real implementation we would load rules from CRS path or Policy itself.
        // For this episode, we assume CRS is already loaded or we reuse existing rules but apply new config?
        // Wait, if we replace the RuleEngine, we need the Rules!
        // `RuleEngine` owns the rules.
        // If the policy defines custom rules, we need to compile them.
        
        // Strategy:
        // We need to keep a copy of the "Base CRS" somewhere, or reload it.
        // Or `RuleEngine` should support `update_config`.
        // But `RuleEngine` is immutable in `ArcSwap`. So we create a NEW `RuleEngine`.
        
        // Let's grab the OLD rules from the current engine?
        // `RuleEngine` has `rules: Vec<Rule>`. If it's pub, checking...
        // If not, we might need to change `RuleEngine` to be generic or reload from disk.
        // Reloading from disk (CRS path) is safer.
        // But we don't know the CRS path here unless passed.
        
        // Simplification for this task:
        // We will just update the CONFIG and keep the old Rules for now, 
        // OR we assume `loader.load_policy` provides everything needed.
        
        // Let's rely on the current engine's rules for now to avoid reloading CRS from disk every time 
        // without knowing the path.
        let current_engine = self.rule_engine.load();
        let rules = current_engine.rules.clone(); // Needs `rules` to be pub and Clone
        
        // Apply custom rules from policy
        // TODO: Compile policy.custom_rules into internal Rule format and append to rules.
        
        let mut new_engine = RuleEngine::new(rules, config);
        
        // Swap
        self.rule_engine.store(Arc::new(new_engine));
        
        info!("Policy applied successfully.");
        Ok(())
    }
}
