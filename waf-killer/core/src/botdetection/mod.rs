pub mod fingerprint;
pub mod challenge;
pub mod behavior;

use fingerprint::{TlsInfo, Http2Fingerprint, calculate_bot_score};
use challenge::{generate_challenge, verify_challenge_response, generate_challenge_html, ChallengeResponse};
use behavior::BehaviorTracker;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone)]
pub struct BotDetectionStats {
    pub total_requests_analyzed: Arc<AtomicU64>,
    pub bots_detected: Arc<AtomicU64>,
    pub bots_blocked: Arc<AtomicU64>,
    pub fingerprint_matches: Arc<AtomicU64>,
    pub behavior_score_blocks: Arc<AtomicU64>,
}

impl Default for BotDetectionStats {
    fn default() -> Self {
        Self {
            total_requests_analyzed: Arc::new(AtomicU64::new(0)),
            bots_detected: Arc::new(AtomicU64::new(0)),
            bots_blocked: Arc::new(AtomicU64::new(0)),
            fingerprint_matches: Arc::new(AtomicU64::new(0)),
            behavior_score_blocks: Arc::new(AtomicU64::new(0)),
        }
    }
}

impl BotDetectionStats {
    pub fn increment_analyzed(&self) {
        self.total_requests_analyzed.fetch_add(1, Ordering::Relaxed);
    }
    
    pub fn increment_detected(&self) {
        self.bots_detected.fetch_add(1, Ordering::Relaxed);
    }
    
    pub fn increment_blocked(&self) {
        self.bots_blocked.fetch_add(1, Ordering::Relaxed);
    }
    
    pub fn increment_fingerprint_match(&self) {
        self.fingerprint_matches.fetch_add(1, Ordering::Relaxed);
    }
    
    pub fn increment_behavior_block(&self) {
        self.behavior_score_blocks.fetch_add(1, Ordering::Relaxed);
    }
    
    pub fn get_snapshot(&self) -> BotStatsSnapshot {
        BotStatsSnapshot {
            total_requests_analyzed: self.total_requests_analyzed.load(Ordering::Relaxed),
            bots_detected: self.bots_detected.load(Ordering::Relaxed),
            bots_blocked: self.bots_blocked.load(Ordering::Relaxed),
            fingerprint_matches: self.fingerprint_matches.load(Ordering::Relaxed),
            behavior_score_blocks: self.behavior_score_blocks.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct BotStatsSnapshot {
    pub total_requests_analyzed: u64,
    pub bots_detected: u64,
    pub bots_blocked: u64,
    pub fingerprint_matches: u64,
    pub behavior_score_blocks: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotDetectionConfig {
    pub enabled: bool,
    pub fingerprint_check: bool,
    pub behavior_analysis: bool,
    pub block_threshold: f32,
}

impl Default for BotDetectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            fingerprint_check: true,
            behavior_analysis: true,
            block_threshold: 0.8,
        }
    }
}

/// Detection result with recommended action
#[derive(Debug, Clone)]
pub enum DetectionAction {
    Allow,                          // Bot score < 0.4
    Challenge(String),              // 0.4 <= score < 0.8, needs JS challenge
    Block,                          // score >= 0.8
}

#[derive(Debug, Clone)]
pub struct DetectionResult {
    pub action: DetectionAction,
    pub bot_score: f32,
    pub details: DetectionDetails,
}

#[derive(Debug, Clone)]
pub struct DetectionDetails {
    pub fingerprint_score: f32,
    pub behavior_score: f32,
    pub has_verification: bool,
}

/// Main bot detection orchestrator
pub struct BotDetector {
    behavior_tracker: Arc<BehaviorTracker>,
    pub stats: Arc<BotDetectionStats>,
}

impl BotDetector {
    pub fn new() -> Self {
        Self {
            behavior_tracker: Arc::new(BehaviorTracker::new()),
            stats: Arc::new(BotDetectionStats::default()),
        }
    }
    
    pub fn with_stats(stats: Arc<BotDetectionStats>) -> Self {
        Self {
            behavior_tracker: Arc::new(BehaviorTracker::new()),
            stats,
        }
    }
    
    /// Detect bot from request metadata
    pub fn detect(
        &self,
        ip: &str,
        user_agent: &str,
        tls_info: Option<&TlsInfo>,
        http2_info: Option<&Http2Fingerprint>,
        has_verification_cookie: bool
    ) -> DetectionResult {
        self.stats.increment_analyzed();
        
        // Layer 1: Passive fingerprinting
        let fingerprint_score = calculate_bot_score(user_agent, tls_info, http2_info);
        if fingerprint_score > 0.0 {
            self.stats.increment_fingerprint_match();
        }
        
        // Layer 2: Track behavior
        self.behavior_tracker.track_request(ip);
        let behavior_score = self.behavior_tracker.calculate_behavior_score(
            ip,
            has_verification_cookie
        );
        
        // Combine scores (weighted)
        let combined_score = (fingerprint_score * 0.6) + (behavior_score * 0.4);
        
        // Determine action
        let action = if has_verification_cookie && combined_score < 0.7 {
            // Verified users get some leeway
            DetectionAction::Allow
        } else if combined_score >= 0.8 {
            self.stats.increment_detected();
            self.stats.increment_blocked();
            if behavior_score >= 0.8 {
                self.stats.increment_behavior_block();
            }
            DetectionAction::Block
        } else if combined_score >= 0.4 {
            self.stats.increment_detected();
            // Generate challenge
            match generate_challenge() {
                Ok(token) => {
                    let html = generate_challenge_html(&token);
                    DetectionAction::Challenge(html)
                }
                Err(_) => DetectionAction::Allow // Fail open
            }
        } else {
            DetectionAction::Allow
        };
        
        DetectionResult {
            action,
            bot_score: combined_score,
            details: DetectionDetails {
                fingerprint_score,
                behavior_score,
                has_verification: has_verification_cookie,
            }
        }
    }
    
    /// Verify a challenge response
    pub fn verify_challenge(&self, response: &ChallengeResponse) -> bool {
        verify_challenge_response(response).unwrap_or(false)
    }
    
    /// Cleanup old behavioral data
    pub fn cleanup(&self) {
        self.behavior_tracker.cleanup();
    }
}

impl Default for BotDetector {
    fn default() -> Self {
        Self::new()
    }
}
