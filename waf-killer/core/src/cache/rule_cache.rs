use regex::Regex;
use dashmap::DashMap;
use std::sync::Arc;
use lru::LruCache;
use parking_lot::Mutex;

pub struct RuleCache {
    compiled_regexes: DashMap<u32, Arc<Regex>>,  // rule_id -> compiled regex
    pattern_cache: Mutex<LruCache<String, bool>>,    // pattern+text -> matches? (LRU to prevent explosion)
}

impl RuleCache {
    pub fn new() -> Self {
        Self {
            compiled_regexes: DashMap::new(),
            pattern_cache: Mutex::new(LruCache::new(std::num::NonZeroUsize::new(1_000_000).unwrap())),
        }
    }

    pub fn get_or_compile(&self, rule_id: u32, pattern: &str) -> Arc<Regex> {
        if let Some(regex) = self.compiled_regexes.get(&rule_id) {
            return regex.clone();
        }

        let regex = Arc::new(Regex::new(pattern).unwrap_or_else(|_| {
            // Fallback to literal match if regex invalid
            Regex::new(&regex::escape(pattern)).unwrap()
        }));

        self.compiled_regexes.insert(rule_id, regex.clone());
        regex
    }
    
    /// Check pattern cache before expensive regex match
    /// Pattern + content as key could be huge, so we might want to hash it or limit content length key.
    /// For WAF, this is tricky because content varies wildy. 
    /// Intelligently, we should cache (rule_id + content_hash) -> bool maybe?
    /// For this exercise, following the plan (pattern + text).
    pub fn matches_cached(&self, rule_id: u32, pattern: &str, text: &str) -> bool {
        // Limit key size for cache sanity
        if text.len() > 1024 {
             // Too big to cache reliably as key, or just cache based on hash?
             // Let's just run the regex/matcher for large bodies to avoid cache thrashing/memory issues with huge keys
             // OR hash request + rule_id.
             // For simplicity matching the prompt's design but added safety.
             let regex = self.get_or_compile(rule_id, pattern);
             return regex.is_match(text);
        }

        let cache_key = format!("{}:{}", rule_id, text); // Using rule_id instead of full pattern string for key efficiency if possible, but pattern can change? Rule ID is safer if unique.
        
        {
            let mut cache = self.pattern_cache.lock();
            if let Some(result) = cache.get(&cache_key) {
                return *result;
            }
        }
        
        // Not in cache, perform match
        let regex = self.get_or_compile(rule_id, pattern);
        let result = regex.is_match(text);
        
        {
            let mut cache = self.pattern_cache.lock();
            cache.put(cache_key, result);
        }
        
        result
    }
}
