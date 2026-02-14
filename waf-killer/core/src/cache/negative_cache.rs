use lru::LruCache;
use parking_lot::RwLock;
use std::time::{Instant, Duration};
use std::sync::atomic::{AtomicU64, Ordering};
use std::num::NonZeroUsize;

pub struct NegativeCache {
    cache: RwLock<LruCache<u64, CacheEntry>>,
    hit_count: AtomicU64,
    miss_count: AtomicU64,
}

struct CacheEntry {
    added_at: Instant,
    hits: u32,
}

impl NegativeCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            cache: RwLock::new(LruCache::new(NonZeroUsize::new(capacity).unwrap())),
            hit_count: AtomicU64::new(0),
            miss_count: AtomicU64::new(0),
        }
    }
    
    pub fn contains(&self, hash: u64) -> bool {
        let mut cache = self.cache.write();
        
        if let Some(entry) = cache.get_mut(&hash) {
            // Check if entry is still fresh (5 min TTL)
            if entry.added_at.elapsed() < Duration::from_secs(300) {
                entry.hits += 1;
                self.hit_count.fetch_add(1, Ordering::Relaxed);
                return true;
            } else {
                // Expired, remove
                cache.pop(&hash);
                // Fallthrough to miss
            }
        }
        
        self.miss_count.fetch_add(1, Ordering::Relaxed);
        false
    }
    
    pub fn insert(&self, hash: u64) {
        let mut cache = self.cache.write();
        cache.put(hash, CacheEntry {
            added_at: Instant::now(),
            hits: 0,
        });
    }
    
    pub fn hit_rate(&self) -> f64 {
        let hits = self.hit_count.load(Ordering::Relaxed);
        let misses = self.miss_count.load(Ordering::Relaxed);
        let total = hits + misses;
        
        if total == 0 {
            0.0
        } else {
            hits as f64 / total as f64
        }
    }
}
