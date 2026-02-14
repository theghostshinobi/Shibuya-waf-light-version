#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

pub struct SimdMatcher;

impl SimdMatcher {
    /// SIMD-accelerated pattern matching (AVX2)
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    unsafe fn match_avx2(haystack: &[u8], pattern: &[u8]) -> bool {
        if pattern.len() > haystack.len() {
            return false;
        }
        
        let pattern_len = pattern.len();
        let search_len = haystack.len() - pattern_len + 1;
        
        // Load first byte of pattern into all 32 lanes
        let first_byte = _mm256_set1_epi8(pattern[0] as i8);
        
        let mut i = 0;
        // Process 32 bytes at a time
        while i + 32 <= search_len {
            // Load 32 bytes from haystack
            let chunk = _mm256_loadu_si256(haystack.as_ptr().add(i) as *const __m256i);
            
            // Compare first byte
            let cmp = _mm256_cmpeq_epi8(chunk, first_byte);
            let mask = _mm256_movemask_epi8(cmp);
            
            if mask != 0 {
                // Found potential match, verify full pattern
                for bit in 0..32 {
                    if (mask & (1 << bit)) != 0 {
                        let pos = i + bit;
                        if pos + pattern_len <= haystack.len() {
                            if &haystack[pos..pos + pattern_len] == pattern {
                                return true;
                            }
                        }
                    }
                }
            }
            
            i += 32;
        }
        
        // Handle remaining bytes with scalar code
        for j in i..search_len {
            if &haystack[j..j + pattern_len] == pattern {
                return true;
            }
        }
        
        false
    }
    
    /// Public API that dispatches to best available SIMD
    pub fn contains(haystack: &[u8], pattern: &[u8]) -> bool {
        if pattern.is_empty() {
            return true;
        }
        if haystack.len() < pattern.len() {
            return false;
        }

        #[cfg(target_arch = "x86_64")]
        {
            if is_x86_feature_detected!("avx2") {
                unsafe { return Self::match_avx2(haystack, pattern); }
            }
        }
        
        // Fallback: use standard library
        haystack.windows(pattern.len()).any(|window| window == pattern)
    }
}
