use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
// Note: We need to expose RuleEngine or similar to bench it. 
// Assuming crate::rules::engine::RuleEngine is public.

// Mocking the bench since we might not have all modules exposed for benching easily without full integration.
// But we can bench the SIMD matcher we created.

use waf_killer_core::simd::string_match::SimdMatcher;

fn bench_simd_matching(c: &mut Criterion) {
    let haystack = "GET /api/users?id=1 HTTP/1.1\r\nHost: example.com\r\n".as_bytes();
    let patterns = vec![
        b"union".as_slice(),
        b"select".as_slice(),
        b"<script".as_slice(),
        b"../".as_slice(),
    ];
    
    let mut group = c.benchmark_group("simd_matching");
    
    for pattern in &patterns {
         group.bench_with_input(
            BenchmarkId::new("simd", String::from_utf8_lossy(pattern)),
            pattern,
            |b, p| {
                b.iter(|| {
                    SimdMatcher::contains(black_box(haystack), black_box(p));
                });
            },
        );
    }
    
    group.finish();
}

criterion_group!(
    benches,
    bench_simd_matching
);
criterion_main!(benches);
