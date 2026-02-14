// =============================================================================
// SHIBUYA WAF — Criterion Micro-Benchmarks
// Benchmarks: parser transforms, rule engine, ML inference, end-to-end pipeline
// Run: cargo bench --bench shibuya_bench
// =============================================================================

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use std::time::Duration;

// Re-export crate modules
use waf_killer_core::parser::transforms::TransformPipeline;
use waf_killer_core::parser::context::RequestContext;
use waf_killer_core::rules::engine::{RuleEngine, EngineConfig, EngineMode};
use waf_killer_core::rules::parser::parse_rule;
use waf_killer_core::rules::seed::generate_owasp_rules;

// ── Realistic Payloads ──────────────────────────────────────────────────────

const SQLI_ENCODED: &str = "1%2527%2520OR%2520%25271%2527%253D%25271%2520UNION%2520SELECT%2520%252A%2520FROM%2520users";
const XSS_ENCODED: &str = "%253Cscript%253Ealert%2528document.cookie%2529%253C%252Fscript%253E";
const CLEAN_QUERY: &str = "hello+world+search+query+with+normal+content";
const PATH_TRAVERSAL: &str = "..%252f..%252f..%252f..%252fetc%252fpasswd";
const LARGE_PARAM: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

// ── Parser Transform Benchmarks ─────────────────────────────────────────────

fn bench_parser_transforms(c: &mut Criterion) {
    let mut group = c.benchmark_group("parser_transforms");
    group.measurement_time(Duration::from_secs(5));

    // Clean input — baseline
    group.bench_function("clean_input", |b| {
        b.iter(|| TransformPipeline::apply(black_box(CLEAN_QUERY)))
    });

    // Double-encoded SQLi — triggers multiple decode passes
    group.bench_function("sqli_double_encoded", |b| {
        b.iter(|| TransformPipeline::apply(black_box(SQLI_ENCODED)))
    });

    // Double-encoded XSS
    group.bench_function("xss_double_encoded", |b| {
        b.iter(|| TransformPipeline::apply(black_box(XSS_ENCODED)))
    });

    // Path traversal with encoding
    group.bench_function("path_traversal_encoded", |b| {
        b.iter(|| TransformPipeline::apply(black_box(PATH_TRAVERSAL)))
    });

    // Large input (512 bytes) — tests linear scaling
    group.throughput(Throughput::Bytes(LARGE_PARAM.len() as u64));
    group.bench_function("large_param_512b", |b| {
        b.iter(|| TransformPipeline::apply(black_box(LARGE_PARAM)))
    });

    group.finish();
}

// ── Rule Engine Benchmarks ──────────────────────────────────────────────────

fn build_engine_with_owasp() -> RuleEngine {
    let owasp_rules = generate_owasp_rules();
    let config = EngineConfig {
        paranoia_level: 1,
        inbound_threshold: 5,
        outbound_threshold: 4,
        enabled: true,
        mode: EngineMode::Blocking,
    };
    RuleEngine::new(owasp_rules, config)
}

fn build_single_rule_engine() -> RuleEngine {
    let rule_str = r#"SecRule ARGS:q "@rx (?i:union.*select)" "id:1000,phase:2,block,msg:'SQLi'""#;
    let rule = parse_rule(rule_str).unwrap();
    let config = EngineConfig {
        paranoia_level: 1,
        inbound_threshold: 5,
        outbound_threshold: 4,
        enabled: true,
        mode: EngineMode::Blocking,
    };
    RuleEngine::new(vec![rule], config)
}

fn make_context(uri: &str, method: &str) -> RequestContext {
    let mut ctx = RequestContext::new(
        uuid::Uuid::new_v4().to_string(),
        "192.168.1.100".to_string(),
    );
    ctx.uri = uri.to_string();
    ctx.method = method.to_string();
    ctx
}

fn bench_rule_engine(c: &mut Criterion) {
    let mut group = c.benchmark_group("rule_engine");
    group.measurement_time(Duration::from_secs(10));

    // Single rule — baseline
    let single_engine = build_single_rule_engine();
    let clean_ctx = make_context("/?q=hello+world", "GET");

    group.bench_function("single_rule_clean", |b| {
        b.iter(|| single_engine.inspect_request(black_box(&clean_ctx)))
    });

    let attack_ctx = make_context("/?q=1'+UNION+SELECT+*+FROM+users--", "GET");
    group.bench_function("single_rule_sqli", |b| {
        b.iter(|| single_engine.inspect_request(black_box(&attack_ctx)))
    });

    // Full OWASP rule set (~600+ rules)
    let owasp_engine = build_engine_with_owasp();

    group.bench_function("owasp_rules_clean", |b| {
        b.iter(|| owasp_engine.inspect_request(black_box(&clean_ctx)))
    });

    group.bench_function("owasp_rules_sqli", |b| {
        b.iter(|| owasp_engine.inspect_request(black_box(&attack_ctx)))
    });

    let xss_ctx = make_context("/?q=<script>alert(1)</script>", "GET");
    group.bench_function("owasp_rules_xss", |b| {
        b.iter(|| owasp_engine.inspect_request(black_box(&xss_ctx)))
    });

    let rce_ctx = make_context("/?cmd=;cat+/etc/passwd", "GET");
    group.bench_function("owasp_rules_rce", |b| {
        b.iter(|| owasp_engine.inspect_request(black_box(&rce_ctx)))
    });

    group.finish();
}

// ── End-to-End Pipeline Benchmark ──────────────────────────────────────────

fn bench_end_to_end(c: &mut Criterion) {
    let mut group = c.benchmark_group("end_to_end_pipeline");
    group.measurement_time(Duration::from_secs(10));

    let engine = build_engine_with_owasp();

    // Full pipeline: decode → transform → rule match
    group.bench_function("clean_request", |b| {
        b.iter(|| {
            // Step 1: Transform input
            let decoded = TransformPipeline::apply(black_box("hello+world+search"));
            // Step 2: Build context
            let ctx = make_context(&format!("/?q={}", decoded), "GET");
            // Step 3: Rule inspection
            engine.inspect_request(black_box(&ctx))
        })
    });

    group.bench_function("encoded_sqli_request", |b| {
        b.iter(|| {
            let decoded = TransformPipeline::apply(black_box(SQLI_ENCODED));
            let ctx = make_context(&format!("/?q={}", decoded), "GET");
            engine.inspect_request(black_box(&ctx))
        })
    });

    group.bench_function("encoded_xss_request", |b| {
        b.iter(|| {
            let decoded = TransformPipeline::apply(black_box(XSS_ENCODED));
            let ctx = make_context(&format!("/?q={}", decoded), "GET");
            engine.inspect_request(black_box(&ctx))
        })
    });

    // Varying payload sizes
    for size in [64, 256, 1024, 4096] {
        let payload = "x".repeat(size);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::new("varying_size", size),
            &payload,
            |b, payload| {
                b.iter(|| {
                    let decoded = TransformPipeline::apply(black_box(payload));
                    let ctx = make_context(&format!("/?q={}", decoded), "GET");
                    engine.inspect_request(black_box(&ctx))
                })
            },
        );
    }

    group.finish();
}

// ── Registration ────────────────────────────────────────────────────────────

criterion_group!(
    benches,
    bench_parser_transforms,
    bench_rule_engine,
    bench_end_to_end,
);
criterion_main!(benches);
