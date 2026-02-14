use criterion::{black_box, criterion_group, criterion_main, Criterion};
use waf_killer_core::rules::engine::{RuleEngine, EngineConfig, EngineMode};
use waf_killer_core::rules::parser::parse_rule;
use waf_killer_core::parser::context::RequestContext;

fn criterion_benchmark(c: &mut Criterion) {
    let rule_str = r#"SecRule ARGS:q "@rx (?i:union.*select)" "id:1000,phase:2,block,msg:'SQLi'""#;
    let rule = parse_rule(rule_str).unwrap();
    let config = EngineConfig {
        paranoia_level: 1,
        inbound_threshold: 5,
        outbound_threshold: 4,
        enabled: true,
        mode: EngineMode::Blocking,
    };
    let engine = RuleEngine::new(vec![rule], config);
    let mut ctx = RequestContext::new("123".to_string(), "1.2.3.4".to_string());
    // Populate simple data
    ctx.uri = "/?q=hello".to_string();
    
    // We want to bench the engine matching logic
    c.bench_function("rule engine inspect", |b| b.iter(|| {
        engine.inspect_request(black_box(&ctx))
    }));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
