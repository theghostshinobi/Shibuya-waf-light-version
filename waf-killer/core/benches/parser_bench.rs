use criterion::{black_box, criterion_group, criterion_main, Criterion};
use waf_killer_core::parser::transforms::TransformPipeline;
use waf_killer_core::parser::http::HttpParser;
use bytes::Bytes;
use pingora::http::RequestHeader;

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("transform_pipeline_sqli", |b| {
        let input = "1%2527%2520OR%2520%25271%2527%253D%25271";
        b.iter(|| TransformPipeline::apply(black_box(input)))
    });

    c.bench_function("transform_pipeline_simple", |b| {
        let input = "simple_string";
        b.iter(|| TransformPipeline::apply(black_box(input)))
    });

    // Mock header for http parsing bench
    let mut header = RequestHeader::build("GET", b"/api/test?q=hello&id=1", None).unwrap();
    header.append_header("Host", "example.com").unwrap();
    header.append_header("Content-Type", "application/json").unwrap();
    let body = Bytes::from(r#"{"key": "value", "list": [1, 2, 3]}"#);

    // Note: HttpParser::parse_request is async, so we need to bench it with async support or use block_on
    // Usually criterion supports async with features, but for now let's just bench transforms which is the CPU intensive part.
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
