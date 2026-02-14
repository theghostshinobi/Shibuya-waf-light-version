use crate::parser::context::RequestContext;
use super::parser::{OpenAPISpec, PathItem, Operation, Schema, SchemaType};
use std::collections::HashMap;
use std::sync::Mutex;
use lazy_static::lazy_static;

lazy_static! {
    static ref RECENT_TRAFFIC: Mutex<Vec<RequestContext>> = Mutex::new(Vec::new());
}

pub struct OpenAPIGenerator {
    // Current inferred schema
}

impl OpenAPIGenerator {
    pub fn new() -> Self {
        Self {}
    }

    pub fn record_request(&self, ctx: RequestContext) {
        let mut traffic = RECENT_TRAFFIC.lock().unwrap();
        traffic.push(ctx);
        if traffic.len() > 1000 {
            traffic.remove(0);
        }
    }

    pub fn generate_spec(&self) -> OpenAPISpec {
        let traffic = RECENT_TRAFFIC.lock().unwrap();
        let mut paths = HashMap::new();

        for ctx in traffic.iter() {
            let path_item = paths.entry(ctx.path.clone()).or_insert_with(|| PathItem {
                operations: HashMap::new(),
            });

            path_item.operations.entry(ctx.method.clone()).or_insert_with(|| Operation {
                operation_id: None,
                parameters: vec![],
                request_body: None,
            });
            
            // TODO: infer parameters and body structure from sampled traffic
        }

        OpenAPISpec {
            info_title: "Auto-generated API Spec".to_string(),
            paths,
        }
    }
}
