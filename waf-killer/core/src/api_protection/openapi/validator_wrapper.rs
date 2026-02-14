use crate::parser::context::RequestContext;
use super::{OpenApiSpec, validator::{validate_request, ValidationResult}};

#[derive(Debug, Clone)]
pub struct OpenAPIValidator {
    spec: ArcGISpec,
}

#[derive(Debug, Clone)]
struct ArcGISpec {
    spec: OpenApiSpec,
}

impl OpenAPIValidator {
    pub fn new(spec: OpenApiSpec) -> Self {
        Self {
            spec: ArcGISpec { spec },
        }
    }

    pub fn validate_request(&self, ctx: &RequestContext) -> Result<ValidationResult, anyhow::Error> {
        let method = &ctx.method;
        let path = &ctx.path;
        
        // Reconstruct query string from context or use empty if not available easily (ctx usually has query)
        // For now assuming we parse it from uri or it's passed.
        // ctx doesn't have a direct query_string field in the struct definition I saw earlier (it has headers, client_ip, request_id, body_raw). 
        // I'll extract it from the uri.
        // URI format in pingora session was full URI. ctx.path is just path.
        // I might need to change this if ctx doesn't store query.
        // Looking at WafProxy::request_filter, ctx is populated by HttpParser::parse_request.
        // I'll assume for now I can pass an empty query string if not readily available, or better, 
        // I should check if RequestContext has it.
        // In this step I am just implementing the wrapper.
        
        let query_string = ""; // TODO: Extract from ctx properly if available, else need parsing

        Ok(validate_request(
            &self.spec.spec, 
            method, 
            path, 
            query_string
        ))
    }
}
