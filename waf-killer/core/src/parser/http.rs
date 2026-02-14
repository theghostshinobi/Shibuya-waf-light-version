use crate::parser::body::parse_body;
use crate::parser::context::{RequestContext, TransformedData};
use crate::parser::transforms::{TransformPipeline, count_special_chars, calculate_entropy};
use anyhow::Result;
use bytes::Bytes;
use pingora::http::RequestHeader;

pub struct HttpParser;

impl HttpParser {
    pub async fn parse_request(
        req_header: &RequestHeader,
        body_bytes: Bytes,
        request_id: String,
        client_ip: String,
    ) -> Result<RequestContext> {
        let mut ctx = RequestContext::new(request_id, client_ip);
        
        // 1. Basic HTTP Info
        ctx.method = req_header.method.as_str().to_string();
        ctx.uri = req_header.uri.to_string();
        ctx.path = req_header.uri.path().to_string();
        ctx.protocol = format!("{:?}", req_header.version); // e.g. HTTP/1.1
        
        if let Some(host) = req_header.headers.get("Host") {
            ctx.server_name = host.to_str().unwrap_or_default().to_string();
        }

        // 2. Headers
        for (name, value) in req_header.headers.iter() {
            let key = name.as_str().to_lowercase();
            let val = value.to_str().unwrap_or("").to_string();
            ctx.headers.entry(key).or_default().push(val);
        }
        
        // 3. Query String & Params
        if let Some(query) = req_header.uri.query() {
            ctx.query_string = query.to_string();
            
            // Parse query params manually or use serde_urlencoded
            // Managing multiple values manualy for better control:
            for pair in query.split('&') {
                 if pair.is_empty() { continue; }
                 let mut parts = pair.splitn(2, '=');
                 let key = parts.next().unwrap_or("");
                 let value = parts.next().unwrap_or("");
                 
                 // Decode key/value here roughly, but strict decoding happens in transforms
                 // We store raw-ish here
                 let decoded_key = urlencoding::decode(key).unwrap_or_default().into_owned();
                 let decoded_val = urlencoding::decode(value).unwrap_or_default().into_owned();
                 
                 ctx.query_params.entry(decoded_key).or_default().push(decoded_val);
            }
        }

        // 4. Body Parsing
        let content_type = ctx.headers.get("content-type").and_then(|v| v.first()).map(|s| s.to_string());
        parse_body(&mut ctx, content_type.as_deref(), body_bytes).await?;
        
        // 5. Transformations & Inspection Metadata
        Self::apply_transformations_and_metadata(&mut ctx);
        
        Ok(ctx)
    }

    fn apply_transformations_and_metadata(ctx: &mut RequestContext) {
        let mut t = TransformedData::default();
        let mut all_data_for_entropy = String::new();
        
        // URI
        t.uri_decoded = TransformPipeline::apply(&ctx.uri);
        all_data_for_entropy.push_str(&ctx.uri);
        
        // Query Params
        for (k, vs) in &ctx.query_params {
            let tk = TransformPipeline::apply(k);
            t.all_args.push(tk.clone());
            
            let mut tvs = Vec::new();
            for v in vs {
                let tv = TransformPipeline::apply(v);
                tvs.push(tv.clone());
                t.all_values.push(tv);
                all_data_for_entropy.push_str(v);
            }
            t.query_params_decoded.insert(tk, tvs);
        }
        
        // Body (if applicable)
        if let Some(text) = &ctx.body_text {
            let t_body = TransformPipeline::apply(text);
            t.body_decoded = Some(t_body.clone());
            t.all_values.push(t_body);
             all_data_for_entropy.push_str(text);
        } else if let Some(json) = &ctx.body_json {
             // Flatten JSON values
             // Complex logic needed here to walk the JSON tree, for now simple implementation
             let json_str = json.to_string();
             let t_body = TransformPipeline::apply(&json_str);
             t.body_decoded = Some(t_body); // Store full string representation
             // Ideally we extract values
             all_data_for_entropy.push_str(&json_str);
        } else if let Some(form) = &ctx.body_form {
            for (k, vs) in form {
                let tk = TransformPipeline::apply(k);
                 t.all_args.push(tk.clone());
                 for v in vs {
                     let tv = TransformPipeline::apply(v);
                     t.all_values.push(tv);
                     all_data_for_entropy.push_str(v);
                 }
            }
        }
        
        // Headers (Selective or All)
        for (k, vs) in &ctx.headers {
            // We usually inspect specific headers like User-Agent, Referer, Cookie, X-Forwarded-For
            // For now, let's normalize all
             let tk = TransformPipeline::apply(k);
             let mut tvs = Vec::new();
             for v in vs {
                 let tv = TransformPipeline::apply(v);
                 tvs.push(tv);
                 // We don't usually add headers to "all_values" unless they are payload carriers
                 if ["user-agent", "referer", "cookie"].contains(&k.as_str()) {
                      all_data_for_entropy.push_str(v);
                 }
             }
             t.headers_normalized.insert(tk, tvs);
        }

        ctx.transformed = t;
        
        // Metadata
        ctx.inspection_metadata.special_char_count = count_special_chars(&all_data_for_entropy);
        ctx.inspection_metadata.entropy = calculate_entropy(&all_data_for_entropy);
        
        // Suspicious patterns (Simple examples)
        if ctx.inspection_metadata.entropy > 7.0 {
            ctx.inspection_metadata.suspicious_patterns.push("High Entropy".to_string());
        }
    }
}
