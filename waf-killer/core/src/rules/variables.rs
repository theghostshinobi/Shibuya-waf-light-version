use crate::parser::context::RequestContext;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub enum Variable {
    Args,
    ArgsNames,
    ArgsSpecific(String),
    ArgsCombinedSize,
    RequestHeaders,
    RequestHeadersSpecific(String),
    RequestHeadersNames,
    RequestCookies,
    RequestCookiesSpecific(String),
    RequestCookiesNames,
    RequestBody,
    RequestUri,
    RequestFilename,
    RequestMethod,
    RemoteAddr,
    QueryString,
    RequestBasename,
    RequestLine,
    RequestProtocol,
    Tx(String),
    TxSpecific(String),
    Geo(String), // Placeholder for GeoIP
    Duration,    // Transaction duration
}

pub fn extract_variable(var: &Variable, ctx: &RequestContext) -> Vec<String> {
    match var {
        Variable::Args => {
            let mut values: Vec<String> = Vec::new();
            // From Query Params
            for (_, vals) in &ctx.query_params {
                values.extend(vals.clone()); 
            }
            // From Body if form/json
            if let Some(form) = &ctx.body_form {
                 for (_, vals) in form {
                      values.extend(vals.clone());
                 }
            }
            values
        },
        Variable::ArgsNames => {
            let mut names: Vec<String> = Vec::new();
            for (key, _) in &ctx.query_params {
                names.push(key.clone());
            }
            if let Some(form) = &ctx.body_form {
                for (key, _) in form {
                    names.push(key.clone());
                }
            }
            names
        },
        Variable::ArgsSpecific(name) => {
             let mut values: Vec<String> = Vec::new();
             if let Some(vals) = ctx.query_params.get(name) {
                 values.extend(vals.clone());
             }
             if let Some(form) = &ctx.body_form {
                 if let Some(vals) = form.get(name) {
                      values.extend(vals.clone());
                 }
             }
             values
        },
        Variable::ArgsCombinedSize => {
            let mut total: usize = 0;
            for (k, vs) in &ctx.query_params {
                total += k.len();
                for v in vs { total += v.len(); }
            }
            if let Some(form) = &ctx.body_form {
                for (k, vs) in form {
                    total += k.len();
                    for v in vs { total += v.len(); }
                }
            }
            vec![total.to_string()]
        },
        Variable::RequestHeaders => {
             let mut values: Vec<String> = Vec::new();
             for (_, vals) in &ctx.headers {
                  values.extend(vals.clone());
             }
             values
        },
        Variable::RequestHeadersSpecific(name) => {
            let mut values: Vec<String> = Vec::new();
             for (k, vals) in &ctx.headers {
                 if k.eq_ignore_ascii_case(name) {
                     values.extend(vals.clone());
                 }
             }
             values
        },
        Variable::RequestHeadersNames => {
            ctx.headers.keys().cloned().collect()
        },
        Variable::RequestCookies => {
            ctx.cookies.values().cloned().collect()
        },
        Variable::RequestCookiesSpecific(name) => {
            if let Some(val) = ctx.cookies.get(name) {
                vec![val.clone()]
            } else {
                vec![]
            }
        },
        Variable::RequestCookiesNames => {
            ctx.cookies.keys().cloned().collect()
        },
        Variable::RequestMethod => vec![ctx.method.to_string()],
        Variable::RequestUri => vec![ctx.uri.to_string()],
        Variable::RequestFilename => vec![ctx.path.to_string()],
        Variable::RemoteAddr => vec![ctx.client_ip.to_string()],
        Variable::QueryString => {
            if ctx.query_string.is_empty() {
                vec![]
            } else {
                vec![ctx.query_string.clone()]
            }
        },
        Variable::RequestBasename => {
            let basename = ctx.path.rsplit('/').next().unwrap_or(&ctx.path);
            vec![basename.to_string()]
        },
        Variable::RequestLine => {
            vec![format!("{} {} {}", ctx.method, ctx.uri, ctx.protocol)]
        },
        Variable::RequestProtocol => vec![ctx.protocol.to_string()],
        Variable::RequestBody => {
            if let Some(text) = &ctx.body_text {
                vec![text.clone()]
            } else if let Some(raw) = &ctx.body_raw {
                vec![String::from_utf8_lossy(raw).to_string()]
            } else {
                vec![]
            }
        },
        Variable::Tx(_) | Variable::TxSpecific(_) => {
            // TX variables are transaction-scoped; handled by scoring context
            vec![]
        },
        Variable::Geo(_) => vec![], // Placeholder for GeoIP
        Variable::Duration => vec!["0".to_string()], // Placeholder
    }
}
