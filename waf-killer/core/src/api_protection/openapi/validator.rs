use regex::Regex;
use std::collections::HashMap;
use super::{OpenApiSpec, Operation};

#[derive(Debug, Clone, PartialEq)]
pub enum ValidationError {
    PathNotFound(String),
    MethodNotAllowed(String),
    InvalidPathParameter {
        param_name: String,
        expected_type: String,
        actual_value: String,
    },
    MissingRequiredQueryParam {
        param_name: String,
    },
    InvalidQueryParameter {
        param_name: String,
        expected_type: String,
        actual_value: String,
    },
    MissingRequestBody,
    InvalidJsonBody {
        reason: String,
    },
    MissingRequiredField {
        field_name: String,
    },
    InvalidFieldType {
        field_name: String,
        expected_type: String,
        actual_type: String,
    },
}

#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub is_valid: bool,
    pub errors: Vec<ValidationError>,
}

impl ValidationResult {
    pub fn valid() -> Self {
        Self {
            is_valid: true,
            errors: vec![],
        }
    }

    pub fn invalid(error: ValidationError) -> Self {
        Self {
            is_valid: false,
            errors: vec![error],
        }
    }
}

/// Parsa query string in una mappa (es. "limit=10&offset=0")
pub fn parse_query_string(query: &str) -> HashMap<String, String> {
    let mut params = HashMap::new();
    
    if query.is_empty() {
        return params;
    }
    
    for pair in query.split('&') {
        if let Some((key, value)) = pair.split_once('=') {
            // URL decode se necessario (per ora versione semplice)
            params.insert(key.to_string(), value.to_string());
        }
    }
    
    params
}

/// Estrae i parametri da un path template (es. /users/{id} -> {"id": "123"})
pub fn extract_path_params(
    template: &str,    // "/users/{id}"
    actual_path: &str, // "/users/123"
) -> Option<HashMap<String, String>> {
    // Converti il template in regex
    // /users/{id} -> ^/users/(?P<id>[^/]+)$
    let mut regex_pattern = template.to_string();
    
    // Trova tutti i placeholder {param}
    let placeholder_re = Regex::new(r"\{([^}]+)\}").unwrap();
    
    for cap in placeholder_re.captures_iter(template) {
        let param_name = &cap[1];
        let placeholder = format!("{{{}}}", param_name);
        let regex_part = format!(r"(?P<{}>[^/]+)", param_name);
        regex_pattern = regex_pattern.replace(&placeholder, &regex_part);
    }
    
    regex_pattern = format!("^{}$", regex_pattern);
    
    let path_regex = Regex::new(&regex_pattern).ok()?;
    let captures = path_regex.captures(actual_path)?;
    
    let mut params = HashMap::new();
    for name in path_regex.capture_names().flatten() {
        if let Some(value) = captures.name(name) {
            params.insert(name.to_string(), value.as_str().to_string());
        }
    }
    
    Some(params)
}

/// Valida che un valore corrisponda al tipo atteso
fn validate_param_type(
    value: &str,
    expected_type: &str,
) -> bool {
    match expected_type {
        "integer" => value.parse::<i64>().is_ok(),
        "number" => value.parse::<f64>().is_ok(),
        "boolean" => matches!(value, "true" | "false"),
        "string" => true, // String è sempre valido
        _ => true, // Tipo sconosciuto, passa
    }
}

/// Valida i path parameters di una richiesta
pub fn validate_path_parameters(
    spec: &OpenApiSpec,
    method: &str,
    path: &str,
) -> ValidationResult {
    // Trova il path template che matcha
    for (template, path_item) in &spec.paths {
        if let Some(params) = extract_path_params(template, path) {
            // Trova l'operation per il metodo HTTP
            let operation = match method.to_uppercase().as_str() {
                "GET" => &path_item.get,
                "POST" => &path_item.post,
                "PUT" => &path_item.put,
                "DELETE" => &path_item.delete,
                _ => &None,
            };
            
            let operation = match operation {
                Some(op) => op,
                None => return ValidationResult::invalid(
                    ValidationError::MethodNotAllowed(method.to_string())
                ),
            };
            
            // Valida ogni parametro
            if let Some(param_defs) = &operation.parameters {
                for param_def in param_defs {
                    if param_def.r#in == "path" {
                        if let Some(actual_value) = params.get(&param_def.name) {
                            if let Some(schema) = &param_def.schema {
                                if !validate_param_type(actual_value, &schema.r#type) {
                                    return ValidationResult::invalid(
                                        ValidationError::InvalidPathParameter {
                                            param_name: param_def.name.clone(),
                                            expected_type: schema.r#type.clone(),
                                            actual_value: actual_value.clone(),
                                        }
                                    );
                                }
                            }
                        }
                    }
                }
            }
            
            return ValidationResult::valid();
        }
    }
    
    ValidationResult::invalid(ValidationError::PathNotFound(path.to_string()))
}

/// Valida i query parameters di una richiesta
pub fn validate_query_parameters(
    operation: &Operation,
    query_string: &str,
) -> Vec<ValidationError> {
    let mut errors = Vec::new();
    
    // Parsa la query string
    let query_params = parse_query_string(query_string);
    
    // Controlla ogni parametro definito nello spec
    if let Some(param_defs) = &operation.parameters {
        for param_def in param_defs {
            // Considera solo query parameters
            if param_def.r#in != "query" {
                continue;
            }
            
            let is_required = param_def.required.unwrap_or(false);
            
            match query_params.get(&param_def.name) {
                Some(actual_value) => {
                    // Parametro presente: valida il tipo
                    if let Some(schema) = &param_def.schema {
                        if !validate_param_type(actual_value, &schema.r#type) {
                            errors.push(ValidationError::InvalidQueryParameter {
                                param_name: param_def.name.clone(),
                                expected_type: schema.r#type.clone(),
                                actual_value: actual_value.clone(),
                            });
                        }
                    }
                }
                None => {
                    // Parametro mancante: errore se required
                    if is_required {
                        errors.push(ValidationError::MissingRequiredQueryParam {
                            param_name: param_def.name.clone(),
                        });
                    }
                }
            }
        }
    }
    
    errors
}

/// Valida l'intera richiesta (path + query)
pub fn validate_request(
    spec: &OpenApiSpec,
    method: &str,
    path: &str,
    query_string: &str,
) -> ValidationResult {
    let mut all_errors = Vec::new();
    
    // Trova il path template che matcha
    for (template, path_item) in &spec.paths {
        if let Some(_params) = extract_path_params(template, path) {
            // Trova l'operation per il metodo HTTP
            let operation = match method.to_uppercase().as_str() {
                "GET" => &path_item.get,
                "POST" => &path_item.post,
                "PUT" => &path_item.put,
                "DELETE" => &path_item.delete,
                _ => &None,
            };
            
            let operation = match operation {
                Some(op) => op,
                None => return ValidationResult::invalid(
                    ValidationError::MethodNotAllowed(method.to_string())
                ),
            };
            
            // Valida path parameters
            let path_result = validate_path_parameters(spec, method, path);
            if !path_result.is_valid {
                all_errors.extend(path_result.errors);
            }
            
            // Valida query parameters
            let query_errors = validate_query_parameters(operation, query_string);
            all_errors.extend(query_errors);
            
            if all_errors.is_empty() {
                return ValidationResult::valid();
            } else {
                return ValidationResult {
                    is_valid: false,
                    errors: all_errors,
                };
            }
        }
    }
    
    ValidationResult::invalid(ValidationError::PathNotFound(path.to_string()))
}


use serde_json::Value as JsonValue;
use super::{JsonSchema};

/// Valida il body JSON contro lo schema
pub fn validate_request_body(
    operation: &Operation,
    body: &str,
) -> Vec<ValidationError> {
    let mut errors = Vec::new();
    
    // Controlla se il body è required
    let body_def = match &operation.request_body {
        Some(rb) => rb,
        None => return errors, // Nessun body atteso
    };
    
    let is_required = body_def.required.unwrap_or(false);
    
    if body.is_empty() {
        if is_required {
            errors.push(ValidationError::MissingRequestBody);
        }
        return errors;
    }
    
    // Parsa il JSON
    let json_value: JsonValue = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => {
            errors.push(ValidationError::InvalidJsonBody {
                reason: format!("Invalid JSON: {}", e),
            });
            return errors;
        }
    };
    
    // Trova lo schema per application/json
    let schema = match body_def.content.get("application/json") {
        Some(media_type) => match &media_type.schema {
            Some(s) => s,
            None => return errors,
        },
        None => return errors,
    };
    
    // Valida contro lo schema
    validate_json_against_schema(&json_value, schema, "", &mut errors);
    
    errors
}

/// Valida ricorsivamente un JSON value contro uno schema
fn validate_json_against_schema(
    value: &JsonValue,
    schema: &JsonSchema,
    path: &str,
    errors: &mut Vec<ValidationError>,
) {
    match schema.r#type.as_str() {
        "object" => {
            let obj = match value.as_object() {
                Some(o) => o,
                None => {
                    errors.push(ValidationError::InvalidFieldType {
                        field_name: path.to_string(),
                        expected_type: "object".to_string(),
                        actual_type: json_type_name(value),
                    });
                    return;
                }
            };
            
            // Controlla campi required
            if let Some(required_fields) = &schema.required {
                for field in required_fields {
                    if !obj.contains_key(field) {
                        errors.push(ValidationError::MissingRequiredField {
                            field_name: format!("{}.{}", path, field).trim_start_matches('.').to_string(),
                        });
                    }
                }
            }
            
            // Valida ogni proprietà
            if let Some(properties) = &schema.properties {
                for (field_name, field_schema) in properties {
                    if let Some(field_value) = obj.get(field_name) {
                        let field_path = if path.is_empty() {
                            field_name.clone()
                        } else {
                            format!("{}.{}", path, field_name)
                        };
                        validate_json_against_schema(field_value, field_schema, &field_path, errors);
                    }
                }
            }
        }
        "string" => {
            if !value.is_string() {
                errors.push(ValidationError::InvalidFieldType {
                    field_name: path.to_string(),
                    expected_type: "string".to_string(),
                    actual_type: json_type_name(value),
                });
            }
        }
        "integer" => {
            if !value.is_i64() && !value.is_u64() {
                errors.push(ValidationError::InvalidFieldType {
                    field_name: path.to_string(),
                    expected_type: "integer".to_string(),
                    actual_type: json_type_name(value),
                });
            }
        }
        "number" => {
            if !value.is_number() {
                errors.push(ValidationError::InvalidFieldType {
                    field_name: path.to_string(),
                    expected_type: "number".to_string(),
                    actual_type: json_type_name(value),
                });
            }
        }
        "boolean" => {
            if !value.is_boolean() {
                errors.push(ValidationError::InvalidFieldType {
                    field_name: path.to_string(),
                    expected_type: "boolean".to_string(),
                    actual_type: json_type_name(value),
                });
            }
        }
        _ => {} // Altri tipi ignorati per ora
    }
}

/// Helper per ottenere il nome del tipo JSON
fn json_type_name(value: &JsonValue) -> String {
    match value {
        JsonValue::Null => "null",
        JsonValue::Bool(_) => "boolean",
        JsonValue::Number(_) => "number",
        JsonValue::String(_) => "string",
        JsonValue::Array(_) => "array",
        JsonValue::Object(_) => "object",
    }.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api_protection::openapi::OpenApiSpec;

    #[test]
    fn test_validate_path_params() {
        let spec = OpenApiSpec::load_from_file("examples/openapi-simple.yaml").unwrap();
        
        // Test valido: /users/123 (id è integer)
        let result = validate_path_parameters(&spec, "GET", "/users/123");
        assert!(result.is_valid);
        
        // Test invalido: /users/abc (id NON è integer)
        let result = validate_path_parameters(&spec, "GET", "/users/abc");
        assert!(!result.is_valid);
    }

    #[test]
    fn test_validate_query_params() {
        let spec = OpenApiSpec::load_from_file("examples/openapi-simple.yaml").unwrap();
        
        // Test valido: ?limit=10
        let result = validate_request(&spec, "GET", "/users", "limit=10");
        assert!(result.is_valid);
        
        // Test invalido: ?limit=abc (deve essere integer)
        let result = validate_request(&spec, "GET", "/users", "limit=abc");
        assert!(!result.is_valid);
    }

    #[test]
    fn test_validate_request_body() {
        let spec = OpenApiSpec::load_from_file("examples/openapi-simple.yaml").unwrap();
        let path_item = spec.paths.get("/users").unwrap();
        let operation = path_item.post.as_ref().unwrap();
        
        // Test valido
        let body = r#"{"email": "test@example.com", "age": 25}"#;
        let errors = validate_request_body(operation, body);
        assert!(errors.is_empty(), "Expected no errors, found: {:?}", errors);
        
        // Test campo mancante
        let body = r#"{"email": "test@example.com"}"#;
        let errors = validate_request_body(operation, body);
        assert!(!errors.is_empty(), "Expected errors for missing required field");
        
        // Test tipo sbagliato
        let body = r#"{"email": "test@example.com", "age": "twenty"}"#;
        let errors = validate_request_body(operation, body);
        assert!(!errors.is_empty(), "Expected errors for invalid field type");
    }
}
