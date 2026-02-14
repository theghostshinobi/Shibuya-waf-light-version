use utoipa::openapi::OpenApi;
use std::collections::HashMap;
use anyhow::{Result, anyhow};
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAPISpec {
    pub info_title: String,
    pub paths: HashMap<String, PathItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathItem {
    pub operations: HashMap<String, Operation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Operation {
    pub operation_id: Option<String>,
    pub parameters: Vec<Parameter>,
    pub request_body: Option<RequestBody>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Parameter {
    pub name: String,
    pub location: ParameterLocation,
    pub required: bool,
    pub schema: Schema,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ParameterLocation {
    Path,
    Query,
    Header,
    Cookie,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestBody {
    pub required: bool,
    pub content: HashMap<String, MediaType>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaType {
    pub schema: Schema,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Schema {
    pub schema_type: SchemaType,
    pub format: Option<String>,
    pub pattern: Option<String>,
    pub min_length: Option<usize>,
    pub max_length: Option<usize>,
    pub minimum: Option<f64>,
    pub maximum: Option<f64>,
    pub enum_values: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SchemaType {
    String,
    Number,
    Integer,
    Boolean,
    Array,
    Object,
    Null,
}

impl OpenAPISpec {
    pub fn from_yaml(yaml: &str) -> Result<Self> {
        let spec: OpenApi = serde_yaml::from_str(yaml)?;
        Self::convert(spec)
    }

    pub fn from_json(json: &str) -> Result<Self> {
        let spec: OpenApi = serde_json::from_str(json)?;
        Self::convert(spec)
    }

    fn convert(spec: OpenApi) -> Result<Self> {
        let mut paths = HashMap::new();

        for (path, item) in spec.paths.paths {
            let mut operations = HashMap::new();

            if let Some(op) = &item.get {
                operations.insert("GET".to_string(), Self::convert_operation(op, &spec)?);
            }
            if let Some(op) = &item.post {
                operations.insert("POST".to_string(), Self::convert_operation(op, &spec)?);
            }
            if let Some(op) = &item.put {
                operations.insert("PUT".to_string(), Self::convert_operation(op, &spec)?);
            }
            if let Some(op) = &item.delete {
                operations.insert("DELETE".to_string(), Self::convert_operation(op, &spec)?);
            }
            if let Some(op) = &item.patch {
                operations.insert("PATCH".to_string(), Self::convert_operation(op, &spec)?);
            }

            paths.insert(path, PathItem { operations });
        }

        Ok(Self {
            info_title: spec.info.title,
            paths,
        })
    }

    fn convert_operation(op: &utoipa::openapi::path::Operation, _spec: &OpenApi) -> Result<Operation> {
        let mut parameters = Vec::new();

        if let Some(params) = &op.parameters {
            for param in params {
                parameters.push(Parameter {
                    name: param.name.clone(),
                    location: match param.in_property {
                        utoipa::openapi::path::ParameterIn::Path => ParameterLocation::Path,
                        utoipa::openapi::path::ParameterIn::Query => ParameterLocation::Query,
                        utoipa::openapi::path::ParameterIn::Header => ParameterLocation::Header,
                        utoipa::openapi::path::ParameterIn::Cookie => ParameterLocation::Cookie,
                    },
                    required: param.required.into(), // it's Required (bool) or Default(bool)
                    schema: Self::convert_schema(&param.schema)?,
                });
            }
        }

        let request_body = if let Some(body) = &op.request_body {
             let mut content = HashMap::new();
             for (mime, media) in &body.content {
                 content.insert(mime.clone(), MediaType {
                     schema: Self::convert_schema(&media.schema)?,
                 });
             }
             Some(RequestBody {
                 required: body.required.map(|r| r.into()).unwrap_or(false),
                 content,
             })
        } else {
            None
        };

        Ok(Operation {
            operation_id: op.operation_id.clone(),
            parameters,
            request_body,
        })
    }

    fn convert_schema(schema: &utoipa::openapi::RefOr<utoipa::openapi::schema::Schema>) -> Result<Schema> {
        match schema {
            utoipa::openapi::RefOr::Ref(_r) => {
                // TODO: handle references properly by looking up in components
                // For now, return a placeholder or error if not resolved
                Ok(Schema {
                    schema_type: SchemaType::Object,
                    format: None,
                    pattern: None,
                    min_length: None,
                    max_length: None,
                    minimum: None,
                    maximum: None,
                    enum_values: None,
                })
            }
            utoipa::openapi::RefOr::T(s) => {
                match s {
                    utoipa::openapi::schema::Schema::Object(obj) => {
                        Ok(Schema {
                            schema_type: match obj.schema_type {
                                utoipa::openapi::schema::SchemaType::Type(t) => match t {
                                    utoipa::openapi::schema::Type::String => SchemaType::String,
                                    utoipa::openapi::schema::Type::Number => SchemaType::Number,
                                    utoipa::openapi::schema::Type::Integer => SchemaType::Integer,
                                    utoipa::openapi::schema::Type::Boolean => SchemaType::Boolean,
                                    utoipa::openapi::schema::Type::Array => SchemaType::Array,
                                    utoipa::openapi::schema::Type::Object => SchemaType::Object,
                                    utoipa::openapi::schema::Type::Null => SchemaType::Null,
                                },
                                _ => SchemaType::Object,
                            },
                            format: obj.format.as_ref().map(|f| format!("{:?}", f)),
                            pattern: obj.pattern.clone(),
                            min_length: obj.min_length.map(|m| m as usize),
                            max_length: obj.max_length.map(|m| m as usize),
                            minimum: obj.minimum,
                            maximum: obj.maximum,
                            enum_values: obj.enum_values.as_ref().map(|ev| {
                                ev.iter().map(|v| v.to_string()).collect()
                            }),
                        })
                    }
                    _ => {
                        // Handle other schema variants or return default
                         Ok(Schema {
                            schema_type: SchemaType::Object,
                            format: None,
                            pattern: None,
                            min_length: None,
                            max_length: None,
                            minimum: None,
                            maximum: None,
                            enum_values: None,
                        })
                    }
                }
            }
        }
    }

    pub fn find_operation(&self, method: &str, path: &str) -> Option<&Operation> {
        for (path_pattern, path_item) in &self.paths {
            if self.match_path(path_pattern, path).is_some() {
                return path_item.operations.get(method);
            }
        }
        None
    }

    pub fn get_path_params(&self, path_pattern: &str, actual_path: &str) -> HashMap<String, String> {
        self.match_path(path_pattern, actual_path).unwrap_or_default()
    }

    fn match_path(&self, pattern: &str, actual: &str) -> Option<HashMap<String, String>> {
        let regex_pattern = pattern
            .split('/')
            .map(|segment| {
                if segment.starts_with('{') && segment.ends_with('}') {
                    let param_name = &segment[1..segment.len()-1];
                    format!(r"(?P<{}>[^/]+)", param_name)
                } else {
                    regex::escape(segment)
                }
            })
            .collect::<Vec<_>>()
            .join("/");

        let regex = Regex::new(&format!("^{}$", regex_pattern)).ok()?;

        regex.captures(actual).map(|captures| {
            let mut params = HashMap::new();
            for name in regex.capture_names().flatten() {
                if let Some(m) = captures.name(name) {
                    params.insert(name.to_string(), m.as_str().to_string());
                }
            }
            params
        })
    }
}
