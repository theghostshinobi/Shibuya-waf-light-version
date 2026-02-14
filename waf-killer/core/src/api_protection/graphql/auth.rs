use super::parser::GraphQLQuery;
use async_graphql_parser::types::*;
use anyhow::Result;

pub struct FieldAuthorizer {
    rules: Vec<AuthRule>,
}

pub struct AuthRule {
    pub field_path: String,
    pub required_roles: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct AuthorizationResult {
    pub authorized: bool,
    pub violations: Vec<String>,
}

impl FieldAuthorizer {
    pub fn new(rules: Vec<AuthRule>) -> Self {
        Self { rules }
    }

    pub fn authorize(&self, query: &GraphQLQuery, user_roles: &[String]) -> Result<AuthorizationResult> {
        let mut violations = Vec::new();
        
        for operation in &query.operations {
            self.check_selection_set(
                &operation.selection_set.node,
                user_roles,
                "",
                &mut violations,
            );
        }
        
        Ok(AuthorizationResult {
            authorized: violations.is_empty(),
            violations,
        })
    }
    
    fn check_selection_set(
        &self,
        selection_set: &SelectionSet,
        user_roles: &[String],
        parent_path: &str,
        violations: &mut Vec<String>,
    ) {
        for selection in &selection_set.items {
            if let Selection::Field(field) = &selection.node {
                let field_name = field.node.name.node.to_string();
                let current_path = if parent_path.is_empty() {
                    field_name.clone()
                } else {
                    format!("{}.{}", parent_path, field_name)
                };
                
                for rule in &self.rules {
                    if rule.field_path == current_path {
                        if !rule.required_roles.iter().any(|r| user_roles.contains(r)) {
                            violations.push(format!("Access to {} denied", current_path));
                        }
                    }
                }
                
                if !field.node.selection_set.node.items.is_empty() {
                    self.check_selection_set(
                        &field.node.selection_set.node,
                        user_roles,
                        &current_path,
                        violations,
                    );
                }
            }
        }
    }
}
