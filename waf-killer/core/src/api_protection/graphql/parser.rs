use async_graphql_parser::{parse_query, types::*};
use anyhow::{Result, anyhow};
use std::collections::HashMap;

pub struct GraphQLQuery {
    pub operations: Vec<OperationDefinition>,
    pub fragments: HashMap<String, FragmentDefinition>,
}

impl GraphQLQuery {
    pub fn parse(query: &str) -> Result<Self> {
        let document = parse_query(query).map_err(|e| anyhow!("GraphQL parse error: {}", e))?;
        
        let mut operations = Vec::new();
        let mut fragments = HashMap::new();
        
        for definition in document.definitions {
            match definition.node {
                Definition::Operation(op) => {
                    operations.push(op.node);
                },
                Definition::Fragment(frag) => {
                    fragments.insert(frag.node.name.node.to_string(), frag.node);
                },
            }
        }
        
        Ok(Self { operations, fragments })
    }
}
