use super::parser::GraphQLQuery;
use async_graphql_parser::types::*;
use anyhow::Result;
use std::collections::HashMap;

pub struct ComplexityScorer {
    max_complexity: u32,
    field_costs: HashMap<String, u32>,
}

#[derive(Debug, Clone)]
pub struct ComplexityScore {
    pub total: u32,
    pub exceeds_limit: bool,
}

impl ComplexityScorer {
    pub fn new(max_complexity: u32, field_costs: HashMap<String, u32>) -> Self {
        Self { max_complexity, field_costs }
    }

    pub fn score(&self, query: &GraphQLQuery) -> Result<ComplexityScore> {
        let mut total_complexity = 0;
        
        for operation in &query.operations {
            let complexity = self.score_selection_set(
                &operation.selection_set.node,
                &query.fragments,
                1,
            )?;
            
            total_complexity += complexity;
        }
        
        Ok(ComplexityScore {
            total: total_complexity,
            exceeds_limit: total_complexity > self.max_complexity,
        })
    }
    
    fn score_selection_set(
        &self,
        selection_set: &SelectionSet,
        fragments: &HashMap<String, FragmentDefinition>,
        multiplier: u32,
    ) -> Result<u32> {
        let mut complexity = 0;
        
        for selection in &selection_set.items {
            match &selection.node {
                Selection::Field(field) => {
                    let field_name = field.node.name.node.to_string();
                    let field_cost = self.field_costs.get(&field_name).copied().unwrap_or(1);
                    
                    let list_multiplier = self.get_list_multiplier(&field.node);
                    
                    complexity += field_cost * multiplier;
                    
                    if !field.node.selection_set.node.items.is_empty() {
                        complexity += self.score_selection_set(
                            &field.node.selection_set.node,
                            fragments,
                            multiplier * list_multiplier,
                        )?;
                    }
                },
                Selection::FragmentSpread(spread) => {
                    let frag_name = spread.node.fragment_name.node.to_string();
                    if let Some(fragment) = fragments.get(&frag_name) {
                        complexity += self.score_selection_set(
                            &fragment.selection_set.node,
                            fragments,
                            multiplier,
                        )?;
                    }
                },
                Selection::InlineFragment(inline) => {
                    complexity += self.score_selection_set(
                        &inline.node.selection_set.node,
                        fragments,
                        multiplier,
                    )?;
                },
            }
        }
        
        Ok(complexity)
    }
    
    fn get_list_multiplier(&self, field: &Field) -> u32 {
        for arg in &field.arguments {
            let name = arg.0.node.to_string();
            if name == "first" || name == "limit" {
                 if let Value::Number(n) = &arg.1.node {
                     if let Some(i) = n.as_i64() {
                         return (i as u32).min(100);
                     }
                 }
            }
        }
        1
    }
}
