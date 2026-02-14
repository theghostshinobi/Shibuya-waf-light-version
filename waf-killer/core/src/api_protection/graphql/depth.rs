use super::parser::GraphQLQuery;
use async_graphql_parser::types::*;
use anyhow::Result;
use std::collections::{HashMap, HashSet};

pub struct DepthAnalyzer {
    max_depth: usize,
}

#[derive(Debug, Clone)]
pub struct DepthAnalysis {
    pub max_depth: usize,
    pub exceeds_limit: bool,
}

impl DepthAnalyzer {
    pub fn new(max_depth: usize) -> Self {
        Self { max_depth }
    }

    pub fn analyze(&self, query: &GraphQLQuery) -> Result<DepthAnalysis> {
        let mut max_depth_found = 0;
        
        for operation in &query.operations {
            let depth = self.calculate_depth(
                &operation.selection_set.node,
                &query.fragments,
                0,
                &mut HashSet::new(),
            )?;
            
            max_depth_found = max_depth_found.max(depth);
        }
        
        Ok(DepthAnalysis {
            max_depth: max_depth_found,
            exceeds_limit: max_depth_found > self.max_depth,
        })
    }
    
    fn calculate_depth(
        &self,
        selection_set: &SelectionSet,
        fragments: &HashMap<String, FragmentDefinition>,
        current_depth: usize,
        visited_fragments: &mut HashSet<String>,
    ) -> Result<usize> {
        let mut max_child_depth = current_depth;
        
        for selection in &selection_set.items {
            match &selection.node {
                Selection::Field(field) => {
                    if field.node.selection_set.node.items.is_empty() {
                        max_child_depth = max_child_depth.max(current_depth + 1);
                    } else {
                        let depth = self.calculate_depth(
                            &field.node.selection_set.node,
                            fragments,
                            current_depth + 1,
                            visited_fragments,
                        )?;
                        max_child_depth = max_child_depth.max(depth);
                    }
                },
                Selection::FragmentSpread(spread) => {
                    let frag_name = spread.node.fragment_name.node.to_string();
                    if visited_fragments.contains(&frag_name) {
                        continue;
                    }
                    
                    visited_fragments.insert(frag_name.clone());
                    
                    if let Some(fragment) = fragments.get(&frag_name) {
                        let depth = self.calculate_depth(
                            &fragment.selection_set.node,
                            fragments,
                            current_depth,
                            visited_fragments,
                        )?;
                        max_child_depth = max_child_depth.max(depth);
                    }
                },
                Selection::InlineFragment(inline) => {
                    let depth = self.calculate_depth(
                        &inline.node.selection_set.node,
                        fragments,
                        current_depth,
                        visited_fragments,
                    )?;
                    max_child_depth = max_child_depth.max(depth);
                },
            }
        }
        
        Ok(max_child_depth)
    }
}
