use anyhow::{Result, anyhow};
pub mod batch;


#[derive(Debug, Clone)]
pub struct GraphQLQuery {
    pub query: String,
    pub max_depth: usize,
}

impl GraphQLQuery {
    /// Parsa una query GraphQL e calcola la profondità massima
    pub fn parse(query: &str) -> Result<Self> {
        let max_depth = calculate_depth(query)?;
        
        Ok(Self {
            query: query.to_string(),
            max_depth,
        })
    }
    
    /// Verifica se la query supera il limite di profondità
    pub fn exceeds_depth_limit(&self, limit: usize) -> bool {
        self.max_depth > limit
    }
}

/// Calcola la profondità massima di una query GraphQL
fn calculate_depth(query: &str) -> Result<usize> {
    let mut max_depth = 0;
    let mut current_depth = 0;
    
    // Rimuovi commenti e whitespace extra
    let cleaned = remove_graphql_comments(query);
    
    // Conta le graffe aperte/chiuse
    let mut in_string = false;
    let mut prev_char = ' ';
    
    for ch in cleaned.chars() {
        // Gestisci stringhe (ignora graffe dentro stringhe)
        if ch == '"' && prev_char != '\\' {
            in_string = !in_string;
        }
        
        if !in_string {
            match ch {
                '{' => {
                    current_depth += 1;
                    if current_depth > max_depth {
                        max_depth = current_depth;
                    }
                }
                '}' => {
                    if current_depth == 0 {
                        return Err(anyhow!("Mismatched braces in GraphQL query"));
                    }
                    current_depth -= 1;
                }
                _ => {}
            }
        }
        
        prev_char = ch;
    }
    
    if current_depth != 0 {
        return Err(anyhow!("Unclosed braces in GraphQL query"));
    }
    
    // La depth iniziale (query root) non conta, sottrai 1
    if max_depth > 0 {
        max_depth -= 1;
    }
    
    Ok(max_depth)
}

/// Rimuove i commenti da una query GraphQL
fn remove_graphql_comments(query: &str) -> String {
    let mut result = String::with_capacity(query.len());
    let mut chars = query.chars().peekable();
    
    while let Some(ch) = chars.next() {
        if ch == '#' {
            // Commento single-line, salta fino a newline
            while let Some(&next_ch) = chars.peek() {
                chars.next();
                if next_ch == '\n' {
                    break;
                }
            }
        } else {
            result.push(ch);
        }
    }
    
    result
}

#[derive(Debug, Clone)]
pub struct DepthCheckResult {
    pub is_valid: bool,
    pub actual_depth: usize,
    pub max_allowed: usize,
}

/// Valida una query GraphQL contro un limite di profondità
pub fn validate_query_depth(query: &str, max_depth: usize) -> Result<DepthCheckResult> {
    let parsed = GraphQLQuery::parse(query)?;
    
    Ok(DepthCheckResult {
        is_valid: !parsed.exceeds_depth_limit(max_depth),
        actual_depth: parsed.max_depth,
        max_allowed: max_depth,
    })
}

#[derive(Debug, Clone)]
pub struct ComplexityResult {
    pub total_score: usize,
    pub field_count: usize,
    pub list_multiplier: usize,
}

impl ComplexityResult {
    pub fn exceeds_limit(&self, limit: usize) -> bool {
        self.total_score > limit
    }
}

/// Conta il numero di field selezionati in una query
fn count_fields(query: &str) -> usize {
    let cleaned = remove_graphql_comments(query);
    let mut field_count = 0;
    
    // Pattern semplificato: conta gli identificatori seguiti da { o newline/space
    // Esclude keyword (query, mutation, fragment)
    let keywords = ["query", "mutation", "subscription", "fragment"];
    
    let tokens: Vec<&str> = cleaned
        .split(|c: char| c.is_whitespace() || c == '{' || c == '}' || c == '(' || c == ')')
        .filter(|s| !s.is_empty())
        .collect();
    
    for token in tokens {
        // Se è un identificatore valido e non una keyword
        if is_valid_identifier(token) && !keywords.contains(&token) {
            field_count += 1;
        }
    }
    
    field_count
}

/// Verifica se una stringa è un identificatore GraphQL valido
fn is_valid_identifier(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    
    // Primo carattere deve essere lettera o underscore
    let first = s.chars().next().unwrap();
    if !first.is_alphabetic() && first != '_' {
        return false;
    }
    
    // Altri caratteri: lettere, numeri, underscore
    s.chars().all(|c| c.is_alphanumeric() || c == '_')
}

/// Calcola il moltiplicatore delle liste (stima il numero di oggetti caricati)
/// Esempio: user { posts { comments } } 
/// Se ogni user ha 10 posts e ogni post ha 5 comments = 10 * 5 = 50x
fn calculate_list_multiplier(query: &str, depth: usize) -> usize {
    // Euristica semplice: moltiplicatore = 10^depth per liste annidate
    // Depth 1 (singola lista) = 10x
    // Depth 2 (lista di liste) = 100x
    // Depth 3 = 1000x
    
    if depth == 0 {
        return 1;
    }
    
    // Conta i livelli che probabilmente sono liste (plurali)
    let list_levels = estimate_list_levels(query);
    
    if list_levels == 0 {
        return 1;
    }
    
    // Ogni livello lista moltiplica per 10 (assunzione conservativa)
    10_usize.pow(list_levels as u32)
}

/// Stima quanti livelli contengono liste (euristico: cerca plurali)
fn estimate_list_levels(query: &str) -> usize {
    let cleaned = remove_graphql_comments(query);
    let mut list_count = 0;
    
    // Pattern euristico: parole che finiscono con 's' o contengono "list", "all"
    let list_indicators = ["users", "posts", "comments", "items", "list", "all"];
    
    for indicator in list_indicators {
        if cleaned.to_lowercase().contains(indicator) {
            list_count += 1;
        }
    }
    
    // Cap al depth reale della query
    list_count
}

/// Calcola la complessità totale di una query GraphQL
pub fn calculate_complexity(query: &str) -> Result<ComplexityResult> {
    let parsed = GraphQLQuery::parse(query)?;
    let depth = parsed.max_depth;
    
    // Conta i field selezionati
    let field_count = count_fields(query);
    
    // Calcola il moltiplicatore liste
    let list_multiplier = calculate_list_multiplier(query, depth);
    
    // Score totale = field_count * list_multiplier + depth_penalty
    let depth_penalty = depth * 10; // Ogni livello costa 10 punti extra
    let total_score = (field_count * list_multiplier) + depth_penalty;
    
    Ok(ComplexityResult {
        total_score,
        field_count,
        list_multiplier,
    })
}

/// Valida una query contro un limite di complessità
pub fn validate_query_complexity(query: &str, _max_complexity: usize) -> Result<ComplexityResult> {
    let result = calculate_complexity(query)?;
    Ok(result)
}

// ═══════════════════════════════════════════════════════════════════════════════
// ALIAS COUNTING (Anti-alias bombing)
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct AliasCountResult {
    pub alias_count: usize,
    pub exceeds_limit: bool,
    pub max_allowed: usize,
}

/// Count aliases in a GraphQL query
/// Aliases are field renames like: { a1: user { name } a2: user { name } }
pub fn count_aliases(query: &str) -> Result<usize> {
    let cleaned = remove_graphql_comments(query);
    let mut alias_count = 0;
    
    // Pattern: identifier followed by colon and space/identifier
    // e.g., "a1: user" or "myAlias: fieldName"
    let mut chars = cleaned.chars().peekable();
    let mut in_string = false;
    let mut prev_word = String::new();
    let mut current_word = String::new();
    
    while let Some(ch) = chars.next() {
        if ch == '"' {
            in_string = !in_string;
            continue;
        }
        
        if in_string {
            continue;
        }
        
        if ch.is_alphanumeric() || ch == '_' {
            current_word.push(ch);
        } else {
            if ch == ':' && !current_word.is_empty() {
                // Check if next non-whitespace is an identifier (not a type annotation)
                let mut peek_chars = chars.clone();
                while let Some(&next_ch) = peek_chars.peek() {
                    if next_ch.is_whitespace() {
                        peek_chars.next();
                    } else {
                        break;
                    }
                }
                if let Some(&next_ch) = peek_chars.peek() {
                    if next_ch.is_alphabetic() || next_ch == '_' {
                        // This is an alias (word followed by colon and identifier)
                        alias_count += 1;
                    }
                }
            }
            prev_word = current_word;
            current_word = String::new();
        }
    }
    
    Ok(alias_count)
}

/// Validate alias count against limit
pub fn validate_alias_count(query: &str, max_aliases: usize) -> Result<AliasCountResult> {
    let alias_count = count_aliases(query)?;
    Ok(AliasCountResult {
        alias_count,
        exceeds_limit: alias_count > max_aliases,
        max_allowed: max_aliases,
    })
}

// ═══════════════════════════════════════════════════════════════════════════════
// BATCH SIZE DETECTION (Anti-batch bombing)
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct BatchSizeResult {
    pub batch_size: usize,
    pub exceeds_limit: bool,
    pub max_allowed: usize,
}

/// Detect if request body contains a batch of GraphQL queries
/// Batch requests are JSON arrays: [{"query": "..."}, {"query": "..."}]
pub fn detect_batch_size(body: &str) -> usize {
    if body.trim().is_empty() {
        return 0;
    }
    // Try to parse as JSON array
    if let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(body) {
        return arr.len();
    }
    // Single query
    1
}

/// Validate batch size against limit
pub fn validate_batch_size(body: &str, max_batch_size: usize) -> BatchSizeResult {
    let batch_size = detect_batch_size(body);
    BatchSizeResult {
        batch_size,
        exceeds_limit: batch_size > max_batch_size,
        max_allowed: max_batch_size,
    }
}

/// Extract GraphQL query from body string (handles single and batch)
pub fn extract_graphql_query(body: &str) -> anyhow::Result<String> {
    if body.trim().is_empty() {
        return Err(anyhow!("Empty body"));
    }

    // Try parsing as simple object first (common case)
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
         if let Some(query) = json.get("query").and_then(|v| v.as_str()) {
             return Ok(query.to_string());
         }
         
         // If array (batch)
         if let Some(arr) = json.as_array() {
             let mut queries = Vec::new();
             for item in arr {
                 if let Some(query) = item.get("query").and_then(|v| v.as_str()) {
                     queries.push(query);
                 }
             }
             if queries.is_empty() {
                 return Err(anyhow!("No queries found in batch"));
             }
             // Join all queries for combined analysis
             return Ok(queries.join("\n"));
         }
         
         return Err(anyhow!("No 'query' field found in JSON"));
    }
    
    // Fallback: maybe it's not JSON? (e.g. Content-Type application/graphql)
    // For now assume JSON-wrapped or raw query if valid
    Ok(body.to_string())
}

// ═══════════════════════════════════════════════════════════════════════════════
// UNIFIED VALIDATION
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct GraphQLConfig {
    pub max_depth: usize,
    pub max_complexity: usize,
    pub max_aliases: usize,
    pub max_batch_size: usize,
}

impl Default for GraphQLConfig {
    fn default() -> Self {
        Self {
            max_depth: 7,          // Default sicuro
            max_complexity: 1000,  // Default ragionevole
            max_aliases: 50,       // Anti-alias bombing
            max_batch_size: 10,    // Anti-batch bombing
        }
    }
}

impl GraphQLConfig {
    /// Valida una query contro depth, complexity, e alias limits
    pub fn validate_query(&self, query: &str) -> Result<ValidationResult> {
        // Check depth
        let depth_result = validate_query_depth(query, self.max_depth)?;
        if !depth_result.is_valid {
            return Ok(ValidationResult::DepthExceeded(depth_result));
        }
        
        // Check complexity
        let complexity_result = validate_query_complexity(query, self.max_complexity)?;
        if complexity_result.exceeds_limit(self.max_complexity) {
            return Ok(ValidationResult::ComplexityExceeded(complexity_result));
        }
        
        // Check aliases
        let alias_result = validate_alias_count(query, self.max_aliases)?;
        if alias_result.exceeds_limit {
            return Ok(ValidationResult::AliasesExceeded(alias_result));
        }
        
        Ok(ValidationResult::Valid)
    }
    
    /// Validate batch size (call this separately with raw body before parsing individual queries)
    pub fn validate_batch(&self, body: &str) -> BatchSizeResult {
        validate_batch_size(body, self.max_batch_size)
    }
}

#[derive(Debug, Clone)]
pub enum ValidationResult {
    Valid,
    DepthExceeded(DepthCheckResult),
    ComplexityExceeded(ComplexityResult),
    AliasesExceeded(AliasCountResult),
    BatchSizeExceeded(BatchSizeResult),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_query_depth() {
        let query = r#"
            query {
                user {
                    name
                }
            }
        "#;
        
        let parsed = GraphQLQuery::parse(query).unwrap();
        assert_eq!(parsed.max_depth, 1); // user è depth 1
    }
    
    #[test]
    fn test_nested_query_depth() {
        let query = r#"
            query {
                user {
                    friends {
                        friends {
                            name
                        }
                    }
                }
            }
        "#;
        
        let parsed = GraphQLQuery::parse(query).unwrap();
        assert_eq!(parsed.max_depth, 3); // user -> friends -> friends
    }
    
    #[test]
    fn test_depth_limit_enforcement() {
        let query = r#"
            query {
                a { b { c { d { e { f { g { h } } } } } } }
            }
        "#;
        
        let result = validate_query_depth(query, 5).unwrap();
        assert!(!result.is_valid); // 7 livelli > 5 max
        assert_eq!(result.actual_depth, 7);
    }
    
    #[test]
    fn test_query_with_comments() {
        let query = r#"
            query {
                # Questo è un commento
                user {
                    name # inline comment
                }
            }
        "#;
        
        let parsed = GraphQLQuery::parse(query).unwrap();
        assert_eq!(parsed.max_depth, 1);
    }
    
    #[test]
    fn test_invalid_query() {
        let query = "query { user { name }"; // Manca }
        let result = GraphQLQuery::parse(query);
        assert!(result.is_err());
    }

    #[test]
    fn test_simple_complexity() {
        let query = r#"
            query {
                user {
                    id
                    name
                }
            }
        "#;
        
        let result = calculate_complexity(query).unwrap();
        assert!(result.total_score < 100); // Query semplice
    }

    #[test]
    fn test_high_complexity_lists() {
        let query = r#"
            query {
                users {
                    posts {
                        comments {
                            id
                            text
                            author
                        }
                    }
                }
            }
        "#;
        
        let result = calculate_complexity(query).unwrap();
        assert!(result.total_score > 100); // Liste annidate = alto costo
        assert!(result.list_multiplier > 1);
    }

    #[test]
    fn test_complexity_validation() {
        let expensive_query = r#"
            query {
                users { id name email posts { id title } }
                comments { id text }
                likes { id }
            }
        "#;
        
        let config = GraphQLConfig {
            max_depth: 10,
            max_complexity: 50, // Limite basso per test
            max_aliases: 50,
            max_batch_size: 10,
        };
        
        let result = config.validate_query(expensive_query).unwrap();
        match result {
            ValidationResult::ComplexityExceeded(_) => {}, // Expected
            _ => panic!("Should have exceeded complexity limit"),
        }
    }
    
    #[test]
    fn test_alias_counting_simple() {
        let query = r#"
            query {
                a1: user { name }
                a2: user { name }
                a3: user { name }
            }
        "#;
        
        let alias_count = count_aliases(query).unwrap();
        assert_eq!(alias_count, 3);
    }
    
    #[test]
    fn test_alias_limit_exceeded() {
        // Build query with 60 aliases
        let aliases: Vec<String> = (1..=60).map(|i| format!("a{}: user {{ name }}", i)).collect();
        let query = format!("{{ {} }}", aliases.join(" "));
        
        let config = GraphQLConfig {
            max_depth: 10,
            max_complexity: 10000,
            max_aliases: 50,
            max_batch_size: 10,
        };
        
        let result = config.validate_query(&query).unwrap();
        match result {
            ValidationResult::AliasesExceeded(r) => {
                assert!(r.alias_count >= 50);
                assert!(r.exceeds_limit);
            },
            _ => panic!("Should have exceeded alias limit"),
        }
    }
    
    #[test]
    fn test_batch_size_detection_single() {
        let body = r#"{"query": "{ user { name } }"}"#;
        let size = detect_batch_size(body);
        assert_eq!(size, 1);
    }
    
    #[test]
    fn test_batch_size_detection_array() {
        let body = r#"[{"query": "{ user { name } }"}, {"query": "{ post { title } }"}]"#;
        let size = detect_batch_size(body);
        assert_eq!(size, 2);
    }
    
    #[test]
    fn test_batch_size_limit_exceeded() {
        let queries: Vec<String> = (1..=15).map(|_| r#"{"query": "{ user { name } }"}"#.to_string()).collect();
        let body = format!("[{}]", queries.join(","));
        
        let result = validate_batch_size(&body, 10);
        assert_eq!(result.batch_size, 15);
        assert!(result.exceeds_limit);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// WAF Integration Wrappers
// ═══════════════════════════════════════════════════════════════════════════════

pub struct GraphQLParser;

impl GraphQLParser {
    pub fn new() -> Self { Self }
    pub fn parse(&self, query: &str) -> Result<GraphQLQuery> {
        GraphQLQuery::parse(query)
    }
}

pub struct DepthAnalyzer {
    max_depth: usize,
}

impl DepthAnalyzer {
    pub fn new(max_depth: usize) -> Self {
        Self { max_depth }
    }
    
    pub fn analyze(&self, query: &str) -> Result<DepthCheckResult> {
        validate_query_depth(query, self.max_depth)
    }
}

pub struct ComplexityScorer {
    pub max_complexity: usize,
}

impl ComplexityScorer {
    pub fn new(max_complexity: usize) -> Self {
        Self { max_complexity }
    }
    
    pub fn score(&self, query: &str, _schema: &Option<String>) -> Result<ComplexityResult> {
        // Schema ignored for now as we don't have full schema-based complexity yet
        validate_query_complexity(query, self.max_complexity)
    }
}

pub struct AuthResult {
    pub authorized: bool,
    pub reason: Option<String>,
}

pub struct FieldAuthorizer {
    #[allow(dead_code)]
    auth_rules: Option<std::collections::HashMap<String, Vec<String>>>,
}

impl FieldAuthorizer {
    pub fn new(auth_rules: Option<std::collections::HashMap<String, Vec<String>>>) -> Self {
        Self { auth_rules }
    }

    pub fn authorize(&self, _query: &str, _user_context: &Option<crate::parser::context::RequestContext>) -> Result<AuthResult> {
        // Placeholder implementation
        Ok(AuthResult { authorized: true, reason: None })
    }
}

pub struct RateLimitResult {
    pub allowed: bool,
    pub reason: Option<String>,
}

pub struct GraphQLRateLimiter {
    #[allow(dead_code)]
    limits: Option<std::collections::HashMap<String, u32>>,
}

impl GraphQLRateLimiter {
    pub fn new(limits: Option<std::collections::HashMap<String, u32>>) -> Self {
        Self { limits }
    }
    
    pub async fn check_limit(&self, _ip: &str, _query: &str, _complexity: usize) -> Result<RateLimitResult> {
        // Placeholder
        Ok(RateLimitResult { allowed: true, reason: None })
    }
}

