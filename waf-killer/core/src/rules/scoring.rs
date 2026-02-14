use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct TransactionContext {
    pub anomaly_score: i32,
    pub sql_injection_score: i32,
    pub xss_score: i32,
    pub rce_score: i32,
    pub lfi_score: i32,
    pub rfi_score: i32,
    pub php_injection_score: i32,
    pub session_fixation_score: i32,
    pub custom_vars: HashMap<String, String>,
}

impl TransactionContext {
    pub fn new() -> Self {
        Self {
            anomaly_score: 0,
            sql_injection_score: 0,
            xss_score: 0,
            rce_score: 0,
            lfi_score: 0,
            rfi_score: 0,
            php_injection_score: 0,
            session_fixation_score: 0,
            custom_vars: HashMap::new(),
        }
    }

    pub fn increment_score(&mut self, score_type: &str, delta: i32) {
        // Always increment total anomaly score
        self.anomaly_score += delta;
        
        // Increment specific score
        match score_type {
            "sql_injection_score" => self.sql_injection_score += delta,
            "xss_score" => self.xss_score += delta,
            "rce_score" => self.rce_score += delta,
            "lfi_score" => self.lfi_score += delta,
            "rfi_score" => self.rfi_score += delta,
            "php_injection_score" => self.php_injection_score += delta,
            "session_fixation_score" => self.session_fixation_score += delta,
            "tx.anomaly_score" => {}, // Already incremented above
            _ => {
                // For other vars, we might want to track them in custom_vars as strings?
                // But scoring usually tracks integers.
                // We'll ignore specific tracking for unknown types for now or use custom_vars string storage
                let current_val = self.get_var(score_type).unwrap_or("0");
                let current_int = current_val.parse::<i32>().unwrap_or(0);
                self.set_var(score_type, (current_int + delta).to_string());
            }
        }
    }

    pub fn set_var(&mut self, var: &str, value: String) {
        match var {
             "tx.anomaly_score" => self.anomaly_score = value.parse().unwrap_or(self.anomaly_score),
             "tx.sql_injection_score" => self.sql_injection_score = value.parse().unwrap_or(self.sql_injection_score),
             // ...
             _ => { self.custom_vars.insert(var.to_string(), value); }
        }
    }

    pub fn get_var(&self, var: &str) -> Option<&str> {
         match var {
             "tx.anomaly_score" => None, // Helper doesn't return refs to primitives easily here w/o conversion. 
             // Logic in variable extraction will handle "TX:variable" by looking up here.
             // But for internal string-based API:
             _ => self.custom_vars.get(var).map(|s| s.as_str()),
         }
    }
}
