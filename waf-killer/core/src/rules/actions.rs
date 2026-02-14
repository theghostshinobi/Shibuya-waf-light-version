use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    Pass,
    Block,
    Log,
    Deny(u16), // HTTP status code
    Redirect(String),
    Drop,
    Id(u32),
    Phase(u8),
    Msg(String),
    LogData(String),
    Severity(Severity),
    Tag(String),
    Ver(String),
    Maturity(u8),
    Rev(String),
    Ctl(String, String), // ctl:ruleRemoveTargetById=942100;ARGS:password
    SetVar(String),      // setvar:tx.anomaly_score=+5
    Chain,
    Skip(u32),
    SkipAfter(String),
    Disabled, // Internal marker for disabled rules
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Emergency = 0,
    Alert = 1,
    Critical = 2,
    Error = 3,
    Warning = 4,
    Notice = 5,
    Info = 6,
    Debug = 7,
}

impl Default for Severity {
    fn default() -> Self {
        Severity::Notice
    }
}
