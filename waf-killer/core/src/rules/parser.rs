use super::actions::{Action, Severity};
use super::operators::Operator;
use super::transformations::Transformation;
use super::variables::Variable;
use anyhow::{Context, Result};
use nom::{
    branch::alt,
    bytes::complete::{escaped, is_not, tag, tag_no_case, take_while1},
    character::complete::{char, digit1, multispace1, space0},
    combinator::{map, opt, value},
    multi::{separated_list0, separated_list1},
    sequence::{delimited, pair, preceded, terminated},

    IResult,
};
use nom::Finish;
use regex::Regex;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Rule {
    pub variables: Vec<RuleVariable>,
    pub operator: Operator,
    pub actions: Vec<Action>,
    pub transformations: Vec<Transformation>, // Added this
    // Metadata extracted from actions for easier access
    pub id: u32,
    pub phase: u8,
    pub chain: bool,
    pub operator_negation: bool, // New field for !@op
}

#[derive(Debug, Clone, Serialize)]
pub struct RuleVariable {
    pub variable: Variable,
    pub count: bool, // &ARGS
    pub negation: bool, // !ARGS
}

// --- Parsers ---

fn parse_quoted_string(input: &str) -> IResult<&str, String> {
    let esc = escaped(is_not("\\\""), '\\', char('"'));
    let p = delimited(char('"'), esc, char('"'));
    map(p, |s: &str| s.to_string())(input)
}

fn parse_single_quoted_string(input: &str) -> IResult<&str, String> {
    let esc = escaped(is_not("\\'"), '\\', char('\''));
    let p = delimited(char('\''), esc, char('\''));
    map(p, |s: &str| s.to_string())(input)
}

// --- Variables ---

fn parse_variable_name(input: &str) -> IResult<&str, Variable> {
    let (input, name) = take_while1(|c: char| c.is_ascii_uppercase() || c == '_')(input)?;
    match name {
        "ARGS" => Ok((input, Variable::Args)),
        "ARGS_NAMES" => Ok((input, Variable::ArgsNames)),
        "ARGS_COMBINED_SIZE" => Ok((input, Variable::ArgsCombinedSize)),
        "REQUEST_HEADERS" => Ok((input, Variable::RequestHeaders)),
        "REQUEST_COOKIES" => Ok((input, Variable::RequestCookies)),
        "REQUEST_COOKIES_NAMES" => Ok((input, Variable::RequestCookiesNames)),
        "REQUEST_BODY" => Ok((input, Variable::RequestBody)),
        "REQUEST_URI" => Ok((input, Variable::RequestUri)),
        "REQUEST_FILENAME" => Ok((input, Variable::RequestFilename)),
        "REQUEST_METHOD" => Ok((input, Variable::RequestMethod)),
        "REMOTE_ADDR" => Ok((input, Variable::RemoteAddr)),
        "QUERY_STRING" => Ok((input, Variable::QueryString)),
        "REQUEST_BASENAME" => Ok((input, Variable::RequestBasename)),
        "REQUEST_LINE" => Ok((input, Variable::RequestLine)),
        "REQUEST_PROTOCOL" => Ok((input, Variable::RequestProtocol)),
        "TX" => Ok((input, Variable::Tx("".to_string()))), // Special case, usually TX:name
        "DURATION" => Ok((input, Variable::Duration)),
        _ => {
            // Fallback or error? For now assume it's a valid variable we might have missed or custom
            Ok((input, Variable::Tx(name.to_string()))) // Default to TX? No, wait.
        }
    }
}

fn parse_variable_with_specific(input: &str) -> IResult<&str, Variable> {
    let (input, name) = take_while1(|c: char| c.is_ascii_uppercase() || c == '_')(input)?;
    let (input, _sep) = char(':')(input)?;
    let (input, specific) = take_while1(|c: char| c != '|' && c != ' ' && c != '"')(input)?;
    
    match name {
        "ARGS" => Ok((input, Variable::ArgsSpecific(specific.to_string()))),
        "REQUEST_HEADERS" => Ok((input, Variable::RequestHeadersSpecific(specific.to_string()))),
        "REQUEST_COOKIES" => Ok((input, Variable::RequestCookiesSpecific(specific.to_string()))),
        "TX" => Ok((input, Variable::TxSpecific(specific.to_string()))),
        "GEO" => Ok((input, Variable::Geo(specific.to_string()))),
        _ => Ok((input, Variable::TxSpecific(format!("{}:{}", name, specific)))), // Fallback
    }
}

fn parse_rule_variable(input: &str) -> IResult<&str, RuleVariable> {
    let (input, negation) = opt(char('!'))(input)?;
    let (input, count) = opt(char('&'))(input)?;
    let (input, variable) = alt((parse_variable_with_specific, parse_variable_name))(input)?;

    Ok((
        input,
        RuleVariable {
            variable,
            count: count.is_some(),
            negation: negation.is_some(),
        },
    ))
}

fn parse_variables(input: &str) -> IResult<&str, Vec<RuleVariable>> {
    separated_list1(char('|'), parse_rule_variable)(input)
}

// --- Operators ---

// --- Operators ---

fn parse_regex_pattern(input: &str) -> IResult<&str, String> {
    let esc = escaped(is_not("\\\""), '\\', nom::character::complete::anychar);
    map(esc, |s: &str| s.to_string())(input)
}

fn parse_operator(input: &str) -> IResult<&str, (Operator, bool)> {
    // Starts with quote, then optional !, then @op or regex, then quote
    preceded(
        char('"'),
        terminated(
            map(
                pair(
                    map(opt(char('!')), |n| n.is_some()),
                    alt((
                        // @rx regex
                        map(preceded(tag_no_case("@rx "), parse_regex_pattern), |s: String| {
                            match Regex::new(&s) {
                                Ok(re) => Operator::Rx(re),
                                Err(_) => Operator::NoOp, // TODO: Log error?
                            }
                        }),
                        // @eq value
                        map(preceded(tag_no_case("@eq "), digit1), |s: &str| {
                             Operator::Eq(s.to_string())
                        }),
                        // @gt value
                        map(preceded(tag_no_case("@gt "), digit1), |s: &str| {
                             Operator::Gt(s.parse().unwrap_or(0))
                        }),
                         // @lt value
                        map(preceded(tag_no_case("@lt "), digit1), |s: &str| {
                             Operator::Lt(s.parse().unwrap_or(0))
                        }),
                        // @contains value
                        map(preceded(tag_no_case("@contains "), parse_regex_pattern), |s: String| {
                             Operator::Contains(s)
                        }),
                        // @streq value
                        map(preceded(tag_no_case("@streq "), parse_regex_pattern), |s: String| {
                             Operator::StrEq(s)
                        }),
                        // @beginsWith value
                        map(preceded(tag_no_case("@beginsWith "), parse_regex_pattern), |s: String| {
                             Operator::BeginsWith(s)
                        }),
                        // @endsWith value
                        map(preceded(tag_no_case("@endsWith "), parse_regex_pattern), |s: String| {
                             Operator::EndsWith(s)
                        }),
                         // @pmFromFile
                        map(preceded(tag_no_case("@pmFromFile "), parse_regex_pattern), |s: String| {
                             Operator::PmFromFile(s)
                        }),
                         // @detectSQLi
                        value(Operator::DetectSQLi, tag_no_case("@detectSQLi")),
                         // @detectXSS
                        value(Operator::DetectXSS, tag_no_case("@detectXSS")),

                        // Default regex if no @
                        map(parse_regex_pattern, |s: String| {
                            match Regex::new(&s) {
                                Ok(re) => Operator::Rx(re),
                                Err(_) => Operator::NoOp,
                            }
                        })
                    ))
                ),
                |(neg, op)| (op, neg)
            ), 
            char('"'),
        ),
    )(input)
}

// --- Actions ---

fn parse_action_key_val(input: &str) -> IResult<&str, Action> {
    let (input, key) = take_while1(|c: char| c.is_ascii_alphanumeric() || c == '.' || c == '-')(input)?;
    let (input, _) = char(':')(input)?;
    
    // value can be quoted or not
    let (input, val_str) = alt((
        parse_single_quoted_string,
        parse_quoted_string,
         map(take_while1(|c: char| c != ',' && c != '"'), |s: &str| s.to_string())
    ))(input)?;

    match key {
        "id" => Ok((input, Action::Id(val_str.parse().unwrap_or(0)))),
        "phase" => Ok((input, Action::Phase(val_str.parse().unwrap_or(2)))),
        "msg" => Ok((input, Action::Msg(val_str))),
        "logdata" => Ok((input, Action::LogData(val_str))),
        "tag" => Ok((input, Action::Tag(val_str))),
        "ver" => Ok((input, Action::Ver(val_str))),
        "rev" => Ok((input, Action::Rev(val_str))),
        "maturity" => Ok((input, Action::Maturity(val_str.parse().unwrap_or(0)))),
        "severity" => {
            let sev = match val_str.to_uppercase().as_str() {
                "CRITICAL" => Severity::Critical,
                "ERROR" => Severity::Error,
                "WARNING" => Severity::Warning,
                "NOTICE" => Severity::Notice,
                "INFO" => Severity::Info,
                _ => Severity::Notice,
            };
            Ok((input, Action::Severity(sev)))
        }
        "t" => {
            let _t = match val_str.as_str() {
                "none" => Transformation::None,
                "lowercase" => Transformation::Lowercase,
                "uppercase" => Transformation::Uppercase,
                "urlDecode" => Transformation::UrlDecode,
                "urlDecodeUni" => Transformation::UrlDecodeUni,
                "htmlEntityDecode" => Transformation::HtmlEntityDecode,
                "base64Decode" => Transformation::Base64Decode,
                "removeWhitespace" => Transformation::RemoveWhitespace,
                "compressWhitespace" => Transformation::CompressWhitespace,
                "removeNulls" => Transformation::RemoveNulls,
                "replaceComments" => Transformation::ReplaceComments,
                "length" => Transformation::Length,
                "md5" => Transformation::Md5,
                "sha1" => Transformation::Sha1,
                "hexEncode" => Transformation::HexEncode,
                "hexDecode" => Transformation::HexDecode,
                 _ => Transformation::None, // Unknown transformation
            };
            // Return Action? No, Action needs to hold transformation? 
            // The Action enum doesn't have Transformation.
            // Oh right, Transformations are Actions in SecLang too! but we separated them in struct Rule.
            // Parser needs to return Action wrapper or we change Action enum to include Transformation(Transformation).
            // Let's add Transformation to Action enum in actions.rs? No, keep pure.
            // But Parse returns Action. The Rule struct separates them.
            // Let's make a temporary Wrapper Enum or just assume Action can handle it?
            // Wait, t:lowercase is an action. list of actions.
            // I should ADD Transformation(Transformation) to Action enum.
            // Or handle it in the caller.
            // Just map it to a placeholder action? No.
            // Let's modify Action Enum in actions.rs potentially?
            // Actually, idiomatic way: transformations are just part of the chain.
            // But the Rule struct has `transformations: Vec<Transformation>`.
            // So I need to separate them later.
            // Let's create a temporary enum `ParsedAction`?
            // Or just put it in Action for now and filter it out into the struct later.
            // I'll assume Action enum will be updated to include `Transform(Transformation)`.
             Ok((input, Action::Tag(format!("TRANSFORM:{}", val_str)))) // HACK for now, will fix Action enum
        },
        "setvar" => Ok((input, Action::SetVar(val_str))),
        "ctl" => Ok((input, Action::Ctl("".to_string(), val_str))), // TODO parse ctl properly
        "redirect" => Ok((input, Action::Redirect(val_str))),
        "skipAfter" => Ok((input, Action::SkipAfter(val_str))),
        _ => Ok((input, Action::Tag(format!("UNKNOWN:{}:{}", key, val_str)))),
    }
}

fn parse_action_flag(input: &str) -> IResult<&str, Action> {
     let (input, flag) = take_while1(|c: char| c.is_ascii_alphanumeric())(input)?;
     match flag {
         "block" => Ok((input, Action::Block)),
         "pass" => Ok((input, Action::Pass)),
         "log" => Ok((input, Action::Log)),
         "deny" => Ok((input, Action::Deny(403))),
         "drop" => Ok((input, Action::Drop)),
         "chain" => Ok((input, Action::Chain)),
         _ => Ok((input, Action::Tag(format!("FLAG:{}", flag)))),
     }
}

fn parse_action(input: &str) -> IResult<&str, Action> {
    alt((parse_action_key_val, parse_action_flag))(input)
}

fn parse_actions(input: &str) -> IResult<&str, Vec<Action>> {
    preceded(
        char('"'),
        terminated(
            separated_list0(pair(char(','), space0), parse_action),
             char('"'),
        ),
    )(input)
}

// --- Main Rule Parser ---

pub fn parse_rule(input: &str) -> Result<Rule> {
    let input = input.trim();
    
    // SecRule VARIABLES "OPERATOR" "ACTIONS"
    let (input, _) = tag::<_, _, nom::error::Error<&str>>("SecRule")(input)
        .finish()
        .map_err(|e| anyhow::anyhow!("Nom error: {:?}", e))
        .context("Missing SecRule")?;
        
    let (input, _) = multispace1::<&str, nom::error::Error<&str>>(input)
        .finish()
        .map_err(|e| anyhow::anyhow!("Nom error: {:?}", e))
        .context("Space after SecRule")?;
    
    let (input, variables) = parse_variables(input)
        .finish()
        .map_err(|e| anyhow::anyhow!("Nom error: {:?}", e))
        .context("Invalid Variables")?;
        
    let (input, _) = multispace1::<&str, nom::error::Error<&str>>(input)
        .finish()
        .map_err(|e| anyhow::anyhow!("Nom error: {:?}", e))?;
    
    let (input, (operator, operator_negation)) = parse_operator(input)
        .finish()
        .map_err(|e| anyhow::anyhow!("Nom error: {:?}", e))
        .context("Invalid Operator")?;
        
    let (input, _) = multispace1::<&str, nom::error::Error<&str>>(input)
        .finish()
        .map_err(|e| anyhow::anyhow!("Nom error: {:?}", e))?;
    
    let (_input, actions) = parse_actions(input)
        .finish()
        .map_err(|e| anyhow::anyhow!("Nom error: {:?}", e))
        .context("Invalid Actions")?;
    
    // Post-process actions to extract metadata and transformations
    let mut transformations = Vec::new();
    let mut rule_id = 0;
    let mut phase = 2; // Default phase 2
    let mut chain = false;
    let mut final_actions = Vec::new();

    for action in actions {
        match action {
            Action::Id(id) => rule_id = id,
            Action::Phase(p) => phase = p,
            Action::Chain => chain = true,
            Action::Tag(ref s) if s.starts_with("TRANSFORM:") => {
                 let t_str = s.trim_start_matches("TRANSFORM:");
                 let t = match t_str {
                    "lowercase" => Transformation::Lowercase,
                    "uppercase" => Transformation::Uppercase,
                    "urlDecode" => Transformation::UrlDecode,
                    "urlDecodeUni" => Transformation::UrlDecodeUni,
                    "htmlEntityDecode" => Transformation::HtmlEntityDecode,
                    "base64Decode" => Transformation::Base64Decode,
                    "removeWhitespace" => Transformation::RemoveWhitespace,
                    "compressWhitespace" => Transformation::CompressWhitespace,
                    "removeNulls" => Transformation::RemoveNulls,
                    "normalizePath" => Transformation::NormalizePath,
                    "length" => Transformation::Length,
                    "none" | "t:none" => Transformation::None,
                     _ => Transformation::None,
                 };
                 if t != Transformation::None {
                     transformations.push(t);
                 }
            }
            _ => final_actions.push(action),
        }
    }

    Ok(Rule {
        variables,
        operator,
        actions: final_actions,
        transformations,
        id: rule_id,
        phase,
        chain,
        operator_negation,
    })
}
