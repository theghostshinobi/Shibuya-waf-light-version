use base64::{Engine as _, engine::general_purpose};
use urlencoding::decode;
use serde::Serialize;
use sha1::Digest as Sha1Digest;
use md5::Digest as Md5Digest;

use crate::parser::transforms;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Transformation {
    None,
    Lowercase,
    Uppercase,
    UrlDecode,
    UrlDecodeUni,
    HtmlEntityDecode,
    Base64Decode,
    RemoveWhitespace,
    CompressWhitespace,
    RemoveNulls,
    NormalizePath,
    ReplaceComments,
    Length,
    Md5,
    Sha1,
    HexEncode,
    HexDecode,
}

impl Transformation {
    pub fn apply(&self, value: &str) -> String {
        match self {
            Transformation::None => value.to_string(),
            Transformation::Lowercase => value.to_lowercase(),
            Transformation::Uppercase => value.to_uppercase(),
            Transformation::UrlDecode => decode(value)
                .unwrap_or(std::borrow::Cow::Borrowed(value))
                .to_string(),
            Transformation::UrlDecodeUni => decode(value)
                .unwrap_or(std::borrow::Cow::Borrowed(value))
                .to_string(),
            Transformation::HtmlEntityDecode => transforms::html_entity_decode(value),
            Transformation::Base64Decode => {
                match general_purpose::STANDARD.decode(value) {
                    Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
                    Err(_) => value.to_string(),
                }
            }
            Transformation::RemoveWhitespace => value.replace(char::is_whitespace, ""),
            Transformation::CompressWhitespace => {
                value.split_whitespace().collect::<Vec<&str>>().join(" ")
            }
            Transformation::RemoveNulls => value.replace('\0', ""),
            Transformation::NormalizePath => transforms::normalize_path(value),
            Transformation::ReplaceComments => transforms::remove_sql_comments(value),
            Transformation::Length => value.len().to_string(),
            Transformation::Md5 => {
                let hash = md5::Md5::digest(value.as_bytes());
                hex::encode(hash)
            }
            Transformation::Sha1 => {
                let hash = sha1::Sha1::digest(value.as_bytes());
                hex::encode(hash)
            }
            Transformation::HexEncode => hex::encode(value.as_bytes()),
            Transformation::HexDecode => {
                match hex::decode(value) {
                    Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
                    Err(_) => value.to_string(),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_html_entity_decode() {
        assert_eq!(
            Transformation::HtmlEntityDecode.apply("&lt;script&gt;"),
            "<script>"
        );
    }

    #[test]
    fn test_remove_nulls() {
        assert_eq!(
            Transformation::RemoveNulls.apply("hel\0lo\0"),
            "hello"
        );
    }

    #[test]
    fn test_normalize_path() {
        assert_eq!(
            Transformation::NormalizePath.apply("/etc/../etc/passwd"),
            "/etc/passwd"
        );
    }

    #[test]
    fn test_replace_comments() {
        assert_eq!(
            Transformation::ReplaceComments.apply("SELECT /* bypass */ * FROM users"),
            "SELECT  * FROM users"
        );
    }

    #[test]
    fn test_md5() {
        // MD5("test") = 098f6bcd4621d373cade4e832627b4f6
        assert_eq!(
            Transformation::Md5.apply("test"),
            "098f6bcd4621d373cade4e832627b4f6"
        );
    }

    #[test]
    fn test_sha1() {
        // SHA1("test") = a94a8fe5ccb19ba61c4c0873d391e987982fbbd3
        assert_eq!(
            Transformation::Sha1.apply("test"),
            "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"
        );
    }

    #[test]
    fn test_hex_encode() {
        assert_eq!(
            Transformation::HexEncode.apply("AB"),
            "4142"
        );
    }

    #[test]
    fn test_hex_decode() {
        assert_eq!(
            Transformation::HexDecode.apply("4142"),
            "AB"
        );
    }
}
