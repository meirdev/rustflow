use std::io;

use thiserror::Error;

pub type Result<T> = std::result::Result<T, ParseError>;

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Invalid IPFIX version: expected {expected}, got {actual}")]
    InvalidVersion { expected: u16, actual: u16 },

    #[error("Template not found: template_id={template_id}, observation_domain_id={observation_domain_id}")]
    TemplateNotFound {
        template_id: u16,
        observation_domain_id: u32,
    },

    #[error("Invalid field length")]
    InvalidFieldLength,

    #[error("Invalid template ID: {0}")]
    InvalidTemplateId(u16),

    #[error("Unsupported data type: {0}")]
    UnsupportedDataType(u16),

    #[error("Invalid UTF-8 string")]
    InvalidUtf8,

    #[error("Nested template error: {0}")]
    NestedTemplateError(Box<ParseError>),

    #[error("Invalid enterprise bit")]
    InvalidEnterpriseBit,

    #[error("Field count is zero (template withdrawal)")]
    TemplateWithdrawal,
}
