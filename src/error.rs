use thiserror::Error;

/// Main error type for ks-sniff
#[derive(Error, Debug)]
pub enum KsError {
    #[error("Packet capture error: {0}")]
    CaptureError(String),

    #[error("Packet decode error: {0}")]
    DecodeError(String),

    #[error("Rule parsing error: {0}")]
    RuleParseError(String),

    #[error("Rule matching error: {0}")]
    RuleMatchError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Channel send error")]
    ChannelSendError,

    #[error("Channel receive error")]
    ChannelRecvError,

    #[error("Invalid network address: {0}")]
    InvalidAddress(String),

    #[error("Alert output error: {0}")]
    AlertError(String),

    #[error("Thread error: {0}")]
    ThreadError(String),

    #[error("Invalid rule option: {0}")]
    InvalidRuleOption(String),

    #[error("Regex error: {0}")]
    RegexError(#[from] regex::Error),

    #[error("YAML parse error: {0}")]
    YamlError(#[from] serde_yaml::Error),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Other error: {0}")]
    Other(String),
}

/// Result type alias for ks-sniff operations
pub type Result<T> = std::result::Result<T, KsError>;

impl<T> From<crossbeam::channel::SendError<T>> for KsError {
    fn from(_: crossbeam::channel::SendError<T>) -> Self {
        KsError::ChannelSendError
    }
}

impl From<crossbeam::channel::RecvError> for KsError {
    fn from(_: crossbeam::channel::RecvError) -> Self {
        KsError::ChannelRecvError
    }
}
