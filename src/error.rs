/// The result type for procmod-scan operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur during pattern operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The pattern string is malformed or empty.
    InvalidPattern(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidPattern(msg) => write!(f, "invalid pattern: {msg}"),
        }
    }
}

impl std::error::Error for Error {}
