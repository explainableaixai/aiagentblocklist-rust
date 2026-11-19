//! The error type shared by the client and the offline parser.

use std::fmt;

/// Everything that can go wrong in this crate.
///
/// Match on the variant to decide what to do. The two variants a
/// subscriber usually needs to handle on purpose are [`Error::NotFound`]
/// (the token or the file name is unknown) and [`Error::AccessEnded`] (the
/// subscription has ended or is paused). Messages never contain the token.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The token is missing or does not look like 32 letters and digits.
    /// Raised before any request is sent.
    Token(String),
    /// A file name, ecosystem or other argument was rejected locally.
    InvalidArgument(String),
    /// HTTP 404: the token or the file name is unknown.
    NotFound {
        /// File that was requested.
        file: String,
    },
    /// HTTP 403: the subscription has ended or is paused.
    AccessEnded {
        /// File that was requested.
        file: String,
    },
    /// Any other HTTP status outside the 2xx range (and not a 304 on a
    /// conditional download).
    Http {
        /// The HTTP status code.
        status: u16,
        /// File that was requested.
        file: String,
    },
    /// Network, file system or JSON problem. The cause is kept as the
    /// error source when one exists.
    Other {
        /// Human readable description, without the token.
        message: String,
        /// The underlying error, if any.
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    },
}

impl Error {
    /// HTTP status behind the error, or 0 when there was no HTTP answer.
    pub fn status(&self) -> u16 {
        match self {
            Error::NotFound { .. } => 404,
            Error::AccessEnded { .. } => 403,
            Error::Http { status, .. } => *status,
            _ => 0,
        }
    }

    /// The message as a string (the same text as `Display`).
    pub fn message(&self) -> String {
        self.to_string()
    }

    pub(crate) fn other<E>(message: impl Into<String>, source: E) -> Error
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Error::Other {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }

    pub(crate) fn plain(message: impl Into<String>) -> Error {
        Error::Other {
            message: message.into(),
            source: None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Token(m) => write!(f, "invalid token: {}", m),
            Error::InvalidArgument(m) => write!(f, "invalid argument: {}", m),
            Error::NotFound { file } => write!(
                f,
                "HTTP 404 for {}: unknown token or unknown file name",
                file
            ),
            Error::AccessEnded { file } => write!(
                f,
                "HTTP 403 for {}: the subscription has ended or is paused",
                file
            ),
            Error::Http { status, file } => write!(f, "HTTP {} for {}", status, file),
            Error::Other { message, .. } => f.write_str(message),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Other {
                source: Some(inner),
                ..
            } => Some(inner.as_ref() as &(dyn std::error::Error + 'static)),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::other(format!("i/o error: {}", e), e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::other(format!("could not parse the feed JSON: {}", e), e)
    }
}

/// Result alias used across the crate.
pub type Result<T> = std::result::Result<T, Error>;
