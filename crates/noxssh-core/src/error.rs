use std::fmt::{Display, Formatter};
use std::io;

#[derive(Debug)]
pub enum SshError {
    BadParam(&'static str),
    Failed(&'static str),
    FailedOwned(String),
    AuthRejected,
    Io(io::Error),
}

impl Display for SshError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadParam(msg) | Self::Failed(msg) => f.write_str(msg),
            Self::FailedOwned(msg) => f.write_str(msg),
            Self::AuthRejected => f.write_str("authentication rejected"),
            Self::Io(err) => write!(f, "io error: {err}"),
        }
    }
}

impl std::error::Error for SshError {}

impl From<io::Error> for SshError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
