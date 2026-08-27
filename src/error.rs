use std::io;
use std::path::Path;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(io::Error),

    #[error("authentication failed - wrong password, wrong device, or corrupted container")]
    Authentication,

    #[error("container format v{0} is not supported by this build")]
    UnsupportedVersion(u8),

    #[error("malformed container: {0}")]
    Format(&'static str),

    #[error("key derivation failed: {0}")]
    KeyDerivation(String),

    #[error("hardware id unavailable: {0}")]
    HardwareId(&'static str),

    #[error("refusing to overwrite '{0}'")]
    WouldOverwrite(String),

    #[error("unsafe path '{0}'")]
    UnsafePath(String),

    #[error("password must be at least {0} characters")]
    WeakPassword(usize),

    #[error("this container holds a directory tree - decrypt it to disk instead")]
    NotAPlainFile,

    #[error("decrypted content is not valid UTF-8")]
    NotUtf8,

    #[error("{0}")]
    Other(String),
}

impl Error {
    pub fn bad_path(path: impl AsRef<Path>) -> Self {
        Error::UnsafePath(path.as_ref().display().to_string())
    }

    pub fn already_there(path: impl AsRef<Path>) -> Self {
        Error::WouldOverwrite(path.as_ref().display().to_string())
    }

    pub fn to_io(self) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, self)
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        if err.get_ref().is_some_and(|inner| inner.is::<Error>()) {
            match err.into_inner().expect("checked above").downcast::<Error>() {
                Ok(boxed) => *boxed,
                Err(other) => Error::Other(other.to_string()),
            }
        } else {
            Error::Io(err)
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
