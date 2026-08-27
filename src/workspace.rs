use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::error::{Error, Result};

pub const CONTAINER_EXTENSION: &str = "enc";

pub fn root() -> &'static Path {
    static ROOT: OnceLock<PathBuf> = OnceLock::new();
    ROOT.get_or_init(|| {
        let base = env::var_os("MYEKRYPT_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("source"));
        let _ = fs::create_dir_all(&base);
        base.canonicalize().unwrap_or(base)
    })
}

pub fn in_ws(name: &str) -> Result<PathBuf> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(Error::UnsafePath(name.to_owned()));
    }
    let file_name = Path::new(trimmed)
        .file_name()
        .ok_or_else(|| Error::UnsafePath(name.to_owned()))?;
    if file_name == ".." || file_name == "." {
        return Err(Error::UnsafePath(name.to_owned()));
    }
    Ok(root().join(file_name))
}

pub fn enc_in_ws(name: &str) -> Result<PathBuf> {
    let path = in_ws(name)?;
    if path.extension().map(|e| e == CONTAINER_EXTENSION).unwrap_or(false) {
        return Ok(path);
    }
    let mut with_extension = path.into_os_string();
    with_extension.push(".");
    with_extension.push(CONTAINER_EXTENSION);
    Ok(PathBuf::from(with_extension))
}

pub fn is_inside(path: &Path) -> bool {
    path.canonicalize()
        .map(|resolved| resolved.starts_with(root()))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_dirs() {
        let resolved = in_ws("../../.ssh/authorized_keys").expect("name is usable");
        assert_eq!(resolved.file_name().expect("has a name"), "authorized_keys");
        assert_eq!(resolved.parent().expect("has a parent"), root());
    }

    #[test]
    fn rejects_dotdot() {
        assert!(in_ws("..").is_err());
        assert!(in_ws("   ").is_err());
    }

    #[test]
    fn adds_enc_once() {
        assert_eq!(enc_in_ws("notes").expect("ok").file_name().expect("name"), "notes.enc");
        assert_eq!(enc_in_ws("notes.enc").expect("ok").file_name().expect("name"), "notes.enc");
    }
}
