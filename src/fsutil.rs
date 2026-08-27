use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use rand::{thread_rng, RngCore};

use crate::error::{Error, Result};

pub struct AtomicFile {
    temp_path: PathBuf,
    final_path: PathBuf,
    file: Option<File>,
}

impl AtomicFile {
    pub fn create(final_path: &Path) -> Result<Self> {
        let parent = final_path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;

        let mut suffix = [0u8; 8];
        thread_rng().fill_bytes(&mut suffix);
        let name = final_path
            .file_name()
            .ok_or_else(|| Error::bad_path(final_path))?
            .to_string_lossy()
            .into_owned();
        let temp_path = parent.join(format!(".{name}.{}.part", hex(&suffix)));

        let file = OpenOptions::new().write(true).create_new(true).open(&temp_path)?;
        Ok(AtomicFile { temp_path, final_path: final_path.to_path_buf(), file: Some(file) })
    }

    pub fn file(&mut self) -> &mut File {
        self.file.as_mut().expect("file is present until commit")
    }

    pub fn commit(mut self) -> Result<PathBuf> {
        let mut file = self.file.take().expect("file is present until commit");
        file.flush()?;
        file.sync_all()?;
        drop(file);

        fs::rename(&self.temp_path, &self.final_path)?;

        if let Some(parent) = self.final_path.parent() {
            if let Ok(dir) = File::open(parent) {
                let _ = dir.sync_all();
            }
        }
        Ok(std::mem::take(&mut self.final_path))
    }
}

impl Drop for AtomicFile {
    fn drop(&mut self) {
        if self.file.take().is_some() {
            let _ = fs::remove_file(&self.temp_path);
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unused_path(base: &Path) -> PathBuf {
    if !base.exists() {
        return base.to_path_buf();
    }
    let parent = base.parent().unwrap_or_else(|| Path::new("."));
    let stem = base.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let extension = base.extension().map(|e| e.to_string_lossy().into_owned());

    for n in 1..10_000u32 {
        let name = match &extension {
            Some(ext) => format!("{stem}-{n}.{ext}"),
            None => format!("{stem}-{n}"),
        };
        let candidate = parent.join(name);
        if !candidate.exists() {
            return candidate;
        }
    }
    base.to_path_buf()
}

pub fn ok_relpath(path: &Path) -> bool {
    if path.as_os_str().is_empty() {
        return false;
    }
    path.components().all(|component| matches!(component, Component::Normal(_)))
}

pub fn dir_size(path: &Path) -> u64 {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return 0;
    };
    if meta.is_file() {
        return meta.len();
    }
    if !meta.is_dir() {
        return 0;
    }
    let Ok(entries) = fs::read_dir(path) else {
        return 0;
    };
    entries.flatten().map(|entry| dir_size(&entry.path())).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_traversal() {
        assert!(ok_relpath(Path::new("notes/todo.txt")));
        assert!(!ok_relpath(Path::new("../escape")));
        assert!(!ok_relpath(Path::new("/etc/passwd")));
        assert!(!ok_relpath(Path::new("")));
        assert!(!ok_relpath(Path::new("a/../../b")));
    }
}
