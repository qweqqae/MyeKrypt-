use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use rand::{thread_rng, RngCore};

use crate::error::Result;

const BUFFER_SIZE: usize = 64 * 1024;

pub fn shred(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path)?;

    if meta.file_type().is_symlink() {
        fs::remove_file(path)?;
        return Ok(());
    }

    if meta.is_dir() {
        for entry in fs::read_dir(path)? {
            shred(&entry?.path())?;
        }
        fs::remove_dir(path)?;
        return Ok(());
    }

    overwrite(path, meta.len())?;
    let renamed = rand_name(path);
    fs::remove_file(&renamed)?;
    Ok(())
}

fn overwrite(path: &Path, len: u64) -> Result<()> {
    if len == 0 {
        return Ok(());
    }
    let mut file = OpenOptions::new().write(true).open(path)?;
    file.seek(SeekFrom::Start(0))?;

    let mut rng = thread_rng();
    let mut buffer = vec![0u8; BUFFER_SIZE];
    let mut written = 0u64;
    while written < len {
        let take = BUFFER_SIZE.min((len - written) as usize);
        rng.fill_bytes(&mut buffer[..take]);
        file.write_all(&buffer[..take])?;
        written += take as u64;
    }
    file.flush()?;
    file.sync_all()?;
    Ok(())
}

fn rand_name(path: &Path) -> PathBuf {
    let Some(parent) = path.parent() else {
        return path.to_path_buf();
    };
    let mut raw = [0u8; 12];
    thread_rng().fill_bytes(&mut raw);
    let scrambled: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    let target = parent.join(scrambled);
    match fs::rename(path, &target) {
        Ok(()) => target,
        Err(_) => path.to_path_buf(),
    }
}
