use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::{thread_rng, RngCore};
use tar::{Archive, Builder};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::format::{
    ContainerInfo, Header, KdfParams, FLAG_HWID, HEADER_LEN, LEGACY_NONCE_LEN, MAGIC,
    NONCE_PREFIX_LEN, SALT_LEN,
};
use crate::fsutil::{self, AtomicFile};
use crate::hwid;
use crate::progress::Progress;
use crate::shred;
use crate::stream::{DecryptReader, EncryptWriter, MemoryReader};

pub const MIN_PASSWORD_LEN: usize = 8;

#[derive(Debug, Clone, Copy, Default)]
pub struct EncryptOptions {
    pub hwid: bool,
    pub shred_source: bool,
    pub overwrite: bool,
}

pub fn check_pass(password: &str) -> Result<()> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(Error::WeakPassword(MIN_PASSWORD_LEN));
    }
    Ok(())
}

pub fn make_key(
    password: &str,
    salt: &[u8],
    use_hwid: bool,
    params: KdfParams,
) -> Result<Zeroizing<[u8; 32]>> {
    let secret = if use_hwid {
        let id = hwid::get_hwid()?;
        Zeroizing::new(format!("{password}:{}", id.as_str()))
    } else {
        Zeroizing::new(password.to_owned())
    };

    let params = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(32))
        .map_err(|e| Error::KeyDerivation(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(secret.as_bytes(), salt, key.as_mut_slice())
        .map_err(|e| Error::KeyDerivation(e.to_string()))?;
    Ok(key)
}

pub fn peek(path: &Path) -> Option<ContainerInfo> {
    let name = path.file_name()?.to_string_lossy().into_owned();
    let mut file = File::open(path).ok()?;
    let mut probe = [0u8; 5];
    if file.read_exact(&mut probe).is_err() {
        return None;
    }

    if &probe[0..4] != MAGIC {
        if !name.ends_with(".enc") {
            return None;
        }
        let minimum = (SALT_LEN + LEGACY_NONCE_LEN + 16) as u64;
        if file.metadata().ok()?.len() < minimum {
            return None;
        }
        return Some(ContainerInfo {
            version: 0,
            hwid: None,
            tar: name.ends_with(".folder.enc"),
        });
    }

    match probe[4] {
        0 | 1 => Some(ContainerInfo {
            version: 1,
            hwid: Some(probe[4] == FLAG_HWID),
            tar: name.ends_with(".folder.enc"),
        }),
        2 => {
            let mut rest = [0u8; HEADER_LEN];
            rest[0..5].copy_from_slice(&probe);
            file.read_exact(&mut rest[5..]).ok()?;
            let header = Header::parse(&rest).ok()?;
            Some(ContainerInfo { version: 2, hwid: Some(header.hwid()), tar: header.tar() })
        }
        other => Some(ContainerInfo { version: other, hwid: None, tar: false }),
    }
}

pub fn encrypt_file(
    source: &Path,
    destination: &Path,
    password: &str,
    options: EncryptOptions,
    progress: &Progress,
) -> Result<PathBuf> {
    let meta = std::fs::symlink_metadata(source)?;
    if meta.file_type().is_symlink() {
        return Err(Error::Other("refusing to encrypt a symlink".to_owned()));
    }
    if !options.overwrite && destination.exists() {
        return Err(Error::already_there(destination));
    }

    let is_directory = meta.is_dir();
    let total = fsutil::dir_size(source);

    let written = write_enc(destination, password, options.hwid, is_directory, total, progress, |sink| {
        if is_directory {
            let mut builder = Builder::new(sink);
            builder.follow_symlinks(false);
            builder.append_dir_all("", source)?;
            builder.into_inner()?;
        } else {
            let mut input = BufReader::new(File::open(source)?);
            io::copy(&mut input, sink)?;
        }
        Ok(())
    })?;

    if options.shred_source {
        shred::shred(source)?;
    }
    Ok(written)
}

pub fn encrypt_buf(
    plaintext: &[u8],
    destination: &Path,
    password: &str,
    options: EncryptOptions,
    progress: &Progress,
) -> Result<PathBuf> {
    if !options.overwrite && destination.exists() {
        return Err(Error::already_there(destination));
    }
    write_enc(
        destination,
        password,
        options.hwid,
        false,
        plaintext.len() as u64,
        progress,
        |sink| sink.write_all(plaintext),
    )
}

#[allow(clippy::too_many_arguments)]
fn write_enc<F>(
    destination: &Path,
    password: &str,
    use_hwid: bool,
    tar: bool,
    total_bytes: u64,
    progress: &Progress,
    fill: F,
) -> Result<PathBuf>
where
    F: FnOnce(&mut EncryptWriter<BufWriter<&mut File>>) -> io::Result<()>,
{
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
    let mut rng = thread_rng();
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut nonce_prefix);

    let kdf = KdfParams::CURRENT;
    let key = make_key(password, &salt, use_hwid, kdf)?;
    progress.set_total(total_bytes);

    let header = Header::new(use_hwid, tar, kdf, salt, nonce_prefix);
    let header_bytes = header.to_bytes();

    let mut output = AtomicFile::create(destination)?;
    output.file().write_all(&header_bytes)?;

    {
        let sink = BufWriter::new(output.file());
        let mut writer =
            EncryptWriter::new(sink, &key, &nonce_prefix, header_bytes.to_vec(), progress.clone());
        fill(&mut writer)?;
        writer.finish()?.into_inner().map_err(|e| e.into_error())?;
    }

    output.commit()
}

pub struct OpenContainer {
    pub info: ContainerInfo,
    reader: PlainReader,
}

impl Read for OpenContainer {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.reader.read(out)
    }
}

enum PlainReader {
    Streamed(Box<DecryptReader<BufReader<File>>>),
    Buffered(MemoryReader),
}

impl Read for PlainReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        match self {
            PlainReader::Streamed(reader) => reader.read(out),
            PlainReader::Buffered(reader) => reader.read(out),
        }
    }
}

pub fn open(
    path: &Path,
    password: &str,
    hwid_hint: Option<bool>,
    progress: &Progress,
) -> Result<OpenContainer> {
    let info = peek(path).ok_or(Error::Format("not a readable container"))?;
    let mut file = File::open(path)?;
    let total = file.metadata().map(|m| m.len()).unwrap_or(0);

    match info.version {
        2 => {
            let mut header_bytes = [0u8; HEADER_LEN];
            file.read_exact(&mut header_bytes)?;
            let header = Header::parse(&header_bytes)?;
            let key = make_key(password, &header.salt, header.hwid(), header.kdf)?;
            progress.set_total(total);
            let reader = DecryptReader::new(
                BufReader::new(file),
                &key,
                &header.nonce_prefix,
                header_bytes.to_vec(),
                progress.clone(),
            );
            Ok(OpenContainer { info, reader: PlainReader::Streamed(Box::new(reader)) })
        }
        1 | 0 => {
            let use_hwid = info.hwid.or(hwid_hint).unwrap_or(false);
            let offset = if info.version == 1 { 5 } else { 0 };
            file.seek(SeekFrom::Start(offset))?;
            let plaintext = open_old(file, password, use_hwid)?;
            progress.set_total(plaintext.len() as u64);
            Ok(OpenContainer {
                info,
                reader: PlainReader::Buffered(MemoryReader::new(plaintext, progress.clone())),
            })
        }
        other => Err(Error::UnsupportedVersion(other)),
    }
}

fn open_old(mut file: File, password: &str, use_hwid: bool) -> Result<Zeroizing<Vec<u8>>> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; LEGACY_NONCE_LEN];
    file.read_exact(&mut salt)?;
    file.read_exact(&mut nonce_bytes)?;

    let mut ciphertext = Vec::new();
    file.read_to_end(&mut ciphertext)?;

    let key = make_key(password, &salt, use_hwid, KdfParams::LEGACY)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_slice()));
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce_bytes), ciphertext.as_ref())
        .map_err(|_| Error::Authentication)?;
    Ok(Zeroizing::new(plaintext))
}

pub fn decrypt(
    path: &Path,
    output_dir: &Path,
    password: &str,
    hwid_hint: Option<bool>,
    progress: &Progress,
) -> Result<PathBuf> {
    let mut container = open(path, password, hwid_hint, progress)?;
    let destination = fsutil::unused_path(&output_dir.join(orig_name(path)));

    if container.info.tar {
        unpack(&mut container, &destination)?;
    } else {
        let mut output = AtomicFile::create(&destination)?;
        let mut sink = BufWriter::new(output.file());
        io::copy(&mut container, &mut sink)?;
        sink.flush()?;
        drop(sink);
        output.commit()?;
    }
    Ok(destination)
}

fn unpack(container: &mut OpenContainer, destination: &Path) -> Result<()> {
    std::fs::create_dir_all(destination)?;

    let mut archive = Archive::new(container);
    archive.set_preserve_permissions(false);
    archive.set_unpack_xattrs(false);
    archive.set_overwrite(false);

    for entry in archive.entries()? {
        let mut entry = entry?;
        let entry_path = entry.path()?.into_owned();
        if entry_path.as_os_str().is_empty() || entry_path == Path::new(".") {
            continue;
        }
        if !fsutil::ok_relpath(&entry_path) {
            return Err(Error::bad_path(entry_path));
        }
        if let Some(link) = entry.link_name()? {
            if !fsutil::ok_relpath(&link) {
                return Err(Error::bad_path(link));
            }
        }
        if !entry.unpack_in(destination)? {
            return Err(Error::bad_path(entry_path));
        }
    }
    Ok(())
}

pub fn decrypt_buf(
    path: &Path,
    password: &str,
    hwid_hint: Option<bool>,
    progress: &Progress,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut container = open(path, password, hwid_hint, progress)?;
    if container.info.tar {
        return Err(Error::NotAPlainFile);
    }
    let hint = std::fs::metadata(path).map(|m| m.len() as usize).unwrap_or(0);
    let mut plaintext = Zeroizing::new(Vec::with_capacity(hint));
    container.read_to_end(&mut plaintext)?;
    Ok(plaintext)
}

pub fn decrypt_text(
    path: &Path,
    password: &str,
    hwid_hint: Option<bool>,
    progress: &Progress,
) -> Result<Zeroizing<String>> {
    let bytes = decrypt_buf(path, password, hwid_hint, progress)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| Error::NotUtf8)?;
    Ok(Zeroizing::new(text.to_owned()))
}

pub fn orig_name(container: &Path) -> String {
    let name = container.file_name().map(|n| n.to_string_lossy().into_owned());
    let Some(name) = name else {
        return "restored".to_owned();
    };
    let stem = name.strip_suffix(".enc").unwrap_or(&name);
    let stem = stem.strip_suffix(".folder").unwrap_or(stem);
    if stem.is_empty() {
        "restored".to_owned()
    } else {
        stem.to_owned()
    }
}

pub fn enc_name(source: &Path) -> PathBuf {
    if source.extension().map(|e| e == "enc").unwrap_or(false) {
        return source.to_path_buf();
    }
    let mut name = source.as_os_str().to_owned();
    name.push(".enc");
    PathBuf::from(name)
}
