use std::fs;
use std::io::Write;
use std::path::Path;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use myekrypt::crypto::{self, EncryptOptions};
use myekrypt::error::Error;
use myekrypt::format::KdfParams;
use myekrypt::progress::Progress;
use myekrypt::stream::CHUNK_SIZE;

const PASSWORD: &str = "correct horse battery staple";

fn options() -> EncryptOptions {
    EncryptOptions { hwid: false, shred_source: false, overwrite: false }
}

fn roundtrip_bytes(payload: &[u8]) {
    let dir = tempfile::tempdir().expect("temp dir");
    let source = dir.path().join("payload.bin");
    fs::write(&source, payload).expect("write source");

    let container = dir.path().join("payload.bin.enc");
    crypto::encrypt_file(&source, &container, PASSWORD, options(), &Progress::new())
        .expect("encrypt");

    let restored = crypto::decrypt_buf(&container, PASSWORD, None, &Progress::new())
        .expect("decrypt");
    assert_eq!(&restored[..], payload, "payload of {} bytes", payload.len());
}

#[test]
fn empty_file() {
    roundtrip_bytes(&[]);
}

#[test]
fn small_file() {
    roundtrip_bytes(b"just a few bytes");
}

#[test]
fn around_chunks() {
    for size in [CHUNK_SIZE - 1, CHUNK_SIZE, CHUNK_SIZE + 1, CHUNK_SIZE * 3] {
        let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        roundtrip_bytes(&payload);
    }
}

#[test]
fn wrong_pass() {
    let dir = tempfile::tempdir().expect("temp dir");
    let source = dir.path().join("secret.txt");
    fs::write(&source, b"classified").expect("write source");
    let container = dir.path().join("secret.txt.enc");
    crypto::encrypt_file(&source, &container, PASSWORD, options(), &Progress::new())
        .expect("encrypt");

    let outcome = crypto::decrypt_buf(&container, "not the password", None, &Progress::new());
    assert!(matches!(outcome, Err(Error::Authentication)), "got {outcome:?}");
}

#[test]
fn tamper() {
    let dir = tempfile::tempdir().expect("temp dir");
    let source = dir.path().join("secret.txt");
    fs::write(&source, b"classified payload").expect("write source");
    let container = dir.path().join("secret.txt.enc");
    crypto::encrypt_file(&source, &container, PASSWORD, options(), &Progress::new())
        .expect("encrypt");

    let mut bytes = fs::read(&container).expect("read container");
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    fs::write(&container, &bytes).expect("rewrite container");

    let outcome = crypto::decrypt_buf(&container, PASSWORD, None, &Progress::new());
    assert!(matches!(outcome, Err(Error::Authentication)), "got {outcome:?}");
}

#[test]
fn flip_flag() {
    let dir = tempfile::tempdir().expect("temp dir");
    let source = dir.path().join("secret.txt");
    fs::write(&source, b"classified").expect("write source");
    let container = dir.path().join("secret.txt.enc");
    crypto::encrypt_file(&source, &container, PASSWORD, options(), &Progress::new())
        .expect("encrypt");

    let mut bytes = fs::read(&container).expect("read container");
    bytes[5] |= 0x02;
    fs::write(&container, &bytes).expect("rewrite container");

    let outcome = crypto::decrypt_buf(&container, PASSWORD, None, &Progress::new());
    assert!(matches!(outcome, Err(Error::Authentication) | Err(Error::NotAPlainFile)));
}

#[test]
fn truncate() {
    let dir = tempfile::tempdir().expect("temp dir");
    let source = dir.path().join("big.bin");
    fs::write(&source, vec![7u8; CHUNK_SIZE * 2]).expect("write source");
    let container = dir.path().join("big.bin.enc");
    crypto::encrypt_file(&source, &container, PASSWORD, options(), &Progress::new())
        .expect("encrypt");

    let bytes = fs::read(&container).expect("read container");
    fs::write(&container, &bytes[..bytes.len() / 2]).expect("truncate");

    let outcome = crypto::decrypt_buf(&container, PASSWORD, None, &Progress::new());
    assert!(outcome.is_err(), "truncated container decrypted cleanly");
}

#[test]
fn dir_roundtrip() {
    let dir = tempfile::tempdir().expect("temp dir");
    let tree = dir.path().join("notes");
    fs::create_dir_all(tree.join("nested/deeper")).expect("create tree");
    fs::write(tree.join("top.txt"), b"top level").expect("write file");
    fs::write(tree.join("nested/middle.txt"), b"middle").expect("write file");
    fs::write(tree.join("nested/deeper/leaf.bin"), vec![9u8; 200_000]).expect("write file");

    let container = dir.path().join("notes.enc");
    crypto::encrypt_file(&tree, &container, PASSWORD, options(), &Progress::new())
        .expect("encrypt tree");

    let info = crypto::peek(&container).expect("inspectable");
    assert!(info.tar, "directory container must set the tar flag");

    let output = dir.path().join("out");
    fs::create_dir_all(&output).expect("create output dir");
    let restored = crypto::decrypt(&container, &output, PASSWORD, None, &Progress::new())
        .expect("decrypt tree");

    assert_eq!(restored.file_name().expect("name"), "notes");
    assert_eq!(fs::read(restored.join("top.txt")).expect("read"), b"top level");
    assert_eq!(fs::read(restored.join("nested/middle.txt")).expect("read"), b"middle");
    assert_eq!(fs::read(restored.join("nested/deeper/leaf.bin")).expect("read").len(), 200_000);
}

#[test]
fn dir_not_text() {
    let dir = tempfile::tempdir().expect("temp dir");
    let tree = dir.path().join("stuff");
    fs::create_dir_all(&tree).expect("create dir");
    fs::write(tree.join("a.txt"), b"a").expect("write");

    let container = dir.path().join("stuff.enc");
    crypto::encrypt_file(&tree, &container, PASSWORD, options(), &Progress::new())
        .expect("encrypt");

    let outcome = crypto::decrypt_text(&container, PASSWORD, None, &Progress::new());
    assert!(matches!(outcome, Err(Error::NotAPlainFile)), "got {outcome:?}");
}

#[test]
fn no_overwrite() {
    let dir = tempfile::tempdir().expect("temp dir");
    let source = dir.path().join("a.txt");
    fs::write(&source, b"first").expect("write");
    let container = dir.path().join("a.txt.enc");

    crypto::encrypt_file(&source, &container, PASSWORD, options(), &Progress::new())
        .expect("first encrypt");
    let first = fs::read(&container).expect("read container");

    let outcome = crypto::encrypt_file(&source, &container, PASSWORD, options(), &Progress::new());
    assert!(matches!(outcome, Err(Error::WouldOverwrite(_))), "got {outcome:?}");
    assert_eq!(fs::read(&container).expect("read container"), first);

    let overwriting = EncryptOptions { overwrite: true, ..options() };
    crypto::encrypt_file(&source, &container, PASSWORD, overwriting, &Progress::new())
        .expect("explicit overwrite");
}

#[test]
fn no_partial() {
    let dir = tempfile::tempdir().expect("temp dir");
    let missing = dir.path().join("does-not-exist");
    let container = dir.path().join("out.enc");

    let outcome = crypto::encrypt_file(&missing, &container, PASSWORD, options(), &Progress::new());
    assert!(outcome.is_err());
    assert!(!container.exists(), "a partial container was left behind");

    let leftovers: Vec<_> = fs::read_dir(dir.path())
        .expect("read dir")
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".part"))
        .collect();
    assert!(leftovers.is_empty(), "temporary files left behind: {leftovers:?}");
}

#[test]
fn shred_after() {
    let dir = tempfile::tempdir().expect("temp dir");
    let source = dir.path().join("plain.txt");
    fs::write(&source, b"burn after reading").expect("write");
    let container = dir.path().join("plain.txt.enc");

    let shredding = EncryptOptions { shred_source: true, ..options() };
    crypto::encrypt_file(&source, &container, PASSWORD, shredding, &Progress::new())
        .expect("encrypt");

    assert!(!source.exists(), "source survived shredding");
    let restored = crypto::decrypt_buf(&container, PASSWORD, None, &Progress::new())
        .expect("decrypt");
    assert_eq!(&restored[..], b"burn after reading");
}

#[test]
fn not_a_container() {
    let dir = tempfile::tempdir().expect("temp dir");

    let readme = dir.path().join("readme.txt");
    fs::write(&readme, b"just some notes, no magic bytes here").expect("write");
    assert!(crypto::peek(&readme).is_none());

    let empty = dir.path().join("empty.txt");
    fs::write(&empty, b"").expect("write");
    assert!(crypto::peek(&empty).is_none());

    let stub = dir.path().join("stub.enc");
    fs::write(&stub, b"tiny").expect("write");
    assert!(crypto::peek(&stub).is_none());

    let directory = dir.path().join("subdir");
    fs::create_dir(&directory).expect("mkdir");
    assert!(crypto::peek(&directory).is_none());
}

#[test]
fn pass_len() {
    assert!(crypto::check_pass("short").is_err());
    assert!(crypto::check_pass("longenough").is_ok());
}

#[test]
fn old_v1() {
    for (password, hwid_flag) in [("legacy secret", 0u8), ("", 0u8)] {
        let dir = tempfile::tempdir().expect("temp dir");
        let container = dir.path().join("old.txt.enc");
        write_old_v1(&container, b"contents from an older release", password, hwid_flag);

        let info = crypto::peek(&container).expect("inspectable");
        assert_eq!(info.version, 1);
        assert_eq!(info.hwid, Some(false));

        let restored = crypto::decrypt_buf(&container, password, None, &Progress::new())
            .expect("decrypt legacy container");
        assert_eq!(&restored[..], b"contents from an older release");
    }
}

#[test]
fn old_v0() {
    let dir = tempfile::tempdir().expect("temp dir");
    let container = dir.path().join("ancient.enc");
    write_old_v0(&container, b"no magic bytes here", "legacy secret");

    let info = crypto::peek(&container).expect("inspectable");
    assert_eq!(info.version, 0);
    assert_eq!(info.hwid, None);

    let restored = crypto::decrypt_buf(&container, "legacy secret", Some(false), &Progress::new())
        .expect("decrypt legacy container");
    assert_eq!(&restored[..], b"no magic bytes here");
}

fn old_seal(plaintext: &[u8], password: &str, salt: &[u8; 16], nonce: &[u8; 12]) -> Vec<u8> {
    let key = crypto::make_key(password, salt, false, KdfParams::LEGACY).expect("derive key");
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_slice()));
    cipher.encrypt(Nonce::from_slice(nonce), plaintext).expect("seal")
}

fn write_old_v1(path: &Path, plaintext: &[u8], password: &str, flag: u8) {
    let salt = [1u8; 16];
    let nonce = [2u8; 12];
    let mut file = fs::File::create(path).expect("create");
    file.write_all(b"MYEK").expect("magic");
    file.write_all(&[flag]).expect("flag");
    file.write_all(&salt).expect("salt");
    file.write_all(&nonce).expect("nonce");
    file.write_all(&old_seal(plaintext, password, &salt, &nonce)).expect("payload");
}

fn write_old_v0(path: &Path, plaintext: &[u8], password: &str) {
    let salt = [3u8; 16];
    let nonce = [4u8; 12];
    let mut file = fs::File::create(path).expect("create");
    file.write_all(&salt).expect("salt");
    file.write_all(&nonce).expect("nonce");
    file.write_all(&old_seal(plaintext, password, &salt, &nonce)).expect("payload");
}
