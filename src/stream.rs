use std::io::{self, Read, Write};

use aes_gcm::aead::stream::{DecryptorBE32, EncryptorBE32};
use aes_gcm::aead::Payload;
use aes_gcm::{Aes256Gcm, Key, KeyInit};
use zeroize::Zeroizing;

use crate::error::Error;
use crate::progress::Progress;

pub const CHUNK_SIZE: usize = 64 * 1024;

const TAG_LEN: usize = 16;
const MAX_FRAME_LEN: usize = CHUNK_SIZE + TAG_LEN;
const KIND_NEXT: u8 = 0;
const KIND_LAST: u8 = 1;

fn cipher(key: &[u8; 32]) -> Aes256Gcm {
    Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key))
}

fn bad_tag() -> io::Error {
    Error::Authentication.to_io()
}

pub struct EncryptWriter<W: Write> {
    inner: W,
    encryptor: Option<EncryptorBE32<Aes256Gcm>>,
    buf: Zeroizing<Vec<u8>>,
    aad: Vec<u8>,
    progress: Progress,
}

impl<W: Write> EncryptWriter<W> {
    pub fn new(
        inner: W,
        key: &[u8; 32],
        nonce_prefix: &[u8; 7],
        aad: Vec<u8>,
        progress: Progress,
    ) -> Self {
        EncryptWriter {
            inner,
            encryptor: Some(EncryptorBE32::from_aead(cipher(key), nonce_prefix.as_slice().into())),
            buf: Zeroizing::new(Vec::with_capacity(CHUNK_SIZE)),
            aad,
            progress,
        }
    }

    pub fn finish(mut self) -> io::Result<W> {
        {
            let Self { encryptor, buf, aad, inner, .. } = &mut self;
            let encryptor =
                encryptor.take().ok_or_else(|| io::Error::other("stream already finished"))?;
            let sealed = encryptor
                .encrypt_last(Payload { msg: buf, aad })
                .map_err(|_| bad_tag())?;
            put_frame(inner, KIND_LAST, &sealed)?;
            inner.flush()?;
        }
        Ok(self.inner)
    }

    fn flush_chunk(&mut self) -> io::Result<()> {
        let Self { encryptor, buf, aad, inner, .. } = self;
        let encryptor =
            encryptor.as_mut().ok_or_else(|| io::Error::other("stream already finished"))?;
        let sealed = encryptor
            .encrypt_next(Payload { msg: buf, aad })
            .map_err(|_| bad_tag())?;
        put_frame(inner, KIND_NEXT, &sealed)?;
        buf.clear();
        Ok(())
    }
}

impl<W: Write> Write for EncryptWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        let room = CHUNK_SIZE - self.buf.len();
        let taken = room.min(data.len());
        self.buf.extend_from_slice(&data[..taken]);
        self.progress.add(taken as u64);
        if self.buf.len() == CHUNK_SIZE {
            self.flush_chunk()?;
        }
        Ok(taken)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

pub struct DecryptReader<R: Read> {
    inner: R,
    decryptor: Option<DecryptorBE32<Aes256Gcm>>,
    plain: Zeroizing<Vec<u8>>,
    offset: usize,
    finished: bool,
    aad: Vec<u8>,
    progress: Progress,
}

impl<R: Read> DecryptReader<R> {
    pub fn new(
        inner: R,
        key: &[u8; 32],
        nonce_prefix: &[u8; 7],
        aad: Vec<u8>,
        progress: Progress,
    ) -> Self {
        DecryptReader {
            inner,
            decryptor: Some(DecryptorBE32::from_aead(cipher(key), nonce_prefix.as_slice().into())),
            plain: Zeroizing::new(Vec::new()),
            offset: 0,
            finished: false,
            aad,
            progress,
        }
    }

    fn fill(&mut self) -> io::Result<()> {
        let mut kind = [0u8; 1];
        match self.inner.read_exact(&mut kind) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
                return Err(Error::Authentication.to_io());
            }
            Err(err) => return Err(err),
        }

        let mut len_bytes = [0u8; 4];
        self.inner.read_exact(&mut len_bytes)?;
        let len = u32::from_le_bytes(len_bytes) as usize;
        if !(TAG_LEN..=MAX_FRAME_LEN).contains(&len) {
            return Err(Error::Format("frame length out of range").to_io());
        }

        let mut frame = vec![0u8; len];
        self.inner.read_exact(&mut frame)?;

        let Self { decryptor, aad, plain, .. } = self;
        let payload = Payload { msg: &frame, aad };
        let opened = match kind[0] {
            KIND_NEXT => {
                let decryptor = decryptor
                    .as_mut()
                    .ok_or_else(|| Error::Format("frame after end of stream").to_io())?;
                decryptor.decrypt_next(payload).map_err(|_| bad_tag())?
            }
            KIND_LAST => {
                let decryptor = decryptor
                    .take()
                    .ok_or_else(|| Error::Format("frame after end of stream").to_io())?;
                let opened = decryptor.decrypt_last(payload).map_err(|_| bad_tag())?;
                self.finished = true;
                opened
            }
            _ => return Err(Error::Format("unknown frame kind").to_io()),
        };

        *plain = Zeroizing::new(opened);
        self.offset = 0;
        Ok(())
    }
}

impl<R: Read> Read for DecryptReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            if self.offset < self.plain.len() {
                let available = self.plain.len() - self.offset;
                let taken = available.min(out.len());
                out[..taken].copy_from_slice(&self.plain[self.offset..self.offset + taken]);
                self.offset += taken;
                self.progress.add(taken as u64);
                return Ok(taken);
            }
            if self.finished {
                return Ok(0);
            }
            self.fill()?;
        }
    }
}

fn put_frame<W: Write>(out: &mut W, kind: u8, ciphertext: &[u8]) -> io::Result<()> {
    out.write_all(&[kind])?;
    out.write_all(&(ciphertext.len() as u32).to_le_bytes())?;
    out.write_all(ciphertext)
}

pub struct MemoryReader {
    data: Zeroizing<Vec<u8>>,
    offset: usize,
    progress: Progress,
}

impl MemoryReader {
    pub fn new(data: Zeroizing<Vec<u8>>, progress: Progress) -> Self {
        MemoryReader { data, offset: 0, progress }
    }
}

impl Read for MemoryReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let available = self.data.len() - self.offset;
        let taken = available.min(out.len());
        out[..taken].copy_from_slice(&self.data[self.offset..self.offset + taken]);
        self.offset += taken;
        self.progress.add(taken as u64);
        Ok(taken)
    }
}
