use std::fmt;

use zeroize::{Zeroize, Zeroizing};

const INITIAL_CAPACITY: usize = 512;

pub struct Secret {
    buf: Vec<u8>,
}

impl Secret {
    pub fn new() -> Self {
        Secret { buf: Vec::with_capacity(INITIAL_CAPACITY) }
    }

    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.buf).unwrap_or("")
    }

    pub fn clone_z(&self) -> Zeroizing<String> {
        Zeroizing::new(self.as_str().to_owned())
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn nchars(&self) -> usize {
        self.as_str().chars().count()
    }

    pub fn push(&mut self, c: char) {
        self.grow(c.len_utf8());
        let mut encoded = [0u8; 4];
        let encoded = c.encode_utf8(&mut encoded);
        self.buf.extend_from_slice(encoded.as_bytes());
    }

    pub fn pop(&mut self) {
        while let Some(&byte) = self.buf.last() {
            let last = self.buf.len() - 1;
            self.buf[last] = 0;
            self.buf.truncate(last);
            if byte & 0b1100_0000 != 0b1000_0000 {
                break;
            }
        }
    }

    pub fn clear(&mut self) {
        self.buf.zeroize();
        self.buf.clear();
    }

    pub fn matches(&self, other: &Secret) -> bool {
        self.buf == other.buf
    }

    fn grow(&mut self, extra: usize) {
        if self.buf.len() + extra <= self.buf.capacity() {
            return;
        }
        let capacity = (self.buf.capacity() * 2).max(self.buf.len() + extra);
        let mut grown = Vec::with_capacity(capacity);
        grown.extend_from_slice(&self.buf);
        let mut stale = std::mem::replace(&mut self.buf, grown);
        stale.zeroize();
    }
}

impl Default for Secret {
    fn default() -> Self {
        Secret::new()
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret({} chars)", self.nchars())
    }
}

impl From<&str> for Secret {
    fn from(value: &str) -> Self {
        let mut secret = Secret::new();
        for c in value.chars() {
            secret.push(c);
        }
        secret
    }
}

#[cfg(test)]
mod tests {
    use super::Secret;

    #[test]
    fn push_pop() {
        let mut secret = Secret::new();
        for c in "пароль-42".chars() {
            secret.push(c);
        }
        assert_eq!(secret.as_str(), "пароль-42");
        assert_eq!(secret.nchars(), 9);

        secret.pop();
        secret.pop();
        assert_eq!(secret.as_str(), "пароль-");

        secret.pop();
        secret.pop();
        assert_eq!(secret.as_str(), "парол");
    }

    #[test]
    fn grows_ok() {
        let mut secret = Secret::new();
        let expected = "ю".repeat(1000);
        for c in expected.chars() {
            secret.push(c);
        }
        assert_eq!(secret.as_str(), expected);
    }

    #[test]
    fn clear_works() {
        let mut secret = Secret::from("hunter2");
        secret.clear();
        assert!(secret.is_empty());
        assert_eq!(secret.as_str(), "");
    }
}
