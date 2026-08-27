use crate::error::{Error, Result};

pub const MAGIC: &[u8; 4] = b"MYEK";
pub const VERSION: u8 = 2;

pub const FLAG_HWID: u8 = 0x01;
pub const FLAG_TAR: u8 = 0x02;

pub const SALT_LEN: usize = 16;
pub const NONCE_PREFIX_LEN: usize = 7;
pub const HEADER_LEN: usize = 4 + 1 + 1 + 4 + 4 + 4 + SALT_LEN + NONCE_PREFIX_LEN;

pub const LEGACY_NONCE_LEN: usize = 12;
pub const V1_HEADER_LEN: usize = 4 + 1 + SALT_LEN + LEGACY_NONCE_LEN;
pub const V0_HEADER_LEN: usize = SALT_LEN + LEGACY_NONCE_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl KdfParams {
    pub const CURRENT: KdfParams = KdfParams { m_cost: 64 * 1024, t_cost: 4, p_cost: 4 };

    pub const LEGACY: KdfParams = KdfParams { m_cost: 64 * 1024, t_cost: 4, p_cost: 4 };

    const MAX_M_COST: u32 = 1024 * 1024;
    const MAX_T_COST: u32 = 64;
    const MAX_P_COST: u32 = 64;

    fn check(self) -> Result<Self> {
        let sane = (8..=Self::MAX_M_COST).contains(&self.m_cost)
            && (1..=Self::MAX_T_COST).contains(&self.t_cost)
            && (1..=Self::MAX_P_COST).contains(&self.p_cost);
        if sane {
            Ok(self)
        } else {
            Err(Error::Format("key derivation parameters out of range"))
        }
    }
}

#[derive(Debug, Clone)]
pub struct Header {
    pub flags: u8,
    pub kdf: KdfParams,
    pub salt: [u8; SALT_LEN],
    pub nonce_prefix: [u8; NONCE_PREFIX_LEN],
}

impl Header {
    pub fn new(
        hwid: bool,
        tar: bool,
        kdf: KdfParams,
        salt: [u8; SALT_LEN],
        nonce_prefix: [u8; NONCE_PREFIX_LEN],
    ) -> Self {
        let mut flags = 0u8;
        if hwid {
            flags |= FLAG_HWID;
        }
        if tar {
            flags |= FLAG_TAR;
        }
        Header { flags, kdf, salt, nonce_prefix }
    }

    pub fn hwid(&self) -> bool {
        self.flags & FLAG_HWID != 0
    }

    pub fn tar(&self) -> bool {
        self.flags & FLAG_TAR != 0
    }

    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0..4].copy_from_slice(MAGIC);
        out[4] = VERSION;
        out[5] = self.flags;
        out[6..10].copy_from_slice(&self.kdf.m_cost.to_le_bytes());
        out[10..14].copy_from_slice(&self.kdf.t_cost.to_le_bytes());
        out[14..18].copy_from_slice(&self.kdf.p_cost.to_le_bytes());
        out[18..34].copy_from_slice(&self.salt);
        out[34..41].copy_from_slice(&self.nonce_prefix);
        out
    }

    pub fn parse(bytes: &[u8; HEADER_LEN]) -> Result<Self> {
        if &bytes[0..4] != MAGIC {
            return Err(Error::Format("bad magic"));
        }
        if bytes[4] != VERSION {
            return Err(Error::UnsupportedVersion(bytes[4]));
        }
        let kdf = KdfParams {
            m_cost: u32::from_le_bytes(bytes[6..10].try_into().expect("4 bytes")),
            t_cost: u32::from_le_bytes(bytes[10..14].try_into().expect("4 bytes")),
            p_cost: u32::from_le_bytes(bytes[14..18].try_into().expect("4 bytes")),
        }
        .check()?;

        Ok(Header {
            flags: bytes[5],
            kdf,
            salt: bytes[18..34].try_into().expect("16 bytes"),
            nonce_prefix: bytes[34..41].try_into().expect("7 bytes"),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContainerInfo {
    pub version: u8,
    pub hwid: Option<bool>,
    pub tar: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let header = Header::new(true, true, KdfParams::CURRENT, [7u8; 16], [3u8; 7]);
        let parsed = Header::parse(&header.to_bytes()).expect("valid header");
        assert!(parsed.hwid());
        assert!(parsed.tar());
        assert_eq!(parsed.kdf, KdfParams::CURRENT);
        assert_eq!(parsed.salt, [7u8; 16]);
        assert_eq!(parsed.nonce_prefix, [3u8; 7]);
    }

    #[test]
    fn crazy_kdf_gets_rejected() {
        let mut bytes = Header::new(false, false, KdfParams::CURRENT, [0u8; 16], [0u8; 7]).to_bytes();
        bytes[6..10].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(Header::parse(&bytes), Err(Error::Format(_))));
    }

    #[test]
    fn unknown_version() {
        let mut bytes = Header::new(false, false, KdfParams::CURRENT, [0u8; 16], [0u8; 7]).to_bytes();
        bytes[4] = 99;
        assert!(matches!(Header::parse(&bytes), Err(Error::UnsupportedVersion(99))));
    }
}
