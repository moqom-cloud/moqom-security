// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

//! The TLS presentation language as RFC 9420 §2.1 uses it: big-endian
//! integers and vectors prefixed with the RFC's variable-length size.

use crate::error::{Error, Result};
use crate::suite::CipherSuite;

pub(crate) const PROTOCOL_VERSION: u16 = 0x0001;

#[derive(Default)]
pub(crate) struct Writer(pub(crate) Vec<u8>);

impl Writer {
    pub(crate) fn from(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }

    pub(crate) fn u8(&mut self, v: u8) {
        self.0.push(v);
    }

    pub(crate) fn u16(&mut self, v: u16) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }

    pub(crate) fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }

    pub(crate) fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }

    pub(crate) fn raw(&mut self, data: &[u8]) {
        self.0.extend_from_slice(data);
    }

    /// RFC 9420 §2.1.2: one, two or four bytes, the top two bits giving which.
    pub(crate) fn length(&mut self, n: usize) {
        if n < 1 << 6 {
            self.u8(n as u8);
        } else if n < 1 << 14 {
            self.u16(n as u16 | 0x4000);
        } else {
            assert!(n < 1 << 30, "mls: vectors are limited to 2^30 bytes");
            self.u32(n as u32 | 0x8000_0000);
        }
    }

    pub(crate) fn vector(&mut self, data: &[u8]) {
        self.length(data.len());
        self.raw(data);
    }

    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

pub(crate) struct Reader<'a>(pub(crate) &'a [u8]);

impl<'a> Reader<'a> {
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.0.len() < n {
            return Err(Error::Malformed("truncated"));
        }
        let (out, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(out)
    }

    pub(crate) fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }

    pub(crate) fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    pub(crate) fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    /// Refuses a value not written in its shortest form, as the RFC requires.
    pub(crate) fn length(&mut self) -> Result<usize> {
        let first = self.u8()?;
        match first >> 6 {
            0 => Ok(usize::from(first)),
            1 => {
                let value = usize::from(first & 0x3f) << 8 | usize::from(self.u8()?);
                if value < 1 << 6 {
                    return Err(Error::Malformed("length not minimally encoded"));
                }
                Ok(value)
            }
            2 => {
                let rest = self.take(3)?;
                let value = usize::from(first & 0x3f) << 24
                    | usize::from(rest[0]) << 16
                    | usize::from(rest[1]) << 8
                    | usize::from(rest[2]);
                if value < 1 << 14 {
                    return Err(Error::Malformed("length not minimally encoded"));
                }
                Ok(value)
            }
            _ => Err(Error::Malformed("reserved length prefix")),
        }
    }

    pub(crate) fn vector(&mut self) -> Result<&'a [u8]> {
        let n = self.length()?;
        self.take(n)
    }

    pub(crate) fn finish(&self) -> Result<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(Error::Malformed("trailing bytes"))
        }
    }

    /// A version and suite, refusing either if not implemented.
    pub(crate) fn cipher_suite(&mut self) -> Result<CipherSuite> {
        let version = self.u16()?;
        let suite = CipherSuite(self.u16()?);
        if version != PROTOCOL_VERSION {
            return Err(Error::Unsupported("protocol version"));
        }
        if !suite.is_known() {
            return Err(Error::Unsupported("cipher suite"));
        }
        Ok(suite)
    }
}

#[cfg(test)]
mod tests {
    use super::{Reader, Writer};

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn published_deserialization() {
        assert!(
            Reader(&[0x40, 0x05, 1, 2, 3, 4, 5]).vector().is_err(),
            "a two-byte encoding of five"
        );
        let Some(cases) = crate::published_vectors("mlswg-deserialization.json") else {
            return;
        };
        for v in &cases {
            let length = v["length"].as_u64().unwrap() as usize;
            let header = hex(v["vlbytes_header"].as_str().unwrap());
            let mut w = Writer::default();
            w.length(length);
            assert_eq!(w.into_bytes(), header);
            let mut r = Reader(&header);
            assert_eq!(r.length().unwrap(), length);
            r.finish().unwrap();
        }
    }
}
