// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

use crate::Error;

/// The KID and CTR that precede an SFrame ciphertext.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Header {
    pub key_id: u64,
    pub counter: u64,
}

impl Header {
    /// RFC 9605 §4.3: a value below 8 rides in the config byte, anything larger
    /// follows in the minimum number of big-endian bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(17);
        out.push(0);
        if self.key_id < 8 {
            out[0] |= (self.key_id as u8) << 4;
        } else {
            let bytes = compact(self.key_id);
            out[0] |= 0x80 | ((bytes.len() as u8 - 1) << 4);
            out.extend_from_slice(bytes.as_slice());
        }
        if self.counter < 8 {
            out[0] |= self.counter as u8;
        } else {
            let bytes = compact(self.counter);
            out[0] |= 0x08 | (bytes.len() as u8 - 1);
            out.extend_from_slice(bytes.as_slice());
        }
        out
    }

    /// Parse a header, returning it and how many bytes it took. A value in
    /// more bytes than it needs is read rather than refused: the tag
    /// authenticates the header bytes as received.
    pub fn read(data: &[u8]) -> Result<(Self, usize), Error> {
        let &config = data.first().ok_or(Error::MalformedHeader)?;
        let mut offset = 1;
        let mut field = |extended: bool, value: u8| -> Result<u64, Error> {
            if !extended {
                return Ok(u64::from(value));
            }
            let length = usize::from(value) + 1;
            let bytes = data
                .get(offset..offset + length)
                .ok_or(Error::MalformedHeader)?;
            offset += length;
            Ok(bytes.iter().fold(0, |acc, &b| (acc << 8) | u64::from(b)))
        };
        let key_id = field(config & 0x80 != 0, (config >> 4) & 0x07)?;
        let counter = field(config & 0x08 != 0, config & 0x07)?;
        Ok((Self { key_id, counter }, offset))
    }
}

struct Compact {
    bytes: [u8; 8],
    start: usize,
}

impl Compact {
    fn len(&self) -> usize {
        8 - self.start
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes[self.start..]
    }
}

fn compact(value: u64) -> Compact {
    let bytes = value.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(7);
    Compact { bytes, start }
}

/// E in RFC 9605 §5.2: a receiver holds the current epoch and, briefly, the one
/// before it, so sixteen distinguishable epochs is far more than is live at once.
pub const EPOCH_BITS: u32 = 4;

/// The label an MLS group exports an epoch's `base_key` under, with an empty
/// context and [`crate::CipherSuite::key_length`] bytes.
pub const MLS_EXPORTER_LABEL: &str = "SFrame 1.0 Base Key";

/// RFC 9605 §5.2's KID for an MLS member with context 0:
/// `(leaf << E) | (epoch mod 2^E)`.
#[must_use]
pub const fn mls_key_id(leaf: u32, epoch: u64) -> u64 {
    ((leaf as u64) << EPOCH_BITS) | (epoch & ((1 << EPOCH_BITS) - 1))
}

/// The low bits of an epoch as a KID carries them.
#[must_use]
pub const fn epoch_tag(key_id: u64) -> u64 {
    key_id & ((1 << EPOCH_BITS) - 1)
}
