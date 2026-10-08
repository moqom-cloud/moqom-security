// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

use crate::Error;

/// The canonical description of one MoQ object, bound into the tag with its
/// payload: the fields a relay reads to schedule, which it can then read and
/// not change.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Metadata {
    pub group: u64,
    pub object: u64,
    pub priority: u8,
    pub properties: Vec<Property>,
}

/// One object property. Even codes carry a varint and odd codes carry bytes;
/// a mismatched pair has no encoding.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Property {
    /// The property type.
    pub code: u64,
    pub value: PropertyValue,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PropertyValue {
    Integer(u64),
    Bytes(Vec<u8>),
}

impl Property {
    #[must_use]
    pub const fn integer(code: u64, value: u64) -> Self {
        Self {
            code,
            value: PropertyValue::Integer(value),
        }
    }

    #[must_use]
    pub const fn bytes(code: u64, value: Vec<u8>) -> Self {
        Self {
            code,
            value: PropertyValue::Bytes(value),
        }
    }
}

const VARINT_MAXIMUM: u64 = (1 << 62) - 1;
const MAXIMUM_PROPERTY_LENGTH: usize = (1 << 16) - 1;

impl Metadata {
    /// The AAD appended to the SFrame header: the MOQT wire encoding of the same
    /// fields, QUIC varints throughout, and properties as a count followed by
    /// type-delta-coded pairs sorted by type, keeping the given order among
    /// equal types.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::with_capacity(16);
        varint(self.group, &mut out)?;
        varint(self.object, &mut out)?;
        out.push(self.priority);
        varint(self.properties.len() as u64, &mut out)?;

        let mut sorted: Vec<&Property> = self.properties.iter().collect();
        sorted.sort_by_key(|p| p.code);
        let mut previous = 0;
        for property in sorted {
            varint(property.code - previous, &mut out)?;
            previous = property.code;
            match &property.value {
                PropertyValue::Integer(value) if property.code % 2 == 0 => {
                    varint(*value, &mut out)?
                }
                PropertyValue::Bytes(value)
                    if property.code % 2 == 1 && value.len() <= MAXIMUM_PROPERTY_LENGTH =>
                {
                    varint(value.len() as u64, &mut out)?;
                    out.extend_from_slice(value);
                }
                _ => return Err(Error::InvalidMetadata),
            }
        }
        Ok(out)
    }
}

/// RFC 9000 §16, minimal length.
fn varint(value: u64, out: &mut Vec<u8>) -> Result<(), Error> {
    match value {
        0..=63 => out.push(value as u8),
        64..=16383 => out.extend_from_slice(&(value as u16 | 0x4000).to_be_bytes()),
        16384..=1_073_741_823 => out.extend_from_slice(&(value as u32 | 0x8000_0000).to_be_bytes()),
        1_073_741_824..=VARINT_MAXIMUM => {
            out.extend_from_slice(&(value | 0xC000_0000_0000_0000).to_be_bytes())
        }
        _ => return Err(Error::InvalidMetadata),
    }
    Ok(())
}
