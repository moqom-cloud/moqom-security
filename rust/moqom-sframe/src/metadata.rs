// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

use crate::Error;

/// A MoQ Full Track Name: the namespace's fields and the track's name, as
/// bytes.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Track {
    pub namespace: Vec<Vec<u8>>,
    pub name: Vec<u8>,
}

impl Track {
    /// MOQT's limit on namespace fields. At least one is required.
    pub const MAX_NAMESPACE_FIELDS: usize = 32;
    /// MOQT's limit on the namespace fields and the name together, in bytes.
    pub const MAX_LENGTH: usize = 4096;

    /// The track with these namespace fields and name, as given.
    pub fn new<F: AsRef<[u8]>>(
        namespace: impl IntoIterator<Item = F>,
        name: impl AsRef<[u8]>,
    ) -> Self {
        Self {
            namespace: namespace.into_iter().map(|f| f.as_ref().to_vec()).collect(),
            name: name.as_ref().to_vec(),
        }
    }

    /// The Serialized Full Track Name of `draft-ietf-moq-secure-objects`
    /// §3.3.1: the number of namespace fields, each field with its length, then
    /// the name with its length, all lengths as varints.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidMetadata`] for no namespace fields, more than
    /// [`Track::MAX_NAMESPACE_FIELDS`], or more than [`Track::MAX_LENGTH`] bytes.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        self.encode_into(&mut out)?;
        Ok(out)
    }

    fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let total = self.namespace.iter().map(Vec::len).sum::<usize>() + self.name.len();
        if !(1..=Self::MAX_NAMESPACE_FIELDS).contains(&self.namespace.len())
            || total > Self::MAX_LENGTH
        {
            return Err(Error::InvalidMetadata);
        }
        varint(self.namespace.len() as u64, out)?;
        for field in &self.namespace {
            varint(field.len() as u64, out)?;
            out.extend_from_slice(field);
        }
        varint(self.name.len() as u64, out)?;
        out.extend_from_slice(&self.name);
        Ok(())
    }
}

/// The canonical description of one MoQ object, bound into the tag with its
/// payload: the fields a relay reads to route and schedule, which it can then
/// read and not change.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Metadata {
    pub track: Track,
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
    /// fields — the Serialized Full Track Name, QUIC varints, and properties as
    /// a count followed by type-delta-coded pairs sorted by type, keeping the
    /// given order among equal types.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidMetadata`] if any field has no encoding.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::with_capacity(32);
        self.track.encode_into(&mut out)?;
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
