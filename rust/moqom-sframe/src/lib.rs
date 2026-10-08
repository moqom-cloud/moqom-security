// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

//! moqom-sframe: SFrame (RFC 9605) for MoQ objects.
//!
//! An object is sealed under a key derived from a base key and a KID, with a
//! counter the sender owns, and with the object's [`Metadata`] — group, object,
//! priority and properties, the fields a relay reads to schedule — bound into
//! the AEAD tag in the shape of `draft-ietf-moq-secure-objects`. A relay can
//! read and forward them and cannot change any of them.
//!
//! Only the AES-GCM suites (0x0004 and 0x0005) are implemented. Every platform
//! MOQOM targets has hardware AES-GCM, and the AES-CTR + HMAC suites would be a
//! composition of our own.
//!
//! [`Context`] is the simple API: [`Context::seal`] and [`Context::open`] under
//! one key. [`Sender`] and [`Receiver`] are the pieces a room uses, a sender per
//! media stream and a receiver holding every other member's key.
//!
//! The same library exists in Go (`github.com/moqom-cloud/moqom-security/go/sframe`)
//! and Swift (`MoqomSFrame`), and all three pass the vectors in `vectors/sframe`.

mod context;
mod header;
mod key;
mod metadata;
mod protect;
#[cfg(test)]
mod vectors;

pub use context::Context;
pub use header::{EPOCH_BITS, Header, MLS_EXPORTER_LABEL, epoch_tag, mls_key_id};
pub use key::Key;
pub use metadata::{Metadata, Property, PropertyValue};
pub use protect::{DEFAULT_REPLAY_WINDOW, Receiver, Sender};

/// An RFC 9605 §8.1 cipher suite.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum CipherSuite {
    /// AES-128-GCM with SHA-256. 16-byte tag.
    Aes128GcmSha256 = 0x0004,
    /// AES-256-GCM with SHA-512. 16-byte tag. The default.
    #[default]
    Aes256GcmSha512 = 0x0005,
}

impl CipherSuite {
    pub const ALL: [Self; 2] = [Self::Aes128GcmSha256, Self::Aes256GcmSha512];

    /// AEAD key length, which is also the length of an MLS-exported base key.
    #[must_use]
    pub const fn key_length(self) -> usize {
        match self {
            Self::Aes128GcmSha256 => 16,
            Self::Aes256GcmSha512 => 32,
        }
    }

    /// 12 for both suites, as GCM wants.
    #[must_use]
    pub const fn nonce_length(self) -> usize {
        12
    }

    /// 16 for both suites.
    #[must_use]
    pub const fn tag_length(self) -> usize {
        16
    }
}

impl TryFrom<u16> for CipherSuite {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self, Error> {
        match value {
            0x0004 => Ok(Self::Aes128GcmSha256),
            0x0005 => Ok(Self::Aes256GcmSha512),
            other => Err(Error::UnsupportedSuite(other)),
        }
    }
}

/// Why an object was refused.
///
/// Each is one of the error classes the shared vectors name; see
/// [`Error::class`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The header is malformed or the object is too short to hold one.
    #[error("sframe header is malformed")]
    MalformedHeader,
    /// No key is held for the KID in the header. Recoverable: key distribution
    /// and media race, so a caller may hold the object and retry.
    #[error("no sframe key for KID {0}")]
    UnknownKey(u64),
    /// Authentication failed. Never report onward in more detail: which objects
    /// fail is information an attacker can use.
    #[error("sframe authentication failed")]
    AuthenticationFailure,
    /// The counter has been seen, or is older than the window.
    #[error("sframe counter {counter} already seen or too old")]
    Replay { counter: u64 },
    /// The counter space for this key is exhausted; the only safe response is
    /// to rekey.
    #[error("sframe counter space exhausted")]
    CounterExhausted,
    /// The sender has no key yet, and refuses rather than send in the clear.
    #[error("no sframe key to send under")]
    NoKey,
    /// Metadata with no canonical encoding; see [`Metadata::encode`].
    #[error("sframe metadata has no canonical encoding")]
    InvalidMetadata,
    /// A cipher suite this library does not implement.
    #[error("sframe cipher suite {0:#06x} is not supported")]
    UnsupportedSuite(u16),
}

impl Error {
    /// The vector error class.
    #[must_use]
    pub const fn class(self) -> &'static str {
        match self {
            Self::MalformedHeader => "malformed_header",
            Self::UnknownKey(_) => "unknown_key",
            Self::AuthenticationFailure => "authentication_failure",
            Self::Replay { .. } => "replay",
            Self::CounterExhausted => "counter_exhausted",
            Self::NoKey => "no_key",
            Self::InvalidMetadata => "invalid_metadata",
            Self::UnsupportedSuite(_) => "unsupported_suite",
        }
    }
}
