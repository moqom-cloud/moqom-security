// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

//! moqom-sframe: SFrame (RFC 9605) for MoQ objects.
//!
//! An object is sealed under a key derived from a base key and a KID, with a
//! counter the sender owns, and with the object's [`Metadata`] — full track
//! name, group, object, priority and properties, the fields
//! `draft-ietf-moq-secure-objects` authenticates — bound into the AEAD tag as
//! AAD after the RFC 9605 header. A relay can read and forward them and cannot
//! change any of them.
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
//!
//! # Sealing and opening an object
//!
//! In a room the base key is exported from the MLS group under
//! [`MLS_EXPORTER_LABEL`]. Both ends derive the same key from it.
//!
//! ```
//! use moqom_sframe::{
//!     CipherSuite, Error, Key, Metadata, Property, Receiver, Sender, Track, mls_key_id,
//! };
//!
//! # fn main() -> Result<(), Error> {
//! let base_key = [0x2a; 32];
//! let key = Key::new(mls_key_id(3, 14), &base_key, CipherSuite::Aes256GcmSha512)?; // leaf 3, epoch 14
//! let sender = Sender::new(key.clone());
//! let receiver = Receiver::default();
//! receiver.add(key);
//!
//! let metadata = Metadata {
//!     track: Track::new(["moqom", "demo", "alice"], "video"),
//!     group: 5,
//!     object: 2,
//!     priority: 64,
//!     properties: vec![
//!         Property::integer(0x78, 1_000_000), // capture time
//!         Property::integer(0x7a, 1),         // temporal layer
//!     ],
//! };
//! let object = sender.protect_object(b"frame", &metadata)?;
//! assert_eq!(object[..2], [0x80, 0x3e]); // KID 62, counter 0
//! assert_eq!(object.len(), 2 + 5 + 16);
//!
//! // A relay that relabels the object's group, moves it to another track, or
//! // flips a bit, is caught.
//! let moved = Metadata { group: 6, ..metadata.clone() };
//! assert_eq!(receiver.unprotect_object(&object, &moved), Err(Error::AuthenticationFailure));
//! let moved = Metadata { track: Track::new(["moqom", "demo", "bob"], "video"), ..metadata.clone() };
//! assert_eq!(receiver.unprotect_object(&object, &moved), Err(Error::AuthenticationFailure));
//! let mut damaged = object.clone();
//! *damaged.last_mut().unwrap() ^= 0x01;
//! assert_eq!(receiver.unprotect_object(&damaged, &metadata), Err(Error::AuthenticationFailure));
//!
//! // Neither failure used up the counter, so the real object still opens.
//! assert_eq!(receiver.unprotect_object(&object, &metadata)?, b"frame");
//! assert_eq!(
//!     receiver.unprotect_object(&object, &metadata),
//!     Err(Error::Replay { counter: 0 })
//! );
//! # Ok(())
//! # }
//! ```
//!
//! # The replay window
//!
//! Objects may arrive out of order. With the default window of 1,024, a
//! counter up to 1,023 behind the highest seen is accepted once.
//!
//! ```
//! use moqom_sframe::{CipherSuite, Context, Error, Metadata, Track};
//!
//! # fn main() -> Result<(), Error> {
//! let context = Context::new(CipherSuite::Aes256GcmSha512, 1, &[0x2a; 32])?;
//! let track = Track::new(["moqom", "demo", "alice"], "audio");
//! let metadata = Metadata { track, group: 0, object: 0, priority: 128, properties: vec![] };
//! let objects = (0..=1024u32)
//!     .map(|counter| context.seal(&counter.to_be_bytes(), &metadata))
//!     .collect::<Result<Vec<_>, _>>()?;
//!
//! context.open(&objects[1024], &metadata)?;
//! context.open(&objects[1], &metadata)?; // 1,023 behind: accepted
//! assert_eq!(context.open(&objects[0], &metadata), Err(Error::Replay { counter: 0 })); // 1,024 behind
//! assert_eq!(context.open(&objects[1], &metadata), Err(Error::Replay { counter: 1 })); // already seen
//! # Ok(())
//! # }
//! ```

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
pub use metadata::{Metadata, Property, PropertyValue, Track};
pub use protect::{DEFAULT_REPLAY_WINDOW, Receiver, Sender};

/// An RFC 9605 §8.1 cipher suite: AES-256-GCM, and nothing else.
///
/// AES-128-GCM (0x0004) is deliberately absent, so an object or a peer that
/// names it is refused rather than negotiated down to.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum CipherSuite {
    /// AES-256-GCM with SHA-512. 16-byte tag.
    #[default]
    Aes256GcmSha512 = 0x0005,
}

impl CipherSuite {
    pub const ALL: [Self; 1] = [Self::Aes256GcmSha512];

    /// AEAD key length, which is also the length of an MLS-exported base key.
    #[must_use]
    pub const fn key_length(self) -> usize {
        32
    }

    /// 12, as GCM wants.
    #[must_use]
    pub const fn nonce_length(self) -> usize {
        12
    }

    /// 16.
    #[must_use]
    pub const fn tag_length(self) -> usize {
        16
    }
}

impl TryFrom<u16> for CipherSuite {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self, Error> {
        match value {
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
    /// A base key that is not the suite's [`CipherSuite::key_length`].
    #[error("sframe base key is not the suite's key length")]
    InvalidBaseKey,
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
            Self::InvalidBaseKey => "invalid_base_key",
        }
    }
}
