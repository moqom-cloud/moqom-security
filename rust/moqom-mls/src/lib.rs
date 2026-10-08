// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

//! moqom-mls: the subset of MLS (RFC 9420) MOQOM rooms run on, bit-compatible
//! with the Swift (`MoqomMLS`) and Go (`go/mls`) implementations and held to
//! the same vectors in `vectors/mls`.
//!
//! - Suites: [`CipherSuite::MLDSA`] (HPKE ML-KEM-768, HKDF-SHA384,
//!   AES-256-GCM, ML-DSA-65), which every new group is founded in,
//!   [`CipherSuite::XWING`] (HPKE X-Wing, HKDF-SHA256, AES-128-GCM, Ed25519)
//!   and [`CipherSuite::X25519`].
//! - Key packages: [`KeyPackageBundle::generate`], [`KeyPackage::parse`].
//! - Groups: [`Group::create`], [`Group::commit`], [`Group::join`],
//!   [`Group::process`], [`Group::exporter`], [`Group::epoch_authenticator`].
//! - Audience envelopes: [`audience::seal`], [`audience::open`].
//!
//! No ratchet tree, no PrivateMessage or PublicMessage framing, no PSKs, no
//! external commits; see `docs/moqom-mls.md`.

pub mod audience;
mod codec;
mod error;
mod group;
mod hpke;
mod key_package;
mod key_schedule;
mod mlkem;
mod suite;
mod xwing;

pub use error::{Error, Result};
pub use group::{CommitMessage, Group, Leaf, PendingCommit, Processed, Welcome};
pub use key_package::{KeyPackage, KeyPackageBundle};
pub use key_schedule::{EpochSecrets, GroupContext, SFRAME_EXPORTER_LABEL, welcome_secret};
pub use suite::{CipherSuite, HpkeCiphertext};
