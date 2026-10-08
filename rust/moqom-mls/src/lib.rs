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
//!
//! # Examples
//!
//! Alice founds a group and adds Bob from his key package. Bob joins from the
//! Welcome, Alice rotates her leaf key with an empty commit, and both end on
//! the same epoch with the same epoch authenticator and SFrame base key.
//!
//! ```
//! use moqom_mls::{
//!     CipherSuite, CommitMessage, Group, KeyPackage, KeyPackageBundle, Processed,
//!     SFRAME_EXPORTER_LABEL, Welcome,
//! };
//!
//! let room = b"acme/room-42";
//! let alice = KeyPackageBundle::generate("alice/phone", CipherSuite::FOUNDING)?;
//! let bob = KeyPackageBundle::generate("bob/laptop", CipherSuite::FOUNDING)?;
//!
//! // Alice reads Bob's published key package and commits to add him.
//! let bob_package = KeyPackage::parse(&bob.key_package.encode())?;
//! let alice_group = Group::create(room, &alice)?;
//! let add = alice_group.commit(&[bob_package], &[])?;
//! let alice_group = add.next; // once the delivery service accepts add.message
//!
//! // Bob joins from the Welcome.
//! let welcome = Welcome::decode(&add.welcome.expect("Bob was added").encode())?;
//! let bob_group = Group::join(&welcome, &bob)?;
//!
//! // An empty commit refreshes Alice's leaf key; Bob follows it.
//! let update = alice_group.commit(&[], &[])?;
//! let alice_group = update.next;
//! let message = CommitMessage::decode(&update.message.encode())?;
//! let Processed::Advanced(bob_group) = bob_group.process(&message)? else {
//!     panic!("Bob was removed");
//! };
//!
//! assert_eq!((alice_group.epoch(), bob_group.epoch()), (2, 2));
//! assert_eq!(alice_group.epoch_authenticator(), bob_group.epoch_authenticator());
//! let base = alice_group.exporter(SFRAME_EXPORTER_LABEL, &[], 32)?;
//! assert_eq!(base, bob_group.exporter(SFRAME_EXPORTER_LABEL, &[], 32)?);
//! # Ok::<(), moqom_mls::Error>(())
//! ```
//!
//! A delivery service checks a key package before accepting it, and a
//! removed member's [`Group::process`] returns [`Processed::Removed`]:
//!
//! ```
//! use moqom_mls::{CipherSuite, Error, Group, KeyPackage, KeyPackageBundle, Processed};
//!
//! let alice = KeyPackageBundle::generate("alice/phone", CipherSuite::FOUNDING)?;
//! let bob = KeyPackageBundle::generate("bob/laptop", CipherSuite::FOUNDING)?;
//!
//! let mut data = bob.key_package.encode();
//! *data.last_mut().unwrap() ^= 1;
//! assert_eq!(KeyPackage::parse(&data), Err(Error::BadSignature("key package")));
//!
//! let add = Group::create(b"acme/room-42", &alice)?.commit(&[bob.key_package.clone()], &[])?;
//! let bob_group = Group::join(add.welcome.as_ref().expect("Bob was added"), &bob)?;
//! let leaf = add.next.leaf_of("bob/laptop").expect("Bob is a member");
//! let removal = add.next.commit(&[], &[leaf])?;
//! assert!(matches!(bob_group.process(&removal.message)?, Processed::Removed));
//! # Ok::<(), moqom_mls::Error>(())
//! ```
//!
//! A broadcast viewer is not a member. The committer seals each epoch's SFrame
//! base key to the viewer's ML-KEM-768 key, for one group and epoch only:
//!
//! ```
//! use moqom_mls::{Error, audience};
//!
//! let group_id = b"acme/room-42";
//! let base = [0u8; 32]; // from group.exporter(SFRAME_EXPORTER_LABEL, &[], 32)
//!
//! let (private, public) = audience::generate_key_pair()?;
//! let envelope = audience::seal(&base, &public, group_id, 7)?;
//!
//! assert_eq!(audience::open(&envelope, &private, group_id, 7)?, base);
//! assert_eq!(audience::open(&envelope, &private, group_id, 8), Err(Error::DecryptionFailed));
//! # Ok::<(), moqom_mls::Error>(())
//! ```

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

/// The cases of a file in the repository's `vectors/mls`, or `None` in a
/// packaged crate, which does not carry that directory. In the repository a
/// missing file fails.
#[cfg(test)]
fn published_vectors(name: &str) -> Option<Vec<serde_json::Value>> {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let dir = root.join("../../vectors/mls");
    if !dir.exists() && root.join("Cargo.toml.orig").exists() {
        eprintln!("{name}: skipped, the shared vectors are not part of the package");
        return None;
    }
    let path = dir.join(name);
    let document: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let cases = document["cases"].as_array().expect("cases").clone();
    assert!(!cases.is_empty(), "{name}");
    Some(cases)
}
