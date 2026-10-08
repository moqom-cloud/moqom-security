// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

//! Sender keys: how a viewer in a large broadcast decrypts without being in
//! the group. Each viewer makes an ML-KEM-768 key pair and hands the public
//! half to the group's committer, which seals each epoch's SFrame base key to
//! it. From the base key and the key ID in a frame the viewer derives any
//! publisher's key exactly as a member does (RFC 9605 §5.2).

use crate::codec::{Reader, Writer};
use crate::error::Result;
use crate::suite::{CipherSuite, HpkeCiphertext};

/// The suite envelopes are sealed in. Viewers' keys are ML-KEM-768 whatever
/// suite the group is in.
pub const SUITE: CipherSuite = CipherSuite::MLDSA;

/// A viewer's public key length.
pub const PUBLIC_KEY_LENGTH: usize = 1184;

const LABEL: &str = "MOQOM audience key";

fn context(group_id: &[u8], epoch: u64) -> Vec<u8> {
    let mut w = Writer::default();
    w.vector(group_id);
    w.u64(epoch);
    w.into_bytes()
}

/// A viewer's key pair: the private half as a 64-byte ML-KEM-768 seed, and
/// the public half it hands out.
///
/// # Errors
/// [`crate::Error::CryptoFailure`] if the key cannot be made.
pub fn generate_key_pair() -> Result<(Vec<u8>, Vec<u8>)> {
    SUITE.generate_key_pair()
}

/// Seals an epoch's base key to a viewer:
/// `EncryptWithLabel(pk, "MOQOM audience key", vector(group_id) || uint64(epoch), base_key)`,
/// encoded as an HPKECiphertext.
///
/// # Errors
/// [`crate::Error::Malformed`] or [`crate::Error::CryptoFailure`] for a key
/// that is not ML-KEM-768's.
pub fn seal(base_key: &[u8], public_key: &[u8], group_id: &[u8], epoch: u64) -> Result<Vec<u8>> {
    let sealed =
        SUITE.encrypt_with_label(public_key, LABEL, &context(group_id, epoch), base_key)?;
    let mut w = Writer::default();
    sealed.write(&mut w);
    Ok(w.into_bytes())
}

/// Opens an envelope sealed for `group_id` at `epoch`.
///
/// # Errors
/// [`crate::Error::DecryptionFailed`] for any other group or epoch, or a
/// tampered envelope; [`crate::Error::Malformed`] if it does not decode.
pub fn open(envelope: &[u8], private_key: &[u8], group_id: &[u8], epoch: u64) -> Result<Vec<u8>> {
    let mut r = Reader(envelope);
    let sealed = HpkeCiphertext::read(&mut r)?;
    r.finish()?;
    SUITE.decrypt_with_label(private_key, LABEL, &context(group_id, epoch), &sealed)
}
