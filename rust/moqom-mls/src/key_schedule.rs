// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

//! The RFC 9420 §8 key schedule, bit-exact with the RFC and held to the
//! working group's key-schedule vectors. What feeds it -- where the commit
//! secret comes from, what the tree hash covers -- is MOQOM's simplification;
//! see `group.rs`.

use zeroize::Zeroize;

use crate::codec::{PROTOCOL_VERSION, Reader, Writer};
use crate::error::{Error, Result};
use crate::suite::CipherSuite;

/// The label RFC 9605 §5.2 exports an epoch's SFrame base_key under, with an
/// empty context and the SFrame suite's AEAD.Nk bytes.
pub const SFRAME_EXPORTER_LABEL: &str = "SFrame 1.0 Base Key";

/// GroupContext, RFC 9420 §8.1. The cipher suite is part of it, so every
/// signature over a commit or GroupInfo, and every secret derived, is bound to
/// the suite the group was founded with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupContext {
    pub cipher_suite: CipherSuite,
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub tree_hash: Vec<u8>,
    pub confirmed_transcript_hash: Vec<u8>,
}

impl GroupContext {
    /// The serialised form. Extensions are always empty: none are implemented.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.u16(PROTOCOL_VERSION);
        w.u16(self.cipher_suite.0);
        w.vector(&self.group_id);
        w.u64(self.epoch);
        w.vector(&self.tree_hash);
        w.vector(&self.confirmed_transcript_hash);
        w.vector(&[]);
        w.into_bytes()
    }

    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self> {
        let context = Self {
            cipher_suite: r.cipher_suite()?,
            group_id: r.vector()?.to_vec(),
            epoch: r.u64()?,
            tree_hash: r.vector()?.to_vec(),
            confirmed_transcript_hash: r.vector()?.to_vec(),
        };
        if !r.vector()?.is_empty() {
            return Err(Error::Unsupported("GroupContext extensions"));
        }
        Ok(context)
    }
}

/// Everything one epoch of the key schedule produces. `Debug` names only the
/// suite.
#[derive(Clone)]
pub struct EpochSecrets {
    pub cipher_suite: CipherSuite,
    pub joiner_secret: Vec<u8>,
    pub welcome_secret: Vec<u8>,
    pub epoch_secret: Vec<u8>,
    pub sender_data_secret: Vec<u8>,
    pub encryption_secret: Vec<u8>,
    pub exporter_secret: Vec<u8>,
    pub external_secret: Vec<u8>,
    pub confirmation_key: Vec<u8>,
    pub membership_key: Vec<u8>,
    pub resumption_psk: Vec<u8>,
    pub epoch_authenticator: Vec<u8>,
    /// The next epoch's init_secret.
    pub init_secret: Vec<u8>,
}

impl core::fmt::Debug for EpochSecrets {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EpochSecrets")
            .field("cipher_suite", &self.cipher_suite)
            .finish_non_exhaustive()
    }
}

impl Drop for EpochSecrets {
    fn drop(&mut self) {
        for secret in [
            &mut self.joiner_secret,
            &mut self.welcome_secret,
            &mut self.epoch_secret,
            &mut self.sender_data_secret,
            &mut self.encryption_secret,
            &mut self.exporter_secret,
            &mut self.external_secret,
            &mut self.confirmation_key,
            &mut self.membership_key,
            &mut self.resumption_psk,
            &mut self.epoch_authenticator,
            &mut self.init_secret,
        ] {
            secret.zeroize();
        }
    }
}

impl EpochSecrets {
    /// One epoch, from the previous epoch's init secret and this commit's
    /// secret. `None` for the PSK secret is the suite's all-zero secret.
    #[must_use]
    pub fn derive(
        init_secret: &[u8],
        commit_secret: &[u8],
        psk_secret: Option<&[u8]>,
        context: &GroupContext,
    ) -> Self {
        Self::derive_encoded(
            context.cipher_suite,
            init_secret,
            commit_secret,
            psk_secret,
            &context.encode(),
        )
    }

    /// The same over a GroupContext already serialised, which is how another
    /// suite's vectors run through the same hash and KDF.
    #[must_use]
    pub fn derive_encoded(
        suite: CipherSuite,
        init_secret: &[u8],
        commit_secret: &[u8],
        psk_secret: Option<&[u8]>,
        encoded_context: &[u8],
    ) -> Self {
        let joiner = suite.expand_label(
            &suite.extract(init_secret, commit_secret),
            "joiner",
            encoded_context,
            suite.hash_length(),
        );
        Self::from_joiner(suite, joiner, psk_secret, encoded_context)
    }

    pub(crate) fn from_joiner(
        suite: CipherSuite,
        joiner: Vec<u8>,
        psk_secret: Option<&[u8]>,
        encoded_context: &[u8],
    ) -> Self {
        let member = suite.extract(&joiner, &psk(suite, psk_secret));
        let epoch = suite.expand_label(&member, "epoch", encoded_context, suite.hash_length());
        let derived = |label| suite.derive_secret(&epoch, label);
        Self {
            cipher_suite: suite,
            welcome_secret: suite.derive_secret(&member, "welcome"),
            sender_data_secret: derived("sender data"),
            encryption_secret: derived("encryption"),
            exporter_secret: derived("exporter"),
            external_secret: derived("external"),
            confirmation_key: derived("confirm"),
            membership_key: derived("membership"),
            resumption_psk: derived("resumption"),
            epoch_authenticator: derived("authentication"),
            init_secret: derived("init"),
            epoch_secret: epoch,
            joiner_secret: joiner,
        }
    }

    /// MLS-Exporter, RFC 9420 §8.5.
    ///
    /// # Errors
    /// [`Error::InvalidLength`] for a `length` past HKDF-Expand's limit of
    /// 255 times the suite's hash length.
    pub fn exporter(&self, label: &str, context: &[u8], length: usize) -> Result<Vec<u8>> {
        let s = self.cipher_suite;
        let max = s.max_expand_length();
        if length > max {
            return Err(Error::InvalidLength { length, max });
        }
        let mut info = Writer::default();
        info.u16(s.hash_length() as u16);
        info.vector(format!("MLS 1.0 {label}").as_bytes());
        info.vector(&[]);
        let secret = s.expand(&self.exporter_secret, &info.into_bytes(), s.hash_length());
        Ok(s.expand_label(&secret, "exported", &s.hash(context), length))
    }
}

fn psk(suite: CipherSuite, secret: Option<&[u8]>) -> Vec<u8> {
    secret.map_or_else(|| vec![0; suite.hash_length()], <[u8]>::to_vec)
}

/// The welcome secret for a joiner secret, without deriving the epoch.
#[must_use]
pub fn welcome_secret(suite: CipherSuite, joiner: &[u8], psk_secret: Option<&[u8]>) -> Vec<u8> {
    suite.derive_secret(&suite.extract(joiner, &psk(suite, psk_secret)), "welcome")
}
