// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

use std::sync::Arc;

use aws_lc_rs::aead::{AES_128_GCM, AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use aws_lc_rs::hkdf::{self, HKDF_SHA256, HKDF_SHA512, KeyType, Salt};

use crate::{CipherSuite, Error};

/// The AEAD key and salt derived from a base key for one KID. Cloning shares
/// the derived key rather than deriving it again.
#[derive(Clone)]
pub struct Key {
    key_id: u64,
    suite: CipherSuite,
    aead: Arc<LessSafeKey>,
    salt: [u8; NONCE_LEN],
    #[cfg(test)]
    pub(crate) raw: Vec<u8>,
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Key")
            .field("key_id", &self.key_id)
            .field("suite", &self.suite)
            .finish_non_exhaustive()
    }
}

struct Length(usize);

impl KeyType for Length {
    fn len(&self) -> usize {
        self.0
    }
}

pub(crate) fn label(prefix: &str, key_id: u64, suite: CipherSuite) -> Vec<u8> {
    let mut label = prefix.as_bytes().to_vec();
    label.extend_from_slice(&key_id.to_be_bytes());
    label.extend_from_slice(&(suite as u16).to_be_bytes());
    label
}

fn extract(base_key: &[u8], suite: CipherSuite) -> hkdf::Prk {
    let algorithm = match suite {
        CipherSuite::Aes128GcmSha256 => HKDF_SHA256,
        CipherSuite::Aes256GcmSha512 => HKDF_SHA512,
    };
    Salt::new(algorithm, &[]).extract(base_key)
}

fn expand(secret: &hkdf::Prk, info: &[u8], out: &mut [u8]) {
    secret
        .expand(&[info], Length(out.len()))
        .and_then(|okm| okm.fill(out))
        .expect("HKDF output of at most 32 bytes always expands");
}

impl Key {
    /// Derive per RFC 9605 §4.4.2. The KID and suite are in the derivation
    /// labels, so a ciphertext made under one KID or suite never authenticates
    /// under another.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidBaseKey`] unless `base_key` is the suite's
    /// [`CipherSuite::key_length`], the length an MLS exporter gives it.
    pub fn new(key_id: u64, base_key: &[u8], suite: CipherSuite) -> Result<Self, Error> {
        if base_key.len() != suite.key_length() {
            return Err(Error::InvalidBaseKey);
        }
        Ok(Self::unchecked(key_id, base_key, suite))
    }

    /// Derive without checking the base key's length, for RFC 9605's Appendix
    /// C, which derives suite 0x0005 keys from a 16-byte base key.
    pub(crate) fn unchecked(key_id: u64, base_key: &[u8], suite: CipherSuite) -> Self {
        let secret = extract(base_key, suite);
        let mut raw = vec![0; suite.key_length()];
        expand(
            &secret,
            &label("SFrame 1.0 Secret key ", key_id, suite),
            &mut raw,
        );
        let mut salt = [0; NONCE_LEN];
        expand(
            &secret,
            &label("SFrame 1.0 Secret salt ", key_id, suite),
            &mut salt,
        );
        let algorithm = match suite {
            CipherSuite::Aes128GcmSha256 => &AES_128_GCM,
            CipherSuite::Aes256GcmSha512 => &AES_256_GCM,
        };
        let aead = Arc::new(LessSafeKey::new(
            UnboundKey::new(algorithm, &raw).expect("derived key has the suite's length"),
        ));
        Self {
            key_id,
            suite,
            aead,
            salt,
            #[cfg(test)]
            raw,
        }
    }

    /// The KID this key seals under.
    #[must_use]
    pub const fn key_id(&self) -> u64 {
        self.key_id
    }

    #[must_use]
    pub const fn suite(&self) -> CipherSuite {
        self.suite
    }

    /// The salt XOR the counter, the counter at the low-order end.
    pub(crate) fn nonce(&self, counter: u64) -> [u8; NONCE_LEN] {
        let mut nonce = self.salt;
        for (byte, c) in nonce[NONCE_LEN - 8..].iter_mut().zip(counter.to_be_bytes()) {
            *byte ^= c;
        }
        nonce
    }

    #[cfg(test)]
    pub(crate) fn salt(&self) -> &[u8] {
        &self.salt
    }

    /// Ciphertext and tag.
    pub(crate) fn seal(
        &self,
        plaintext: &[u8],
        counter: u64,
        aad: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let mut body = plaintext.to_vec();
        self.aead
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(self.nonce(counter)),
                Aad::from(aad),
                &mut body,
            )
            .map_err(|_| Error::AuthenticationFailure)?;
        Ok(body)
    }

    pub(crate) fn open(
        &self,
        ciphertext: &[u8],
        counter: u64,
        aad: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if ciphertext.len() < self.suite.tag_length() {
            return Err(Error::AuthenticationFailure);
        }
        let mut buffer = ciphertext.to_vec();
        let length = self
            .aead
            .open_in_place(
                Nonce::assume_unique_for_key(self.nonce(counter)),
                Aad::from(aad),
                &mut buffer,
            )
            .map_err(|_| Error::AuthenticationFailure)?
            .len();
        buffer.truncate(length);
        Ok(buffer)
    }
}
