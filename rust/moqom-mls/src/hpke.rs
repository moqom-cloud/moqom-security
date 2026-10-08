// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

//! RFC 9180 HPKE, base mode, single shot, for the three KEMs implemented here:
//! ML-KEM-768 (0x0041) and X-Wing (0x647a), whose shared secrets are used as
//! they are (draft-ietf-hpke-pq), and DHKEM(X25519, HKDF-SHA256) (0x0020).
//! aws-lc-rs has no HPKE, so this is RFC 9180 §4 and §5.1 over its KEM,
//! X25519, HKDF and AEAD. The ML-KEM and X-Wing compositions are held to Go's
//! crypto/hpke and CryptoKit by the vectors.

use aws_lc_rs::{aead, agreement, digest, hkdf, hmac, kem};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

pub(crate) const MLKEM768_PUBLIC_KEY_LENGTH: usize = 1184;
pub(crate) const MLKEM768_CIPHERTEXT_LENGTH: usize = 1088;
pub(crate) const MLKEM768_SEED_LENGTH: usize = 64;

/// A shared secret or key, wiped when dropped.
pub(crate) type Secret = Zeroizing<Vec<u8>>;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kem {
    MlKem768,
    XWing,
    X25519,
}

#[derive(Clone, Copy)]
pub(crate) enum Kdf {
    Sha256,
    Sha384,
}

impl Kdf {
    fn id(self) -> u16 {
        match self {
            Self::Sha256 => 0x0001,
            Self::Sha384 => 0x0002,
        }
    }

    fn hmac(self) -> hmac::Algorithm {
        match self {
            Self::Sha256 => hmac::HMAC_SHA256,
            Self::Sha384 => hmac::HMAC_SHA384,
        }
    }

    fn hkdf(self) -> hkdf::Algorithm {
        match self {
            Self::Sha256 => hkdf::HKDF_SHA256,
            Self::Sha384 => hkdf::HKDF_SHA384,
        }
    }

    pub(crate) fn hash(self, data: &[u8]) -> Vec<u8> {
        let algorithm = match self {
            Self::Sha256 => &digest::SHA256,
            Self::Sha384 => &digest::SHA384,
        };
        digest::digest(algorithm, data).as_ref().to_vec()
    }

    pub(crate) fn length(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
        }
    }

    /// HKDF-Extract, which is HMAC keyed with the salt (RFC 5869 §2.2); an
    /// empty salt is HMAC's zero-padded key, as the RFC's default.
    pub(crate) fn extract(self, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        self.mac(salt, ikm)
    }

    pub(crate) fn expand(self, prk: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>> {
        struct Len(usize);
        impl hkdf::KeyType for Len {
            fn len(&self) -> usize {
                self.0
            }
        }
        // Prk::new_less_safe panics past a SHA-512 output.
        if prk.len() > digest::MAX_OUTPUT_LEN {
            return Err(Error::CryptoFailure);
        }
        let prk = hkdf::Prk::new_less_safe(self.hkdf(), prk);
        let mut out = vec![0; length];
        prk.expand(&[info], Len(length))
            .and_then(|okm| okm.fill(&mut out))
            .map_err(|_| Error::CryptoFailure)?;
        Ok(out)
    }

    pub(crate) fn mac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        hmac::sign(&hmac::Key::new(self.hmac(), key), data)
            .as_ref()
            .to_vec()
    }
}

#[derive(Clone, Copy)]
pub(crate) enum Aead {
    Aes128Gcm,
    Aes256Gcm,
}

impl Aead {
    fn id(self) -> u16 {
        match self {
            Self::Aes128Gcm => 0x0001,
            Self::Aes256Gcm => 0x0002,
        }
    }

    pub(crate) fn key_length(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm => 32,
        }
    }

    fn key(self, key: &[u8]) -> Result<aead::LessSafeKey> {
        let algorithm = match self {
            Self::Aes128Gcm => &aead::AES_128_GCM,
            Self::Aes256Gcm => &aead::AES_256_GCM,
        };
        Ok(aead::LessSafeKey::new(
            aead::UnboundKey::new(algorithm, key).map_err(|_| Error::CryptoFailure)?,
        ))
    }

    pub(crate) fn seal(self, key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce =
            aead::Nonce::try_assume_unique_for_key(nonce).map_err(|_| Error::CryptoFailure)?;
        let mut out = plaintext.to_vec();
        self.key(key)?
            .seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut out)
            .map_err(|_| Error::CryptoFailure)?;
        Ok(out)
    }

    pub(crate) fn open(self, key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let nonce =
            aead::Nonce::try_assume_unique_for_key(nonce).map_err(|_| Error::DecryptionFailed)?;
        let mut out = ciphertext.to_vec();
        let length = self
            .key(key)
            .map_err(|_| Error::DecryptionFailed)?
            .open_in_place(nonce, aead::Aad::empty(), &mut out)
            .map_err(|_| Error::DecryptionFailed)?
            .len();
        out.truncate(length);
        Ok(out)
    }
}

pub(crate) const AEAD_NONCE_LENGTH: usize = 12;

#[derive(Clone, Copy)]
pub(crate) struct Hpke {
    pub(crate) kem: Kem,
    pub(crate) kdf: Kdf,
    pub(crate) aead: Aead,
}

fn labeled_extract(kdf: Kdf, suite_id: &[u8], salt: &[u8], label: &str, ikm: &[u8]) -> Vec<u8> {
    let input = [b"HPKE-v1".as_slice(), suite_id, label.as_bytes(), ikm].concat();
    kdf.extract(salt, &input)
}

fn labeled_expand(
    kdf: Kdf,
    suite_id: &[u8],
    prk: &[u8],
    label: &str,
    info: &[u8],
    length: usize,
) -> Result<Vec<u8>> {
    let input = [
        &(length as u16).to_be_bytes(),
        b"HPKE-v1".as_slice(),
        suite_id,
        label.as_bytes(),
        info,
    ]
    .concat();
    kdf.expand(prk, &input, length)
}

const DHKEM_X25519: u16 = 0x0020;
const MLKEM768: u16 = 0x0041;
const XWING: u16 = 0x647a;

impl Kem {
    fn id(self) -> u16 {
        match self {
            Self::MlKem768 => MLKEM768,
            Self::XWing => XWING,
            Self::X25519 => DHKEM_X25519,
        }
    }

    pub(crate) fn private_key_length(self) -> usize {
        match self {
            Self::MlKem768 => MLKEM768_SEED_LENGTH,
            Self::XWing => crate::xwing::SEED_LENGTH,
            Self::X25519 => 32,
        }
    }

    pub(crate) fn public_key_length(self) -> usize {
        match self {
            Self::MlKem768 => MLKEM768_PUBLIC_KEY_LENGTH,
            Self::XWing => crate::xwing::PUBLIC_KEY_LENGTH,
            Self::X25519 => 32,
        }
    }

    pub(crate) fn encapsulation_length(self) -> usize {
        match self {
            Self::MlKem768 => MLKEM768_CIPHERTEXT_LENGTH,
            Self::XWing => crate::xwing::CIPHERTEXT_LENGTH,
            Self::X25519 => 32,
        }
    }

    /// The public key for a private key as RFC 9180's SerializePrivateKey
    /// gives it: ML-KEM-768's 64-byte seed, X-Wing's 32-byte seed or the
    /// X25519 scalar.
    pub(crate) fn public_key(self, private: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::MlKem768 => Ok(crate::mlkem::from_seed(private)?.1),
            Self::XWing => crate::xwing::public_key(private),
            Self::X25519 => {
                let key = agreement::PrivateKey::from_private_key(&agreement::X25519, private)
                    .map_err(|_| Error::CryptoFailure)?;
                Ok(key
                    .compute_public_key()
                    .map_err(|_| Error::CryptoFailure)?
                    .as_ref()
                    .to_vec())
            }
        }
    }

    /// Whether a public key is the KEM's: for ML-KEM-768, alone or as
    /// X-Wing's first half, whether it passes FIPS 203's encapsulation key
    /// check, which encapsulation applies.
    pub(crate) fn is_valid_public_key(self, public: &[u8]) -> bool {
        if public.len() != self.public_key_length() {
            return false;
        }
        match self {
            Self::MlKem768 | Self::XWing => {
                kem::EncapsulationKey::new(&kem::ML_KEM_768, &public[..MLKEM768_PUBLIC_KEY_LENGTH])
                    .and_then(|key| key.encapsulate().map_err(Into::into))
                    .is_ok()
            }
            Self::X25519 => true,
        }
    }

    fn encapsulate(self, public: &[u8]) -> Result<(Secret, Vec<u8>)> {
        match self {
            Self::MlKem768 => {
                let key = kem::EncapsulationKey::new(&kem::ML_KEM_768, public)
                    .map_err(|_| Error::CryptoFailure)?;
                let (enc, shared) = key.encapsulate().map_err(|_| Error::CryptoFailure)?;
                Ok((
                    Zeroizing::new(shared.as_ref().to_vec()),
                    enc.as_ref().to_vec(),
                ))
            }
            Self::XWing => crate::xwing::encapsulate(public),
            Self::X25519 => {
                let ephemeral = agreement::PrivateKey::generate(&agreement::X25519)
                    .map_err(|_| Error::CryptoFailure)?;
                let enc = ephemeral
                    .compute_public_key()
                    .map_err(|_| Error::CryptoFailure)?
                    .as_ref()
                    .to_vec();
                let dh = agreement::agree(
                    &ephemeral,
                    agreement::UnparsedPublicKey::new(&agreement::X25519, public),
                    Error::CryptoFailure,
                    |dh| Ok(Zeroizing::new(dh.to_vec())),
                )?;
                let shared = Self::dhkem_shared_secret(&dh, &enc, public)?;
                Ok((shared, enc))
            }
        }
    }

    fn decapsulate(self, enc: &[u8], private: &[u8]) -> Result<Secret> {
        match self {
            Self::MlKem768 => {
                let (key, _) =
                    crate::mlkem::from_seed(private).map_err(|_| Error::DecryptionFailed)?;
                let shared = key
                    .decapsulate(enc.into())
                    .map_err(|_| Error::DecryptionFailed)?;
                Ok(Zeroizing::new(shared.as_ref().to_vec()))
            }
            Self::XWing => crate::xwing::decapsulate(enc, private),
            Self::X25519 => {
                let key = agreement::PrivateKey::from_private_key(&agreement::X25519, private)
                    .map_err(|_| Error::DecryptionFailed)?;
                let public = key
                    .compute_public_key()
                    .map_err(|_| Error::DecryptionFailed)?
                    .as_ref()
                    .to_vec();
                let dh = agreement::agree(
                    &key,
                    agreement::UnparsedPublicKey::new(&agreement::X25519, enc),
                    Error::DecryptionFailed,
                    |dh| Ok(Zeroizing::new(dh.to_vec())),
                )?;
                Self::dhkem_shared_secret(&dh, enc, &public)
            }
        }
    }

    /// RFC 9180 §4.1's ExtractAndExpand for DHKEM(X25519, HKDF-SHA256).
    fn dhkem_shared_secret(dh: &[u8], enc: &[u8], public: &[u8]) -> Result<Secret> {
        let suite_id = [b"KEM".as_slice(), &DHKEM_X25519.to_be_bytes()].concat();
        let prk = Zeroizing::new(labeled_extract(Kdf::Sha256, &suite_id, &[], "eae_prk", dh));
        labeled_expand(
            Kdf::Sha256,
            &suite_id,
            &prk,
            "shared_secret",
            &[enc, public].concat(),
            32,
        )
        .map(Zeroizing::new)
    }
}

impl Hpke {
    fn suite_id(self) -> Vec<u8> {
        [
            b"HPKE".as_slice(),
            &self.kem.id().to_be_bytes(),
            &self.kdf.id().to_be_bytes(),
            &self.aead.id().to_be_bytes(),
        ]
        .concat()
    }

    /// RFC 9180 §5.1's KeySchedule in mode_base: the key and base nonce, which
    /// is the first message's nonce.
    fn key_schedule(self, shared: &[u8], info: &[u8]) -> Result<(Secret, Vec<u8>)> {
        let suite_id = self.suite_id();
        let psk_id_hash = labeled_extract(self.kdf, &suite_id, &[], "psk_id_hash", &[]);
        let info_hash = labeled_extract(self.kdf, &suite_id, &[], "info_hash", info);
        let context = [&[0u8][..], &psk_id_hash, &info_hash].concat();
        let secret = Zeroizing::new(labeled_extract(self.kdf, &suite_id, shared, "secret", &[]));
        let key = Zeroizing::new(labeled_expand(
            self.kdf,
            &suite_id,
            &secret,
            "key",
            &context,
            self.aead.key_length(),
        )?);
        let nonce = labeled_expand(
            self.kdf,
            &suite_id,
            &secret,
            "base_nonce",
            &context,
            AEAD_NONCE_LENGTH,
        )?;
        Ok((key, nonce))
    }

    /// Single-shot seal with an empty AAD: the encapsulation and ciphertext.
    pub(crate) fn seal(
        self,
        public: &[u8],
        info: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let (shared, enc) = self.kem.encapsulate(public)?;
        let (key, nonce) = self.key_schedule(&shared, info)?;
        Ok((enc, self.aead.seal(&key, &nonce, plaintext)?))
    }

    pub(crate) fn open(
        self,
        enc: &[u8],
        private: &[u8],
        info: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let shared = self.kem.decapsulate(enc, private)?;
        let (key, nonce) = self
            .key_schedule(&shared, info)
            .map_err(|_| Error::DecryptionFailed)?;
        self.aead.open(&key, &nonce, ciphertext)
    }
}
