// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

use aws_lc_rs::signature::{self, KeyPair};

use crate::codec::{Reader, Writer};
use crate::error::{Error, Result};
use crate::hpke::{Aead, Hpke, Kdf, Kem};

/// An MLS cipher suite identifier, RFC 9420 §17.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CipherSuite(pub u16);

impl CipherSuite {
    /// MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519, RFC 9420's mandatory
    /// suite, kept for groups founded in it.
    pub const X25519: Self = Self(0x0001);
    /// MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519, draft-ietf-mls-pq-ciphersuites'
    /// first suite (HPKE KEM 0x647a, X-Wing), private-use until IANA assigns
    /// the draft's value.
    pub const XWING: Self = Self(0xF0A1);
    /// MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65, the draft's TBD10: HPKE KEM
    /// 0x0041 (pure ML-KEM-768), HKDF-SHA384, AES-256-GCM and ML-DSA-65
    /// signatures (pure, empty context). Private-use until IANA assigns it.
    pub const MLDSA: Self = Self(0xF0AA);
    /// The suite every new group is founded in.
    pub const FOUNDING: Self = Self::MLDSA;

    const ML_DSA_65_PUBLIC_KEY_LENGTH: usize = 1952;
    const ML_DSA_65_SIGNATURE_LENGTH: usize = 3309;

    /// Whether the suite is one this crate implements.
    #[must_use]
    pub fn is_known(self) -> bool {
        matches!(self, Self::X25519 | Self::XWING | Self::MLDSA)
    }

    /// The suite's registered name.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::X25519 => "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
            Self::XWING => "MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519",
            Self::MLDSA => "MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65",
            _ => "unknown",
        }
    }

    pub(crate) fn kdf(self) -> Kdf {
        if self == Self::MLDSA {
            Kdf::Sha384
        } else {
            Kdf::Sha256
        }
    }

    pub(crate) fn aead(self) -> Aead {
        if self == Self::MLDSA {
            Aead::Aes256Gcm
        } else {
            Aead::Aes128Gcm
        }
    }

    fn kem(self) -> Kem {
        match self {
            Self::X25519 => Kem::X25519,
            Self::XWING => Kem::XWing,
            _ => Kem::MlKem768,
        }
    }

    fn hpke(self) -> Result<Hpke> {
        if !self.is_known() {
            return Err(Error::Unsupported("cipher suite"));
        }
        Ok(Hpke {
            kem: self.kem(),
            kdf: self.kdf(),
            aead: self.aead(),
        })
    }

    /// KDF.Nh: 48 for SHA-384, 32 for SHA-256.
    #[must_use]
    pub fn hash_length(self) -> usize {
        self.kdf().length()
    }

    /// An init or leaf encryption key's length, HPKE's Npk.
    #[must_use]
    pub fn public_key_length(self) -> usize {
        self.kem().public_key_length()
    }

    /// HPKE's Nenc.
    #[must_use]
    pub fn encapsulation_length(self) -> usize {
        self.kem().encapsulation_length()
    }

    /// A signature public key's length: 1,952 for ML-DSA-65, 32 for Ed25519.
    #[must_use]
    pub fn signature_key_length(self) -> usize {
        if self == Self::MLDSA {
            Self::ML_DSA_65_PUBLIC_KEY_LENGTH
        } else {
            32
        }
    }

    pub(crate) fn hash(self, data: &[u8]) -> Vec<u8> {
        self.kdf().hash(data)
    }

    pub(crate) fn extract(self, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        self.kdf().extract(salt, ikm)
    }

    pub(crate) fn expand(self, secret: &[u8], info: &[u8], length: usize) -> Vec<u8> {
        self.kdf()
            .expand(secret, info, length)
            .expect("HKDF-Expand within its limits")
    }

    pub(crate) fn mac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        self.kdf().mac(key, data)
    }

    pub(crate) fn random_secret(self) -> Vec<u8> {
        random(self.hash_length())
    }

    /// ExpandWithLabel, RFC 9420 §5.1.3.
    #[must_use]
    pub fn expand_with_label(
        self,
        secret: &[u8],
        label: &str,
        context: &[u8],
        length: usize,
    ) -> Vec<u8> {
        let mut info = Writer::default();
        info.u16(length as u16);
        info.vector(format!("MLS 1.0 {label}").as_bytes());
        info.vector(context);
        self.expand(secret, &info.into_bytes(), length)
    }

    /// DeriveSecret, RFC 9420 §5.1.3.
    #[must_use]
    pub fn derive_secret(self, secret: &[u8], label: &str) -> Vec<u8> {
        self.expand_with_label(secret, label, &[], self.hash_length())
    }

    /// RefHash, RFC 9420 §5.2.
    #[must_use]
    pub fn ref_hash(self, label: &str, value: &[u8]) -> Vec<u8> {
        let mut input = Writer::default();
        input.vector(label.as_bytes());
        input.vector(value);
        self.hash(&input.into_bytes())
    }

    /// A fresh signature key: the private half as a 32-byte ML-DSA-65 seed
    /// (FIPS 204's xi) or Ed25519 seed, and the public half as it travels.
    ///
    /// # Errors
    /// [`Error::CryptoFailure`] if the key cannot be made.
    pub fn generate_signature_key_pair(self) -> Result<(Vec<u8>, Vec<u8>)> {
        let private = random(32);
        let public = self.signature_public_key(&private)?;
        Ok((private, public))
    }

    pub(crate) fn signature_public_key(self, private: &[u8]) -> Result<Vec<u8>> {
        if self == Self::MLDSA {
            let key = signature::PqdsaKeyPair::from_seed(&signature::ML_DSA_65_SIGNING, private)
                .map_err(|_| Error::CryptoFailure)?;
            Ok(key.public_key().as_ref().to_vec())
        } else {
            let key = signature::Ed25519KeyPair::from_seed_unchecked(private)
                .map_err(|_| Error::CryptoFailure)?;
            Ok(key.public_key().as_ref().to_vec())
        }
    }

    /// SignWithLabel, RFC 9420 §5.1.2, with a private key as
    /// [`Self::generate_signature_key_pair`] returns it.
    ///
    /// # Errors
    /// [`Error::CryptoFailure`] if the key is not one or signing fails.
    pub fn sign_with_label(self, private: &[u8], label: &str, content: &[u8]) -> Result<Vec<u8>> {
        let message = sign_content(label, content);
        if self == Self::MLDSA {
            let key = signature::PqdsaKeyPair::from_seed(&signature::ML_DSA_65_SIGNING, private)
                .map_err(|_| Error::CryptoFailure)?;
            let mut out = vec![0; Self::ML_DSA_65_SIGNATURE_LENGTH];
            let length = key
                .sign(&message, &mut out)
                .map_err(|_| Error::CryptoFailure)?;
            out.truncate(length);
            Ok(out)
        } else {
            let key = signature::Ed25519KeyPair::from_seed_unchecked(private)
                .map_err(|_| Error::CryptoFailure)?;
            Ok(key.sign(&message).as_ref().to_vec())
        }
    }

    /// VerifyWithLabel, RFC 9420 §5.1.2.
    #[must_use]
    pub fn verify_with_label(
        self,
        public: &[u8],
        label: &str,
        content: &[u8],
        signature: &[u8],
    ) -> bool {
        if public.len() != self.signature_key_length() {
            return false;
        }
        let message = sign_content(label, content);
        let algorithm: &'static dyn signature::VerificationAlgorithm = if self == Self::MLDSA {
            &signature::ML_DSA_65
        } else {
            &signature::ED25519
        };
        signature::UnparsedPublicKey::new(algorithm, public)
            .verify(&message, signature)
            .is_ok()
    }

    /// A fresh KEM key pair: the private half as RFC 9180's
    /// SerializePrivateKey gives it (ML-KEM-768's 64-byte seed d || z,
    /// X-Wing's 32-byte seed, or the X25519 scalar) and the public half as it
    /// travels.
    ///
    /// # Errors
    /// [`Error::Unsupported`] for a suite not implemented.
    pub fn generate_key_pair(self) -> Result<(Vec<u8>, Vec<u8>)> {
        let kem = self.hpke()?.kem;
        let private = random(kem.private_key_length());
        let public = kem.public_key(&private)?;
        Ok((private, public))
    }

    /// The KEM public key for a private key as [`Self::generate_key_pair`]
    /// returns it.
    ///
    /// # Errors
    /// [`Error::Unsupported`] for a suite not implemented,
    /// [`Error::CryptoFailure`] for a private key that is not one.
    pub fn kem_public_key(self, private: &[u8]) -> Result<Vec<u8>> {
        self.hpke()?.kem.public_key(private)
    }

    /// Whether a key is the suite's KEM's: the right length and, for
    /// ML-KEM-768 alone or as X-Wing's first half, one FIPS 203's
    /// encapsulation key check accepts.
    pub(crate) fn is_valid_public_key(self, public: &[u8]) -> bool {
        self.kem().is_valid_public_key(public)
    }

    /// EncryptWithLabel, RFC 9420 §5.1.3: HPKE base mode, empty AAD.
    ///
    /// # Errors
    /// [`Error::Malformed`] for a key of the wrong length,
    /// [`Error::Unsupported`] for a suite not implemented,
    /// [`Error::CryptoFailure`] for a key encapsulation refuses.
    pub fn encrypt_with_label(
        self,
        public: &[u8],
        label: &str,
        context: &[u8],
        plaintext: &[u8],
    ) -> Result<HpkeCiphertext> {
        let hpke = self.hpke()?;
        if public.len() != self.public_key_length() {
            return Err(Error::Malformed("public key length"));
        }
        let (kem_output, ciphertext) =
            hpke.seal(public, &encrypt_context(label, context), plaintext)?;
        Ok(HpkeCiphertext {
            kem_output,
            ciphertext,
        })
    }

    /// DecryptWithLabel, RFC 9420 §5.1.3, with a private key as
    /// [`Self::generate_key_pair`] returns it.
    ///
    /// # Errors
    /// [`Error::DecryptionFailed`] for anything that does not open.
    pub fn decrypt_with_label(
        self,
        private: &[u8],
        label: &str,
        context: &[u8],
        ciphertext: &HpkeCiphertext,
    ) -> Result<Vec<u8>> {
        let hpke = self.hpke()?;
        if ciphertext.kem_output.len() != self.encapsulation_length() {
            return Err(Error::DecryptionFailed);
        }
        hpke.open(
            &ciphertext.kem_output,
            private,
            &encrypt_context(label, context),
            &ciphertext.ciphertext,
        )
    }
}

impl core::fmt::Display for CipherSuite {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} ({:#06x})", self.name(), self.0)
    }
}

pub(crate) fn random(n: usize) -> Vec<u8> {
    let mut out = vec![0; n];
    aws_lc_rs::rand::fill(&mut out).expect("the system random source");
    out
}

fn sign_content(label: &str, content: &[u8]) -> Vec<u8> {
    let mut tbs = Writer::default();
    tbs.vector(format!("MLS 1.0 {label}").as_bytes());
    tbs.vector(content);
    tbs.into_bytes()
}

fn encrypt_context(label: &str, context: &[u8]) -> Vec<u8> {
    let mut info = Writer::default();
    info.vector(format!("MLS 1.0 {label}").as_bytes());
    info.vector(context);
    info.into_bytes()
}

/// HPKECiphertext, RFC 9420 §5.1.3.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HpkeCiphertext {
    pub kem_output: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl HpkeCiphertext {
    pub(crate) fn write(&self, w: &mut Writer) {
        w.vector(&self.kem_output);
        w.vector(&self.ciphertext);
    }

    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            kem_output: r.vector()?.to_vec(),
            ciphertext: r.vector()?.to_vec(),
        })
    }
}
