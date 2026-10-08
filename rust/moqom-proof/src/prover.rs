// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::rand::{SecureRandom as _, SystemRandom};
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _, ML_DSA_65_SIGNING, PqdsaKeyPair,
};

use crate::jwk::{ML_DSA_65_PUBLIC_KEY_BYTES, P256_COORDINATE_BYTES};
use crate::{Algorithm, Error, Jwk, b64, sha256_b64};

/// The JWS `typ` of a proof, so that a JWS made for anything else, including a
/// token from the same deployment, is not one.
pub const PROOF_TYPE: &str = "MOQT-POP";

enum Key {
    MlDsa65(PqdsaKeyPair),
    Es256(EcdsaKeyPair),
}

/// A device key, and the proofs it signs.
pub struct Prover {
    key: Key,
    jwk: Jwk,
    canonical: String,
    thumbprint: String,
}

impl Prover {
    fn new(key: Key) -> Result<Self, Error> {
        let jwk = match &key {
            Key::MlDsa65(pair) => {
                let public = pair.public_key().as_ref();
                if public.len() != ML_DSA_65_PUBLIC_KEY_BYTES {
                    return Err(Error::Unsupported);
                }
                Jwk::ml_dsa_65(public)
            }
            Key::Es256(pair) => {
                let point = pair.public_key().as_ref();
                if point.len() != 1 + 2 * P256_COORDINATE_BYTES || point[0] != 0x04 {
                    return Err(Error::Malformed("not an uncompressed P-256 point"));
                }
                Jwk::p256(
                    &point[1..=P256_COORDINATE_BYTES],
                    &point[1 + P256_COORDINATE_BYTES..],
                )
            }
        };
        let canonical = jwk.canonical()?;
        Ok(Self {
            thumbprint: sha256_b64(canonical.as_bytes()),
            canonical,
            jwk,
            key,
        })
    }

    /// A new software key for `algorithm`.
    ///
    /// # Errors
    /// [`Error::Signing`] if key generation fails.
    pub fn generate(algorithm: Algorithm) -> Result<Self, Error> {
        Self::new(match algorithm {
            Algorithm::MlDsa65 => Key::MlDsa65(
                PqdsaKeyPair::generate(&ML_DSA_65_SIGNING).map_err(|_| Error::Signing)?,
            ),
            Algorithm::Es256 => Key::Es256(
                EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING)
                    .map_err(|_| Error::Signing)?,
            ),
        })
    }

    /// An ML-DSA-65 key from its 32-byte FIPS 204 seed.
    ///
    /// # Errors
    /// [`Error::Malformed`] if `seed` is not 32 bytes.
    pub fn ml_dsa_65_from_seed(seed: &[u8]) -> Result<Self, Error> {
        Self::new(Key::MlDsa65(
            PqdsaKeyPair::from_seed(&ML_DSA_65_SIGNING, seed)
                .map_err(|_| Error::Malformed("not a 32-byte ML-DSA-65 seed"))?,
        ))
    }

    /// A key from PKCS#8: ML-DSA-65 (seed or expanded form) or P-256.
    ///
    /// # Errors
    /// [`Error::Malformed`] if it is neither.
    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self, Error> {
        if let Ok(pair) = PqdsaKeyPair::from_pkcs8(&ML_DSA_65_SIGNING, pkcs8) {
            return Self::new(Key::MlDsa65(pair));
        }
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8)
            .map_err(|_| Error::Malformed("not a PKCS#8 ML-DSA-65 or P-256 private key"))?;
        Self::new(Key::Es256(pair))
    }

    /// The private key as PKCS#8 v1, to store it. ML-DSA-65 keys are stored as
    /// their seed.
    ///
    /// # Errors
    /// [`Error::Signing`] if the key cannot be serialised.
    pub fn to_pkcs8(&self) -> Result<Vec<u8>, Error> {
        let document = match &self.key {
            Key::MlDsa65(pair) => pair.to_pkcs8v1(),
            Key::Es256(pair) => pair.to_pkcs8v1(),
        }
        .map_err(|_| Error::Signing)?;
        Ok(document.as_ref().to_vec())
    }

    /// The algorithm this key signs with.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        match self.key {
            Key::MlDsa65(_) => Algorithm::MlDsa65,
            Key::Es256(_) => Algorithm::Es256,
        }
    }

    /// The public key, as a proof carries it and `/join` receives it.
    #[must_use]
    pub const fn jwk(&self) -> &Jwk {
        &self.jwk
    }

    /// The public key as canonical JWK JSON: the form a proof header carries.
    #[must_use]
    pub fn jwk_json(&self) -> &str {
        &self.canonical
    }

    /// The JWK thumbprint, what a token's `cnf.jkt` must equal.
    #[must_use]
    pub fn thumbprint(&self) -> &str {
        &self.thumbprint
    }

    /// The raw public key: 1,952 bytes for ML-DSA-65, the 65-byte uncompressed
    /// point for P-256.
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        match &self.key {
            Key::MlDsa65(pair) => pair.public_key().as_ref(),
            Key::Es256(pair) => pair.public_key().as_ref(),
        }
    }

    /// Sign a proof that this key holds `token`, for the peer whose leaf
    /// certificate has SHA-256 `certificate_hash`, using `nonce` as its
    /// single-use `jti` and `issued_at` as its `iat`.
    ///
    /// `nonce` must be fresh for every proof; [`nonce`] makes one. An empty
    /// `certificate_hash` binds the proof to no certificate, which a checker
    /// that knows its own refuses.
    ///
    /// # Errors
    /// [`Error::Malformed`] for an empty nonce; [`Error::Signing`] if the key
    /// refuses.
    pub fn prove(
        &self,
        token: &[u8],
        certificate_hash: &[u8],
        nonce: &str,
        issued_at: SystemTime,
    ) -> Result<Vec<u8>, Error> {
        if nonce.is_empty() {
            return Err(Error::Malformed("a proof needs a nonce"));
        }
        let iat = issued_at
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Malformed("issued before 1970"))?
            .as_secs();
        let header = format!(
            r#"{{"alg":"{}","typ":"{PROOF_TYPE}","jwk":{}}}"#,
            self.algorithm().jose(),
            self.canonical
        );
        let claims = format!(
            r#"{{"ath":"{}","iat":{iat},"jti":{},"rel":"{}"}}"#,
            sha256_b64(token),
            serde_json::to_string(nonce).map_err(|_| Error::Malformed("nonce"))?,
            b64(certificate_hash)
        );
        let signed = format!("{}.{}", b64(header.as_bytes()), b64(claims.as_bytes()));
        let signature = self.sign(signed.as_bytes())?;
        Ok(format!("{signed}.{}", b64(&signature)).into_bytes())
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        match &self.key {
            Key::MlDsa65(pair) => {
                let mut signature = vec![0; ML_DSA_65_SIGNING.signature_len()];
                let written = pair
                    .sign(message, &mut signature)
                    .map_err(|_| Error::Signing)?;
                signature.truncate(written);
                Ok(signature)
            }
            Key::Es256(pair) => pair
                .sign(&SystemRandom::new(), message)
                .map(|signature| signature.as_ref().to_vec())
                .map_err(|_| Error::Signing),
        }
    }
}

impl std::fmt::Debug for Prover {
    /// The thumbprint and nothing else.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Prover")
            .field("algorithm", &self.algorithm())
            .field("thumbprint", &self.thumbprint)
            .finish_non_exhaustive()
    }
}

/// A fresh 128-bit nonce, base64url.
///
/// # Errors
/// [`Error::Signing`] if the system random source fails.
pub fn nonce() -> Result<String, Error> {
    let mut bytes = [0u8; 16];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| Error::Signing)?;
    Ok(b64(&bytes))
}
