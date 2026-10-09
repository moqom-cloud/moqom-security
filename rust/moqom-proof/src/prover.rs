// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::rand::{SecureRandom as _, SystemRandom};
use aws_lc_rs::signature::{KeyPair as _, ML_DSA_87_SIGNING, PqdsaKeyPair};

use crate::jwk::ML_DSA_87_PUBLIC_KEY_BYTES;
use crate::{Algorithm, Error, Jwk, b64, sha256_b64};

/// The JWS `typ` of a proof, so that a JWS made for anything else, including a
/// token from the same deployment, is not one.
pub const PROOF_TYPE: &str = "MOQT-POP";

/// A device key, and the proofs it signs.
pub struct Prover {
    pair: PqdsaKeyPair,
    jwk: Jwk,
    canonical: String,
    thumbprint: String,
}

impl Prover {
    fn new(pair: PqdsaKeyPair) -> Result<Self, Error> {
        let public = pair.public_key().as_ref();
        if public.len() != ML_DSA_87_PUBLIC_KEY_BYTES {
            return Err(Error::Unsupported);
        }
        let jwk = Jwk::ml_dsa_87(public);
        let canonical = jwk.canonical()?;
        Ok(Self {
            thumbprint: sha256_b64(canonical.as_bytes()),
            canonical,
            jwk,
            pair,
        })
    }

    /// A new software key for `algorithm`.
    ///
    /// # Errors
    /// [`Error::Signing`] if key generation fails.
    pub fn generate(algorithm: Algorithm) -> Result<Self, Error> {
        match algorithm {
            Algorithm::MlDsa87 => {
                Self::new(PqdsaKeyPair::generate(&ML_DSA_87_SIGNING).map_err(|_| Error::Signing)?)
            }
        }
    }

    /// An ML-DSA-87 key from its 32-byte FIPS 204 seed.
    ///
    /// # Errors
    /// [`Error::Malformed`] if `seed` is not 32 bytes.
    pub fn ml_dsa_87_from_seed(seed: &[u8]) -> Result<Self, Error> {
        Self::new(
            PqdsaKeyPair::from_seed(&ML_DSA_87_SIGNING, seed)
                .map_err(|_| Error::Malformed("not a 32-byte ML-DSA-87 seed"))?,
        )
    }

    /// An ML-DSA-87 key from PKCS#8, seed or expanded form.
    ///
    /// # Errors
    /// [`Error::Malformed`] if it is not one.
    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self, Error> {
        Self::new(
            PqdsaKeyPair::from_pkcs8(&ML_DSA_87_SIGNING, pkcs8)
                .map_err(|_| Error::Malformed("not a PKCS#8 ML-DSA-87 private key"))?,
        )
    }

    /// The private key as PKCS#8 v1, to store it: the seed.
    ///
    /// # Errors
    /// [`Error::Signing`] if the key cannot be serialised.
    pub fn to_pkcs8(&self) -> Result<Vec<u8>, Error> {
        let document = self.pair.to_pkcs8v1().map_err(|_| Error::Signing)?;
        Ok(document.as_ref().to_vec())
    }

    /// The algorithm this key signs with.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        Algorithm::MlDsa87
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

    /// The raw public key, 2,592 bytes.
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        self.pair.public_key().as_ref()
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
        let mut signature = vec![0; ML_DSA_87_SIGNING.signature_len()];
        let written = self
            .pair
            .sign(message, &mut signature)
            .map_err(|_| Error::Signing)?;
        signature.truncate(written);
        Ok(signature)
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
