// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

use serde::{Deserialize, Serialize};

use crate::json::present;
use crate::{Error, b64, sha256_b64, unb64};

pub(crate) const ML_DSA_87_PUBLIC_KEY_BYTES: usize = 2592;

/// Members that carry a private key: `d` (EC, OKP, RSA), RSA's other primes,
/// `oct`'s `k`, and AKP's `priv` and `seed`. A proof carrying one has leaked
/// its device key and is refused.
pub(crate) const PRIVATE_MEMBERS: [&str; 10] =
    ["d", "p", "q", "dp", "dq", "qi", "oth", "k", "priv", "seed"];

/// A proof's JOSE `alg`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Algorithm {
    /// ML-DSA-87 (FIPS 204), signing the message directly with an empty
    /// context, as `draft-ietf-cose-dilithium` specifies for JOSE. The only
    /// algorithm, so every proof is post-quantum: ES256, ML-DSA-65 and every
    /// other algorithm are refused as [`Error::Unsupported`].
    MlDsa87,
}

impl Algorithm {
    /// Every algorithm a [`crate::Checker`] accepts by default.
    pub const ALL: [Self; 1] = [Self::MlDsa87];

    /// The JOSE name.
    #[must_use]
    pub const fn jose(self) -> &'static str {
        match self {
            Self::MlDsa87 => "ML-DSA-87",
        }
    }

    /// The algorithm a JOSE name means, if it is one of these.
    #[must_use]
    pub fn from_jose(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|alg| alg.jose() == name)
    }
}

/// A device's public key as a JSON Web Key: `kty` `AKP` with `alg`
/// `ML-DSA-87` and `pub`.
///
/// Only the members a thumbprint is computed over are modelled.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwk {
    /// Key type: `AKP`.
    #[serde(default)]
    pub kty: String,
    /// `ML-DSA-87`.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub alg: Option<String>,
    /// The raw ML-DSA-87 public key, base64url.
    #[serde(
        default,
        rename = "pub",
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub public: Option<String>,
}

impl Jwk {
    /// An `AKP` ML-DSA-87 key from its raw public key.
    #[must_use]
    pub fn ml_dsa_87(public: &[u8]) -> Self {
        Self {
            kty: "AKP".into(),
            alg: Some(Algorithm::MlDsa87.jose().into()),
            public: Some(b64(public)),
        }
    }

    /// The proof algorithm this key signs with.
    ///
    /// # Errors
    /// [`Error::Unsupported`] for any other kind of key.
    pub fn algorithm(&self) -> Result<Algorithm, Error> {
        match (self.kty.as_str(), self.alg.as_deref()) {
            ("AKP", Some("ML-DSA-87")) => Ok(Algorithm::MlDsa87),
            _ => Err(Error::Unsupported),
        }
    }

    /// The raw ML-DSA-87 public key, checked for length.
    pub(crate) fn public_key(&self) -> Result<Vec<u8>, Error> {
        self.algorithm()?;
        exact(
            self.public.as_deref(),
            ML_DSA_87_PUBLIC_KEY_BYTES,
            "pub is not a base64url ML-DSA-87 key",
        )
    }

    /// The required members in lexicographic order with no whitespace, rebuilt
    /// from the decoded key so a key has one form however it was spelled.
    ///
    /// # Errors
    /// [`Error::Unsupported`] or [`Error::Malformed`].
    pub fn canonical(&self) -> Result<String, Error> {
        Ok(format!(
            r#"{{"alg":"ML-DSA-87","kty":"AKP","pub":"{}"}}"#,
            b64(&self.public_key()?)
        ))
    }

    /// The JWK thumbprint, base64url SHA-256 of [`Self::canonical`], the form
    /// `draft-ietf-cose-dilithium` gives `AKP` keys, as RFC 7638 computes it.
    ///
    /// # Errors
    /// [`Error::Unsupported`] or [`Error::Malformed`].
    pub fn thumbprint(&self) -> Result<String, Error> {
        Ok(sha256_b64(self.canonical()?.as_bytes()))
    }
}

fn exact(value: Option<&str>, size: usize, why: &'static str) -> Result<Vec<u8>, Error> {
    value
        .and_then(unb64)
        .filter(|bytes| bytes.len() == size)
        .ok_or(Error::Malformed(why))
}
