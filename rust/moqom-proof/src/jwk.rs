// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

use serde::{Deserialize, Serialize};

use crate::{Error, b64, sha256_b64, unb64};

pub(crate) const ML_DSA_65_PUBLIC_KEY_BYTES: usize = 1952;
pub(crate) const P256_COORDINATE_BYTES: usize = 32;

/// Members that carry a private key: `d` (EC, OKP, RSA), RSA's other primes,
/// `oct`'s `k`, and AKP's `priv` and `seed`. A proof carrying one has leaked
/// its device key and is refused.
pub(crate) const PRIVATE_MEMBERS: [&str; 10] =
    ["d", "p", "q", "dp", "dq", "qi", "oth", "k", "priv", "seed"];

/// A proof's JOSE `alg`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Algorithm {
    /// ML-DSA-65 (FIPS 204), signing the message directly with an empty
    /// context, as `draft-ietf-cose-dilithium` specifies for JOSE.
    MlDsa65,
    /// ECDSA on P-256 with SHA-256, the signature as fixed-width `r || s`.
    Es256,
}

impl Algorithm {
    /// Every algorithm a [`crate::Checker`] accepts by default, preferred first.
    pub const ALL: [Self; 2] = [Self::MlDsa65, Self::Es256];

    /// The JOSE name.
    #[must_use]
    pub const fn jose(self) -> &'static str {
        match self {
            Self::MlDsa65 => "ML-DSA-65",
            Self::Es256 => "ES256",
        }
    }

    /// The algorithm a JOSE name means, if it is one of these.
    #[must_use]
    pub fn from_jose(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|alg| alg.jose() == name)
    }
}

/// A device's public key as a JSON Web Key: `kty` `AKP` with `alg` and `pub`
/// for ML-DSA-65, `kty` `EC` with `crv`, `x` and `y` for P-256.
///
/// Only the members a thumbprint is computed over are modelled.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwk {
    /// Key type: `AKP` or `EC`.
    #[serde(default)]
    pub kty: String,
    /// `ML-DSA-65`, for an `AKP` key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    /// The raw ML-DSA public key, base64url, for an `AKP` key.
    #[serde(default, rename = "pub", skip_serializing_if = "Option::is_none")]
    pub public: Option<String>,
    /// `P-256`, for an `EC` key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    /// The x coordinate, base64url, for an `EC` key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    /// The y coordinate, base64url, for an `EC` key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
}

/// A key decoded and checked for shape, ready to verify with.
pub(crate) enum PublicKey {
    MlDsa65(Vec<u8>),
    /// The uncompressed point `0x04 || x || y`.
    Es256(Vec<u8>),
}

impl Jwk {
    /// An `AKP` ML-DSA-65 key from its raw public key.
    #[must_use]
    pub fn ml_dsa_65(public: &[u8]) -> Self {
        Self {
            kty: "AKP".into(),
            alg: Some(Algorithm::MlDsa65.jose().into()),
            public: Some(b64(public)),
            ..Self::default()
        }
    }

    /// An `EC` P-256 key from its two coordinates.
    #[must_use]
    pub fn p256(x: &[u8], y: &[u8]) -> Self {
        Self {
            kty: "EC".into(),
            crv: Some("P-256".into()),
            x: Some(b64(x)),
            y: Some(b64(y)),
            ..Self::default()
        }
    }

    /// The proof algorithm this key signs with.
    ///
    /// # Errors
    /// [`Error::Unsupported`] for any other kind of key.
    pub fn algorithm(&self) -> Result<Algorithm, Error> {
        match (self.kty.as_str(), self.alg.as_deref(), self.crv.as_deref()) {
            ("AKP", Some("ML-DSA-65"), _) => Ok(Algorithm::MlDsa65),
            ("EC", _, Some("P-256")) => Ok(Algorithm::Es256),
            _ => Err(Error::Unsupported),
        }
    }

    pub(crate) fn public_key(&self) -> Result<PublicKey, Error> {
        match self.algorithm()? {
            Algorithm::MlDsa65 => Ok(PublicKey::MlDsa65(exact(
                self.public.as_deref(),
                ML_DSA_65_PUBLIC_KEY_BYTES,
                "pub is not a base64url ML-DSA-65 key",
            )?)),
            Algorithm::Es256 => {
                let x = exact(
                    self.x.as_deref(),
                    P256_COORDINATE_BYTES,
                    "x is not a base64url 32-byte coordinate",
                )?;
                let y = exact(
                    self.y.as_deref(),
                    P256_COORDINATE_BYTES,
                    "y is not a base64url 32-byte coordinate",
                )?;
                let mut point = Vec::with_capacity(1 + 2 * P256_COORDINATE_BYTES);
                point.push(0x04);
                point.extend_from_slice(&x);
                point.extend_from_slice(&y);
                Ok(PublicKey::Es256(point))
            }
        }
    }

    /// The required members in lexicographic order with no whitespace, rebuilt
    /// from the decoded key so a key has one form however it was spelled.
    ///
    /// # Errors
    /// [`Error::Unsupported`] or [`Error::Malformed`].
    pub fn canonical(&self) -> Result<String, Error> {
        Ok(match self.public_key()? {
            PublicKey::MlDsa65(raw) => {
                format!(r#"{{"alg":"ML-DSA-65","kty":"AKP","pub":"{}"}}"#, b64(&raw))
            }
            PublicKey::Es256(point) => format!(
                r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
                b64(&point[1..=P256_COORDINATE_BYTES]),
                b64(&point[1 + P256_COORDINATE_BYTES..])
            ),
        })
    }

    /// The JWK thumbprint, base64url SHA-256 of [`Self::canonical`]: RFC 7638
    /// for `EC`, `draft-ietf-cose-dilithium` for `AKP`.
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
