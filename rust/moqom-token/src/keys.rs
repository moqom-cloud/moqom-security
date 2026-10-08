// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

use aws_lc_rs::signature::{
    ED25519, KeyPair, ML_DSA_65, ML_DSA_65_SIGNING, PqdsaKeyPair, UnparsedPublicKey,
    VerificationAlgorithm,
};
use std::collections::HashSet;

use aws_lc_rs::{digest, rand};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::verify::UniqueMembers;
use crate::{Claims, Error};

/// What a key verifies with.
///
/// A property of the key rather than of the token, which is the defence against
/// algorithm confusion: a verifier that dispatches on the token's own `alg` can
/// be told to use `none`, or an HMAC keyed with the public key. A token must name
/// its key's algorithm and is verified with that one and no other.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Algorithm {
    /// ML-DSA-65, which every token is signed with.
    MlDsa65,
    /// Ed25519, read only to verify tokens signed before ML-DSA.
    Ed25519,
}

impl Algorithm {
    /// The JOSE `alg` a token signed with this key carries.
    #[must_use]
    pub const fn jose(self) -> &'static str {
        match self {
            Self::MlDsa65 => "ML-DSA-65",
            Self::Ed25519 => "EdDSA",
        }
    }

    /// The length of a raw public key.
    #[must_use]
    pub const fn public_key_bytes(self) -> usize {
        match self {
            Self::MlDsa65 => 1952,
            Self::Ed25519 => 32,
        }
    }
}

/// The identifier a key gets when nobody names it: the first eight bytes of the
/// SHA-256 of the raw public key, base64url. A function of the key, so a key has
/// one name everywhere and cannot be republished under a second one.
#[must_use]
pub fn key_id(public: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(&digest::digest(&digest::SHA256, public).as_ref()[..8])
}

/// A key tokens may be verified with.
///
/// Made only by [`PublicKey::ml_dsa_65`], [`PublicKey::ed25519`] or
/// [`PublicKey::parse_set`], which refuse a key of the wrong length.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct PublicKey {
    /// The `kid` naming it.
    pub id: String,
    /// What it verifies with.
    pub algorithm: Algorithm,
    /// The raw public key.
    pub bytes: Vec<u8>,
}

impl PublicKey {
    /// An ML-DSA-65 key from its 1,952-byte encoding.
    ///
    /// # Errors
    /// [`KeyError::Invalid`] for bytes that are not 1,952 long.
    pub fn ml_dsa_65(id: impl Into<String>, bytes: Vec<u8>) -> Result<Self, KeyError> {
        Self::new(id.into(), Algorithm::MlDsa65, bytes)
    }

    /// A legacy Ed25519 key from its 32 bytes.
    ///
    /// # Errors
    /// [`KeyError::Invalid`] for bytes that are not 32 long.
    pub fn ed25519(id: impl Into<String>, bytes: Vec<u8>) -> Result<Self, KeyError> {
        Self::new(id.into(), Algorithm::Ed25519, bytes)
    }

    fn new(id: String, algorithm: Algorithm, bytes: Vec<u8>) -> Result<Self, KeyError> {
        if bytes.len() != algorithm.public_key_bytes() {
            return Err(KeyError::Invalid {
                kid: id,
                reason: match algorithm {
                    Algorithm::MlDsa65 => "an ML-DSA-65 public key is 1,952 bytes",
                    Algorithm::Ed25519 => "an Ed25519 public key is 32 bytes",
                },
            });
        }
        Ok(Self {
            id,
            algorithm,
            bytes,
        })
    }

    /// Whether `signature` is this key's over `message`, by this key's own
    /// algorithm.
    #[must_use]
    pub fn verifies(&self, message: &[u8], signature: &[u8]) -> bool {
        let algorithm: &dyn VerificationAlgorithm = match self.algorithm {
            Algorithm::MlDsa65 => &ML_DSA_65,
            Algorithm::Ed25519 => &ED25519,
        };
        UnparsedPublicKey::new(algorithm, self.bytes.as_slice())
            .verify(message, signature)
            .is_ok()
    }

    /// The key as a JWK: AKP for ML-DSA-65, per the JOSE ML-DSA draft, or OKP
    /// for Ed25519.
    #[must_use]
    pub fn jwk(&self) -> serde_json::Value {
        let encoded = URL_SAFE_NO_PAD.encode(&self.bytes);
        match self.algorithm {
            Algorithm::MlDsa65 => serde_json::json!({
                "kty": "AKP", "alg": "ML-DSA-65", "kid": self.id, "pub": encoded,
            }),
            Algorithm::Ed25519 => serde_json::json!({
                "kty": "OKP", "crv": "Ed25519", "kid": self.id, "x": encoded,
            }),
        }
    }

    /// Read a JWK set, as a bare array or wrapped in `{"keys": [...]}`.
    ///
    /// The whole document is read first ([`KeyError::Malformed`]), then each
    /// key in order: it must be AKP/ML-DSA-65 or OKP/Ed25519
    /// ([`KeyError::Unsupported`]), its public key must be canonical base64url
    /// of the right length ([`KeyError::Invalid`]), and its `kid` must not repeat
    /// one before it ([`KeyError::DuplicateKeyId`]). A key that fails is refused
    /// rather than skipped, because a set that silently lost a key verifies
    /// fewer tokens than its author thinks. Members a key does not need (`use`,
    /// `key_ops`) are ignored.
    ///
    /// # Errors
    /// The first [`KeyError`] in that order.
    pub fn parse_set(document: &str) -> Result<Vec<Self>, KeyError> {
        #[derive(Deserialize)]
        struct Jwk {
            kty: String,
            #[serde(default)]
            crv: String,
            #[serde(default)]
            alg: String,
            kid: String,
            #[serde(default)]
            x: String,
            #[serde(default, rename = "pub")]
            public: String,
        }
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Document {
            Wrapped { keys: Vec<Jwk> },
            Bare(Vec<Jwk>),
        }

        serde_json::from_str::<UniqueMembers>(document)
            .map_err(|e| KeyError::Malformed(e.to_string()))?;
        let parsed: Document = serde_json::from_str(document).map_err(|_| {
            KeyError::Malformed(
                "not an array of JWKs or {\"keys\": [...]}, or a JWK with a missing, null or \
                 mistyped member"
                    .into(),
            )
        })?;
        let (Document::Wrapped { keys: jwks } | Document::Bare(jwks)) = parsed;
        if jwks.iter().any(|jwk| jwk.kid.is_empty()) {
            return Err(KeyError::Malformed("a key has an empty kid".into()));
        }

        let mut seen = HashSet::new();
        let mut keys = Vec::with_capacity(jwks.len());
        for jwk in jwks {
            let (algorithm, field, name) = match (jwk.kty.as_str(), jwk.crv.as_str()) {
                ("AKP", _) if jwk.alg == "ML-DSA-65" => (Algorithm::MlDsa65, &jwk.public, "pub"),
                ("OKP", "Ed25519") => (Algorithm::Ed25519, &jwk.x, "x"),
                _ => return Err(KeyError::Unsupported { kid: jwk.kid }),
            };
            let Ok(bytes) = URL_SAFE_NO_PAD.decode(field.as_bytes()) else {
                return Err(KeyError::Invalid {
                    kid: jwk.kid,
                    reason: if name == "pub" {
                        "pub is not base64url"
                    } else {
                        "x is not base64url"
                    },
                });
            };
            let key = Self::new(jwk.kid, algorithm, bytes)?;
            if !seen.insert(key.id.clone()) {
                return Err(KeyError::DuplicateKeyId(key.id));
            }
            keys.push(key);
        }
        Ok(keys)
    }
}

/// Why a key, a key set or a seed was refused.
///
/// Each is one of the error classes the key set vectors name; see
/// [`KeyError::class`].
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    /// Not a JWK set: not JSON, not an array or `{"keys": [...]}`, a key that is
    /// not an object, a member that is null, of the wrong type or named twice,
    /// or a key with no `kty` or no `kid`.
    #[error("not a JWK set: {0}")]
    Malformed(String),
    /// A key that is not AKP/ML-DSA-65 or OKP/Ed25519.
    #[error("key {kid}: only AKP/ML-DSA-65 and OKP/Ed25519 are supported")]
    Unsupported {
        /// The key's `kid`.
        kid: String,
    },
    /// Key material that is not canonical base64url or not the algorithm's
    /// length, in a set or given raw.
    #[error("key {kid}: {reason}")]
    Invalid {
        /// The key's `kid`.
        kid: String,
        /// What was wrong with it.
        reason: &'static str,
    },
    /// A set naming one `kid` twice. Which of the two a token's `kid` would
    /// select is the kind of question a verifier must not answer by accident.
    #[error("key ID {0} appears twice in the set")]
    DuplicateKeyId(String),
    /// A seed the ML-DSA-65 implementation will not load.
    #[error("the seed is not an ML-DSA-65 seed")]
    Seed,
    /// The system random number generator failed.
    #[error("the system random number generator failed")]
    Random,
}

impl KeyError {
    /// The vector error class. [`KeyError::Seed`] is `key_invalid`, and
    /// [`KeyError::Random`] is `random`, which no vector names.
    #[must_use]
    pub const fn class(&self) -> &'static str {
        match self {
            Self::Malformed(_) => "set_malformed",
            Self::Unsupported { .. } => "key_unsupported",
            Self::Invalid { .. } | Self::Seed => "key_invalid",
            Self::DuplicateKeyId(_) => "duplicate_kid",
            Self::Random => "random",
        }
    }
}

/// Mints tokens with an ML-DSA-65 key.
pub struct Signer {
    pair: PqdsaKeyPair,
    seed: Zeroizing<[u8; 32]>,
    id: String,
}

impl std::fmt::Debug for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signer")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl Signer {
    /// Load an ML-DSA-65 key from its 32-byte FIPS 204 seed, named by
    /// [`key_id`] of its public half.
    ///
    /// # Errors
    /// [`KeyError::Seed`] for a seed the ML-DSA-65 implementation will not load.
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self, KeyError> {
        let pair = PqdsaKeyPair::from_seed(&ML_DSA_65_SIGNING, seed).map_err(|_| KeyError::Seed)?;
        let id = key_id(pair.public_key().as_ref());
        Ok(Self {
            pair,
            seed: Zeroizing::new(*seed),
            id,
        })
    }

    /// A new ML-DSA-65 key from a random seed, named by [`key_id`] of its public
    /// half. Store [`Signer::seed`] to load the same key again.
    ///
    /// # Errors
    /// [`KeyError::Random`] if the system random number generator failed.
    pub fn generate() -> Result<Self, KeyError> {
        let mut seed = Zeroizing::new([0u8; 32]);
        rand::fill(seed.as_mut()).map_err(|_| KeyError::Random)?;
        Self::from_seed(&seed)
    }

    /// The same key under another `kid`, for a deployment that names its keys
    /// itself.
    #[must_use]
    pub fn with_id(self, id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            ..self
        }
    }

    /// The 32-byte FIPS 204 seed, for storing the key.
    #[must_use]
    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    /// The `kid` tokens from this signer carry.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The half a verifier needs.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            id: self.id.clone(),
            algorithm: Algorithm::MlDsa65,
            bytes: self.pair.public_key().as_ref().to_vec(),
        }
    }

    /// Mint a token carrying `claims`, exactly as given.
    ///
    /// # Errors
    /// Refused rather than repaired: [`Error::Incomplete`] for claims with no
    /// subject, tenant or thumbprint, [`Error::Thumbprint`] for a thumbprint
    /// that is not RFC 7638 SHA-256, and [`Error::Lifetime`] for `iat` and `exp`
    /// unset, out of order, or more than [`crate::MAX_LIFETIME`] apart.
    pub fn sign(&self, claims: &Claims) -> Result<String, Error> {
        let input = claims.signing_input(Algorithm::MlDsa65.jose(), &self.id)?;
        let signature = self.sign_message(input.as_bytes());
        Ok(format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature)))
    }

    /// Sign `message` with the token key, for a protocol that shares it.
    ///
    /// The caller owns the domain separation: `message` must never be a valid
    /// JWS signing input, or the signature could be spliced into a token.
    /// Starting it with a fixed context string that is not base64url is enough.
    #[must_use]
    pub fn sign_message(&self, message: &[u8]) -> Vec<u8> {
        let mut signature = vec![0u8; ML_DSA_65_SIGNING.signature_len()];
        let written = self
            .pair
            .sign(message, &mut signature)
            .expect("ML-DSA-65 signs any message into a buffer of its signature length");
        signature.truncate(written);
        signature
    }
}
