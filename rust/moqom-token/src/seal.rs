// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

//! Sealed tokens: a signed token encrypted for its verifiers, so its claims
//! are opaque bytes to everyone else, the holder included.
//!
//! ```text
//! base64url( version | key ID | nonce | AES-256-GCM(segments) )
//! ```
//!
//! The version ([`SEAL_VERSION`]) and the key ID ([`SEAL_KEY_ID_BYTES`]) are
//! the additional data. The segments are the JWS's header, claims and signature
//! as raw bytes, each of the first two after a two-byte big-endian length.
//! Sealing adds confidentiality and nothing else: what a token grants is still
//! decided by its signature, checked after it is opened.

use std::collections::HashSet;

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::verify::{Object, UniqueMembers};
use crate::{Error, KeyError, MAX_TOKEN_BYTES};

/// The first byte of every sealed token.
pub const SEAL_VERSION: u8 = 0x01;

/// The length of a seal key's ID. Random rather than chosen, so the one thing a
/// sealed token shows in the clear says nothing about whose it is.
pub const SEAL_KEY_ID_BYTES: usize = 8;

const SECRET_BYTES: usize = 32;
const TAG_BYTES: usize = 16;
const PREFIX: usize = 1 + SEAL_KEY_ID_BYTES;

/// An AES-256 key tokens are sealed with, held by the issuer and by every
/// verifier, and by nobody else.
///
/// GCM with a random nonce: rotate the key well before it has sealed 2³²
/// tokens, the limit NIST SP 800-38D sets for random nonces.
#[derive(Clone)]
pub struct SealKey {
    id: [u8; SEAL_KEY_ID_BYTES],
    secret: Zeroizing<[u8; SECRET_BYTES]>,
}

impl std::fmt::Debug for SealKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealKey")
            .field("kid", &self.key_id())
            .finish_non_exhaustive()
    }
}

impl SealKey {
    /// A seal key from its eight-byte ID and 32-byte secret.
    ///
    /// # Errors
    /// [`KeyError::Invalid`] for either of the wrong length.
    pub fn new(id: &[u8], secret: &[u8]) -> Result<Self, KeyError> {
        let invalid = || KeyError::Invalid {
            kid: URL_SAFE_NO_PAD.encode(id),
            reason: "a seal key is an 8-byte ID and a 32-byte secret",
        };
        let id: [u8; SEAL_KEY_ID_BYTES] = id.try_into().map_err(|_| invalid())?;
        let secret: [u8; SECRET_BYTES] = secret.try_into().map_err(|_| invalid())?;
        Ok(Self {
            id,
            secret: Zeroizing::new(secret),
        })
    }

    /// A new random key with a random ID.
    ///
    /// # Errors
    /// [`KeyError::Random`] if the system random number generator fails.
    pub fn generate() -> Result<Self, KeyError> {
        let mut material = Zeroizing::new([0u8; SEAL_KEY_ID_BYTES + SECRET_BYTES]);
        aws_lc_rs::rand::fill(material.as_mut()).map_err(|_| KeyError::Random)?;
        Self::new(
            &material[..SEAL_KEY_ID_BYTES],
            &material[SEAL_KEY_ID_BYTES..],
        )
    }

    /// The ID, as sealed tokens carry it.
    #[must_use]
    pub const fn id(&self) -> &[u8; SEAL_KEY_ID_BYTES] {
        &self.id
    }

    /// The ID as a JWK `kid`: unpadded base64url.
    #[must_use]
    pub fn key_id(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.id)
    }

    /// The 32-byte AES key, for storing it.
    #[must_use]
    pub fn secret(&self) -> &[u8; SECRET_BYTES] {
        &self.secret
    }

    /// The key as an RFC 7517 `oct` JWK, secret included: for the issuer's
    /// secret store and a verifier's configuration, never for publishing.
    #[must_use]
    pub fn jwk(&self) -> Zeroizing<String> {
        Zeroizing::new(
            serde_json::json!({
                "kty": "oct",
                "alg": "A256GCM",
                "kid": self.key_id(),
                "k": URL_SAFE_NO_PAD.encode(*self.secret),
            })
            .to_string(),
        )
    }

    fn aead(&self) -> LessSafeKey {
        LessSafeKey::new(
            UnboundKey::new(&AES_256_GCM, self.secret.as_ref())
                .expect("a 32-byte key is an AES-256 key"),
        )
    }

    /// Encrypt a signed token for the verifiers holding this key.
    ///
    /// # Errors
    /// [`Error::Malformed`] for a token that is not a compact JWS.
    pub fn seal(&self, token: &str) -> Result<String, Error> {
        let mut nonce = [0u8; NONCE_LEN];
        aws_lc_rs::rand::fill(&mut nonce).map_err(|_| Error::Malformed("no randomness"))?;
        self.seal_with_nonce(token, nonce)
    }

    /// [`SealKey::seal`] with the nonce given, for reproducing the shared
    /// vectors. A nonce must never repeat under one key.
    #[doc(hidden)]
    pub fn seal_with_nonce(&self, token: &str, nonce: [u8; NONCE_LEN]) -> Result<String, Error> {
        let parts: Vec<&str> = token.split('.').collect();
        let [header, claims, signature] = parts[..] else {
            return Err(Error::Malformed("expected three segments"));
        };
        let mut segments = Vec::with_capacity(token.len());
        for (index, part) in [header, claims, signature].into_iter().enumerate() {
            let raw = URL_SAFE_NO_PAD
                .decode(part)
                .map_err(|_| Error::Malformed("a segment is not base64url"))?;
            if index < 2 {
                let length = u16::try_from(raw.len())
                    .map_err(|_| Error::Malformed("a segment is too long"))?;
                segments.extend_from_slice(&length.to_be_bytes());
            }
            segments.extend_from_slice(&raw);
        }
        let mut prefix = [0u8; PREFIX];
        prefix[0] = SEAL_VERSION;
        prefix[1..].copy_from_slice(&self.id);
        self.aead()
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(prefix),
                &mut segments,
            )
            .map_err(|_| Error::Malformed("cannot seal"))?;
        let mut sealed = Vec::with_capacity(PREFIX + NONCE_LEN + segments.len());
        sealed.extend_from_slice(&prefix);
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&segments);
        Ok(URL_SAFE_NO_PAD.encode(sealed))
    }

    /// Read seal keys from a JWK set, as a bare array or `{"keys": [...]}`:
    /// each `kty` `oct`, `alg` `A256GCM`, an eight-byte `kid` and a 32-byte `k`,
    /// both unpadded base64url.
    ///
    /// # Errors
    /// [`KeyError::Malformed`] for a document that is not a set,
    /// [`KeyError::Unsupported`] for another kind of key, [`KeyError::Invalid`]
    /// for the wrong lengths and [`KeyError::DuplicateKeyId`].
    pub fn parse_set(document: &str) -> Result<Vec<Self>, KeyError> {
        #[derive(Deserialize)]
        struct Jwk {
            kty: String,
            #[serde(default)]
            alg: String,
            kid: String,
            #[serde(default)]
            k: String,
        }
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Document {
            Wrapped(Object<Wrapped>),
            Bare(Vec<Object<Jwk>>),
        }
        #[derive(Deserialize)]
        struct Wrapped {
            keys: Vec<Object<Jwk>>,
        }

        serde_json::from_str::<UniqueMembers>(document)
            .map_err(|e| KeyError::Malformed(e.to_string()))?;
        let parsed: Document = serde_json::from_str(document)
            .map_err(|_| KeyError::Malformed("not a JWK set of seal keys".into()))?;
        let (Document::Wrapped(Object(Wrapped { keys: jwks })) | Document::Bare(jwks)) = parsed;
        let mut seen = HashSet::new();
        let mut keys = Vec::with_capacity(jwks.len());
        for Object(jwk) in jwks {
            if jwk.kty != "oct" || jwk.alg != "A256GCM" {
                return Err(KeyError::Unsupported { kid: jwk.kid });
            }
            let invalid = |kid: &str| KeyError::Invalid {
                kid: kid.to_owned(),
                reason: "a seal key is an 8-byte kid and a 32-byte k, in base64url",
            };
            let id = URL_SAFE_NO_PAD
                .decode(&jwk.kid)
                .map_err(|_| invalid(&jwk.kid))?;
            let secret = Zeroizing::new(
                URL_SAFE_NO_PAD
                    .decode(&jwk.k)
                    .map_err(|_| invalid(&jwk.kid))?,
            );
            let key = Self::new(&id, &secret).map_err(|_| invalid(&jwk.kid))?;
            if !seen.insert(key.id) {
                return Err(KeyError::DuplicateKeyId(jwk.kid));
            }
            keys.push(key);
        }
        Ok(keys)
    }
}

/// Whether `token` is in the sealed form rather than a JWS. It says nothing
/// about whether it opens.
#[must_use]
pub fn is_sealed(token: &[u8]) -> bool {
    !token.is_empty() && !token.contains(&b'.')
}

/// Decrypt a sealed token with whichever of `keys` sealed it, and return the
/// signed token inside, still to be verified.
///
/// # Errors
/// [`Error::Malformed`] for a token that is not the sealed form or is cut
/// short, [`Error::Unsupported`] for another version, [`Error::UnknownKey`] for
/// a key ID none of `keys` has, and [`Error::BadSignature`] for anything that
/// does not authenticate under the key it names.
pub fn open(token: &[u8], keys: &[SealKey]) -> Result<String, Error> {
    if token.is_empty() || token.len() > MAX_TOKEN_BYTES {
        return Err(Error::Malformed("token length is out of range"));
    }
    let mut sealed = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| Error::Malformed("sealed token is not base64url"))?;
    if sealed.len() < PREFIX + NONCE_LEN + TAG_BYTES {
        return Err(Error::Malformed("sealed token is too short"));
    }
    if sealed[0] != SEAL_VERSION {
        return Err(Error::Unsupported);
    }
    let Some(key) = keys.iter().find(|key| key.id[..] == sealed[1..PREFIX]) else {
        return Err(Error::UnknownKey);
    };
    let mut prefix = [0u8; PREFIX];
    prefix.copy_from_slice(&sealed[..PREFIX]);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&sealed[PREFIX..PREFIX + NONCE_LEN]);
    let segments = key
        .aead()
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(prefix),
            &mut sealed[PREFIX + NONCE_LEN..],
        )
        .map_err(|_| Error::BadSignature)?;

    let mut rest: &[u8] = segments;
    let mut parts = Vec::with_capacity(3);
    for _ in 0..2 {
        let cut = Error::Malformed("sealed segments are cut short");
        let (length, after) = rest.split_first_chunk::<2>().ok_or(cut)?;
        let length = usize::from(u16::from_be_bytes(*length));
        if after.len() < length {
            return Err(cut);
        }
        parts.push(URL_SAFE_NO_PAD.encode(&after[..length]));
        rest = &after[length..];
    }
    parts.push(URL_SAFE_NO_PAD.encode(rest));
    Ok(parts.join("."))
}
