// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED, ML_DSA_65, UnparsedPublicKey};
use serde::Deserialize;

use crate::jwk::PublicKey;
use crate::{
    Algorithm, Error, Jwk, MemoryNonceStore, NonceStore, PROOF_TYPE, b64, constant_time_eq,
    sha256_b64, unb64,
};

/// A proof may not be larger than this, checked before any parsing. An
/// ML-DSA-65 proof, key included, is about 8 KB.
pub const MAX_PROOF_BYTES: usize = 16 * 1024;

/// How far a proof's `iat` may be from the checker's clock, either way.
pub const DEFAULT_WINDOW: Duration = Duration::from_secs(300);

/// Checks proofs and spends their nonces.
#[derive(Debug)]
pub struct Checker<S = MemoryNonceStore> {
    store: S,
    algorithms: Vec<Algorithm>,
    window: Duration,
}

#[derive(Deserialize)]
struct Header {
    #[serde(default)]
    alg: String,
    #[serde(default)]
    typ: String,
    jwk: Option<Jwk>,
}

#[derive(Deserialize)]
struct Claims {
    #[serde(default)]
    ath: String,
    iat: Option<i64>,
    #[serde(default)]
    jti: String,
    #[serde(default)]
    rel: String,
}

impl<S: NonceStore> Checker<S> {
    /// A checker accepting every [`Algorithm`] within [`DEFAULT_WINDOW`],
    /// spending nonces in `store`.
    #[must_use]
    pub fn new(store: S) -> Self {
        Self {
            store,
            algorithms: Algorithm::ALL.to_vec(),
            window: DEFAULT_WINDOW,
        }
    }

    /// Accept only `algorithms`.
    #[must_use]
    pub fn with_algorithms(mut self, algorithms: &[Algorithm]) -> Self {
        self.algorithms = algorithms.to_vec();
        self
    }

    /// Allow `iat` to be up to `window` from now, either way.
    #[must_use]
    pub const fn with_window(mut self, window: Duration) -> Self {
        self.window = window;
        self
    }

    /// The nonce store.
    #[must_use]
    pub const fn store(&self) -> &S {
        &self.store
    }

    /// Check that `proof` was signed by the key whose thumbprint is
    /// `thumbprint` (the token's `cnf.jkt`), over `token`, for the certificate
    /// whose SHA-256 is `certificate_hash`, at a time within the window of
    /// `now`, and spend its nonce until `until` (normally the token's expiry).
    ///
    /// `certificate_hash` is `None` only where the checker has no certificate
    /// of its own, an in-process harness; the binding is then not checked.
    ///
    /// The signature is verified before any claim is read, and the nonce is
    /// spent only once every other check has passed, so a corrupted proof
    /// cannot burn a genuine one's nonce.
    ///
    /// # Errors
    /// The [`Error`] naming the first check that failed.
    pub fn check(
        &self,
        proof: &[u8],
        token: &[u8],
        certificate_hash: Option<&[u8]>,
        thumbprint: &str,
        now: SystemTime,
        until: SystemTime,
    ) -> Result<(), Error> {
        if proof.is_empty() || proof.len() > MAX_PROOF_BYTES {
            return Err(Error::Malformed("proof length is out of range"));
        }
        let (header, claims, signed, signature) = split(proof)?;

        let header: Header = decode(header).ok_or(Error::Malformed("header is not JSON"))?;
        let alg = Algorithm::from_jose(&header.alg)
            .filter(|alg| self.algorithms.contains(alg))
            .ok_or(Error::Unsupported)?;
        if header.typ != PROOF_TYPE {
            return Err(Error::Unsupported);
        }
        let jwk = header
            .jwk
            .ok_or(Error::Malformed("header carries no key"))?;
        if jwk.algorithm()? != alg {
            return Err(Error::Unsupported);
        }
        let key = match jwk.public_key()? {
            PublicKey::MlDsa65(raw) => UnparsedPublicKey::new(&ML_DSA_65, raw).parse(),
            PublicKey::Es256(point) => UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, point).parse(),
        }
        .map_err(|_| Error::Malformed("the key is not a valid public key"))?;
        key.verify_sig(signed, &signature)
            .map_err(|_| Error::BadSignature)?;

        // Without this, anybody could sign with a key of their own beside a
        // stolen token.
        if !constant_time_eq(jwk.thumbprint()?.as_bytes(), thumbprint.as_bytes()) {
            return Err(Error::WrongKey);
        }

        let claims: Claims = decode(claims).ok_or(Error::Malformed("claims are not JSON"))?;
        if !constant_time_eq(claims.ath.as_bytes(), sha256_b64(token).as_bytes()) {
            return Err(Error::WrongToken);
        }
        if let Some(certificate) = certificate_hash
            && !constant_time_eq(claims.rel.as_bytes(), b64(certificate).as_bytes())
        {
            return Err(Error::WrongCertificate);
        }
        let iat = claims.iat.ok_or(Error::Malformed("no iat"))?;
        let issued = if iat >= 0 {
            UNIX_EPOCH + Duration::from_secs(iat.unsigned_abs())
        } else {
            UNIX_EPOCH - Duration::from_secs(iat.unsigned_abs())
        };
        if now.checked_sub(self.window).is_some_and(|earliest| issued < earliest) {
            return Err(Error::Expired);
        }
        if now.checked_add(self.window).is_some_and(|latest| issued > latest) {
            return Err(Error::NotYetValid);
        }
        if claims.jti.is_empty() {
            return Err(Error::Malformed("no jti to spend"));
        }
        self.store.spend(&claims.jti, until, now)
    }
}

/// A compact JWS's segments, with the signed bytes taken verbatim from the
/// input: the signature is over bytes, and a round trip need not keep them.
fn split(jws: &[u8]) -> Result<(&[u8], &[u8], &[u8], Vec<u8>), Error> {
    let mut segments = jws.split(|&byte| byte == b'.');
    let (Some(header), Some(claims), Some(signature), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return Err(Error::Malformed("expected three segments"));
    };
    let signature = std::str::from_utf8(signature)
        .ok()
        .and_then(unb64)
        .ok_or(Error::Malformed("signature is not base64url"))?;
    Ok((
        header,
        claims,
        &jws[..header.len() + 1 + claims.len()],
        signature,
    ))
}

fn decode<T: for<'de> Deserialize<'de>>(segment: &[u8]) -> Option<T> {
    let raw = unb64(std::str::from_utf8(segment).ok()?)?;
    serde_json::from_slice(&raw).ok()
}
