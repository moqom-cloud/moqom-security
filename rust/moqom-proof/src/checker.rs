// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::signature::{ML_DSA_87, UnparsedPublicKey};
use serde::Deserialize;

use crate::json::{object, present};
use crate::jwk::PRIVATE_MEMBERS;
use crate::{
    Algorithm, Error, Jwk, MemoryNonceStore, NonceStore, PROOF_TYPE, b64, constant_time_eq,
    sha256_b64, unb64,
};

/// A proof may not be larger than this, checked before any parsing. An
/// ML-DSA-87 proof, key included, is about 11 KB.
pub const MAX_PROOF_BYTES: usize = 16 * 1024;

/// How far a proof's `iat` may be from the checker's clock, either way, unless
/// [`Checker::with_window`] says otherwise.
pub const DEFAULT_WINDOW: Duration = Duration::from_secs(300);

/// Checks proofs and spends their nonces.
#[derive(Debug)]
pub struct Checker<S = MemoryNonceStore> {
    store: S,
    algorithms: Vec<Algorithm>,
    window: Duration,
    require_certificate: bool,
}

#[derive(Deserialize)]
struct Header {
    #[serde(default)]
    alg: String,
    #[serde(default)]
    typ: String,
    #[serde(default, deserialize_with = "present")]
    jwk: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Deserialize)]
struct Claims {
    #[serde(default)]
    ath: String,
    #[serde(default, deserialize_with = "present")]
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
            require_certificate: false,
        }
    }

    /// Accept only `algorithms`.
    ///
    /// # Errors
    /// [`Error::Configuration`] if `algorithms` is empty.
    pub fn with_algorithms(mut self, algorithms: &[Algorithm]) -> Result<Self, Error> {
        if algorithms.is_empty() {
            return Err(Error::Configuration(
                "a checker must accept at least one algorithm",
            ));
        }
        self.algorithms = algorithms.to_vec();
        Ok(self)
    }

    /// Allow `iat` to be up to `window` from now, either way.
    ///
    /// # Errors
    /// [`Error::Configuration`] if `window` is zero.
    pub fn with_window(mut self, window: Duration) -> Result<Self, Error> {
        if window.is_zero() {
            return Err(Error::Configuration("window is not positive"));
        }
        self.window = window;
        Ok(self)
    }

    /// Refuse every proof when [`Checker::check`] is given no certificate,
    /// rather than accepting only proofs that name none.
    #[must_use]
    pub const fn with_certificate_required(mut self, required: bool) -> Self {
        self.require_certificate = required;
        self
    }

    /// The nonce store.
    #[must_use]
    pub const fn store(&self) -> &S {
        &self.store
    }

    /// The algorithms this checker accepts.
    #[must_use]
    pub fn algorithms(&self) -> &[Algorithm] {
        &self.algorithms
    }

    /// How far `iat` may be from the checker's clock, either way.
    #[must_use]
    pub const fn window(&self) -> Duration {
        self.window
    }

    /// Whether every proof is refused when the checker is given no
    /// certificate.
    #[must_use]
    pub const fn certificate_required(&self) -> bool {
        self.require_certificate
    }

    /// Check that `proof` was signed by the key whose thumbprint is
    /// `thumbprint` (the token's `cnf.jkt`), over `token`, for the certificate
    /// whose SHA-256 is `certificate_hash`, at a time within the window of
    /// `now`, and spend its nonce until `until` (normally the token's expiry),
    /// or until one second past the end of the proof's window if that is later.
    ///
    /// `certificate_hash` is `None` (or empty) only where the checker has no
    /// certificate of its own, an in-process harness. The proof must then name
    /// no certificate either, since one it names cannot be checked, and a
    /// checker built [`Checker::with_certificate_required`] refuses it.
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
        // The key's members are typed here, with the rest of the header, so a
        // badly typed key is malformed whatever its alg.
        let jwk: Option<Jwk> = header
            .jwk
            .as_ref()
            .map(|members| serde_json::from_value(members.clone().into()))
            .transpose()
            .map_err(|_| Error::Malformed("header is not JSON"))?;
        let alg = Algorithm::from_jose(&header.alg)
            .filter(|alg| self.algorithms.contains(alg))
            .ok_or(Error::Unsupported)?;
        if header.typ != PROOF_TYPE {
            return Err(Error::Unsupported);
        }
        let (Some(members), Some(jwk)) = (header.jwk, jwk) else {
            return Err(Error::Malformed("header carries no key"));
        };
        if PRIVATE_MEMBERS
            .iter()
            .any(|name| members.contains_key(*name))
        {
            return Err(Error::Malformed("the key carries a private member"));
        }
        if jwk.algorithm()? != alg {
            return Err(Error::Unsupported);
        }
        let key = UnparsedPublicKey::new(&ML_DSA_87, jwk.public_key()?)
            .parse()
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
        let certificate = certificate_hash.filter(|hash| !hash.is_empty());
        if certificate.is_none() && self.require_certificate {
            return Err(Error::WrongCertificate);
        }
        let expected = certificate.map(b64).unwrap_or_default();
        if !constant_time_eq(claims.rel.as_bytes(), expected.as_bytes()) {
            return Err(Error::WrongCertificate);
        }
        let iat = claims.iat.ok_or(Error::Malformed("no iat"))?;
        let issued = if iat >= 0 {
            UNIX_EPOCH + Duration::from_secs(iat.unsigned_abs())
        } else {
            UNIX_EPOCH - Duration::from_secs(iat.unsigned_abs())
        };
        if now
            .checked_sub(self.window)
            .is_some_and(|earliest| issued < earliest)
        {
            return Err(Error::Expired);
        }
        if now
            .checked_add(self.window)
            .is_some_and(|latest| issued > latest)
        {
            return Err(Error::NotYetValid);
        }
        if claims.jti.is_empty() {
            return Err(Error::Malformed("no jti to spend"));
        }
        // The proof is accepted until issued + window, inclusive, and a store
        // keeps a nonce while its until is after now. A shorter until would
        // let the same proof in again once the store forgot it.
        let remember = issued
            .checked_add(self.window + Duration::from_secs(1))
            .map_or(until, |end| end.max(until));
        self.store.spend(&claims.jti, remember, now)
    }
}

/// The header and claims segments, the signed bytes, and the decoded signature.
type Segments<'a> = (&'a [u8], &'a [u8], &'a [u8], Vec<u8>);

/// A compact JWS's segments, with the signed bytes taken verbatim from the
/// input: the signature is over bytes, and a round trip need not keep them.
fn split(jws: &[u8]) -> Result<Segments<'_>, Error> {
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
    object(&unb64(std::str::from_utf8(segment).ok()?)?)
}
