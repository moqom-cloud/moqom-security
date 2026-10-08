// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use serde::de::{self, MapAccess, SeqAccess, Visitor};

use crate::claims::Header;
use crate::{CLOCK_SKEW, Claims, Error, MAX_LIFETIME, MAX_TOKEN_BYTES, PublicKey, TOKEN_TYPE};

/// Checks tokens against a set of keys.
///
/// A set rather than one key, because rotation needs an overlap: the new key is
/// published, signing moves to it, and the old one stays verifiable until the
/// last token it signed has expired.
#[derive(Clone, Debug, Default)]
pub struct Verifier {
    keys: HashMap<String, PublicKey>,
    issuer: String,
    tenant: String,
}

impl Verifier {
    /// Accept tokens signed by `keys` and issued by `issuer`; an empty issuer
    /// accepts any.
    #[must_use]
    pub fn new(issuer: impl Into<String>, keys: impl IntoIterator<Item = PublicKey>) -> Self {
        Self {
            keys: keys.into_iter().map(|key| (key.id.clone(), key)).collect(),
            issuer: issuer.into(),
            tenant: String::new(),
        }
    }

    /// The same, refusing every token not issued for `tenant`
    /// ([`Error::WrongTenant`]). Empty accepts any.
    #[must_use]
    pub fn for_tenant(mut self, tenant: impl Into<String>) -> Self {
        self.tenant = tenant.into();
        self
    }

    /// The pinned issuer, empty for any.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The pinned tenant, empty for any.
    #[must_use]
    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    /// The keys tokens may be signed by.
    pub fn keys(&self) -> impl Iterator<Item = &PublicKey> {
        self.keys.values()
    }

    /// Check `token` at `now` and return its claims.
    ///
    /// The signature is checked before any claim is read: acting on a claim from
    /// an unverified token, even to word an error, is how a parser becomes an
    /// attack surface. Then the claims, in this order: issuer, expiry,
    /// not-before, lifetime, completeness, tenant.
    ///
    /// # Errors
    /// The first check that failed.
    pub fn verify(&self, token: &[u8], now: SystemTime) -> Result<Claims, Error> {
        if token.is_empty() || token.len() > MAX_TOKEN_BYTES {
            return Err(Error::Malformed("token length is out of range"));
        }
        let mut segments = token.split(|&byte| byte == b'.');
        let (Some(header_segment), Some(claims_segment), Some(signature_segment), None) = (
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
        ) else {
            return Err(Error::Malformed("expected three segments"));
        };

        let header: Header = decode(header_segment)
            .map_err(|bad| Error::Malformed(bad.describe("header")))?;
        if header.typ != TOKEN_TYPE {
            return Err(Error::Unsupported);
        }
        let Some(key) = self.keys.get(&header.kid) else {
            return Err(Error::UnknownKey);
        };
        if header.alg != key.algorithm.jose() {
            return Err(Error::Unsupported);
        }

        let signature = URL_SAFE_NO_PAD
            .decode(signature_segment)
            .map_err(|_| Error::Malformed("signature is not base64url"))?;
        // The signed message is the first two segments verbatim: a round trip
        // through a parser would not reproduce them, and the signature is over
        // bytes.
        let signed = &token[..header_segment.len() + 1 + claims_segment.len()];
        if !key.verifies(signed, &signature) {
            return Err(Error::BadSignature);
        }

        let claims: Claims = decode(claims_segment)
            .map_err(|bad| Error::Malformed(bad.describe("claims")))?;
        self.check(&claims, now)?;
        Ok(claims)
    }

    fn check(&self, claims: &Claims, now: SystemTime) -> Result<(), Error> {
        if !self.issuer.is_empty() && claims.iss != self.issuer {
            return Err(Error::WrongIssuer);
        }
        if claims.exp == 0 {
            return Err(Error::Malformed("no expiry"));
        }
        let now = unix(now);
        let skew = i64::try_from(CLOCK_SKEW.as_secs()).unwrap_or(i64::MAX);
        let limit = i64::try_from(MAX_LIFETIME.as_secs()).unwrap_or(i64::MAX);
        if now.saturating_sub(skew) > claims.exp {
            return Err(Error::Expired);
        }
        if claims.iat != 0 && now.saturating_add(skew) < claims.iat {
            return Err(Error::NotYetValid);
        }
        // Without `iat` the lifetime is measured from now, with the skew
        // allowed, so leaving it out cannot buy a longer token.
        let too_long = if claims.iat == 0 {
            claims.exp.saturating_sub(now) > limit + skew
        } else {
            claims.exp.saturating_sub(claims.iat) > limit
        };
        if too_long {
            return Err(Error::Lifetime);
        }
        if claims.sub.is_empty() || claims.tenant.is_empty() || claims.cnf.jkt.is_empty() {
            return Err(Error::Incomplete);
        }
        if !self.tenant.is_empty() && claims.tenant != self.tenant {
            return Err(Error::WrongTenant);
        }
        Ok(())
    }
}

enum Undecodable {
    Base64,
    Json,
}

impl Undecodable {
    const fn describe(&self, what: &str) -> &'static str {
        match (self, what.as_bytes()) {
            (Self::Base64, b"header") => "header is not base64url",
            (Self::Json, b"header") => "header is not JSON",
            (Self::Base64, _) => "claims are not base64url",
            (Self::Json, _) => "claims are not JSON",
        }
    }
}

fn decode<T: for<'de> Deserialize<'de>>(segment: &[u8]) -> Result<T, Undecodable> {
    let decoded = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| Undecodable::Base64)?;
    // serde reads a struct from an array as readily as from an object, and
    // neither other implementation does.
    if decoded.trim_ascii_start().first() != Some(&b'{') {
        return Err(Undecodable::Json);
    }
    serde_json::from_slice::<UniqueMembers>(&decoded).map_err(|_| Undecodable::Json)?;
    serde_json::from_slice(&decoded).map_err(|_| Undecodable::Json)
}

/// JSON in which no object, at any depth, names a member twice. `serde_json`
/// keeps the last of a duplicate it does not model and other parsers the first,
/// so a token with one would mean different things to different verifiers.
/// Names are compared after unescaping, so `sub` and `s\u0075b` are the same.
struct UniqueMembers;

impl<'de> Deserialize<'de> for UniqueMembers {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(UniqueMembers)
    }
}

impl<'de> Visitor<'de> for UniqueMembers {
    type Value = Self;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("JSON with no duplicate member names")
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self, E> {
        Ok(self)
    }

    fn visit_i64<E>(self, _: i64) -> Result<Self, E> {
        Ok(self)
    }

    fn visit_u64<E>(self, _: u64) -> Result<Self, E> {
        Ok(self)
    }

    fn visit_f64<E>(self, _: f64) -> Result<Self, E> {
        Ok(self)
    }

    fn visit_str<E>(self, _: &str) -> Result<Self, E> {
        Ok(self)
    }

    fn visit_unit<E>(self) -> Result<Self, E> {
        Ok(self)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self, A::Error> {
        while seq.next_element::<Self>()?.is_some() {}
        Ok(self)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self, A::Error> {
        let mut names = HashSet::new();
        while let Some(name) = map.next_key::<String>()? {
            if !names.insert(name) {
                return Err(de::Error::custom("duplicate member"));
            }
            map.next_value::<Self>()?;
        }
        Ok(self)
    }
}

fn unix(time: SystemTime) -> i64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(after) => i64::try_from(after.as_secs()).unwrap_or(i64::MAX),
        Err(before) => -i64::try_from(before.duration().as_secs()).unwrap_or(i64::MAX),
    }
}
