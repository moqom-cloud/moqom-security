// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

use std::io;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use crate::{Error, MAX_LIFETIME, TOKEN_TYPE};

/// What a token asserts, in the order and spelling it has on the wire.
///
/// Unknown top-level claims are ignored, so an issuer can add one without
/// upgrading every verifier first; the grant is the exception, see [`Grant`].
/// A `null` member is refused rather than read as absent.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claims {
    /// The deployment that issued the token.
    #[serde(default)]
    pub iss: String,
    /// The holder's username.
    #[serde(default)]
    pub sub: String,
    /// The tenant: the customer the token is for, carried as the audience.
    #[serde(default, rename = "aud")]
    pub tenant: String,
    /// The token's identifier.
    #[serde(default)]
    pub jti: String,
    /// When it was minted, in Unix seconds; 0 when absent.
    #[serde(default)]
    pub iat: i64,
    /// When it stops being valid, in Unix seconds.
    #[serde(default)]
    pub exp: i64,
    /// What the token is bound to.
    #[serde(default, deserialize_with = "crate::verify::object")]
    pub cnf: Confirmation,
    /// What the holder may do in MoQ.
    #[serde(default, rename = "moqt", deserialize_with = "crate::verify::object")]
    pub grant: Grant,
    /// The username whose following brought the holder in. Provenance, not
    /// authorisation: it grants nothing.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub via: String,
    /// The room's end-to-end encryption policy, for the client.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub e2ee: String,
}

/// What a token is bound to.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Confirmation {
    /// The RFC 7638 SHA-256 thumbprint of the device key, base64url.
    #[serde(default)]
    pub jkt: String,
}

/// What the holder may do, the `moqt` claim.
///
/// Parsed strictly: a field this build does not know is refused, because a field
/// added later is as likely to narrow a grant as to widen one, and a verifier
/// that ignored a narrowing would enforce more than was issued.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)] // the claim's shape
pub struct Grant {
    /// The room it admits the holder to; empty names none. The library carries
    /// it without interpreting it: what a token naming no room may do is the
    /// product's rule.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub room: String,
    /// Media kinds the holder may publish, as a bitmask whose bit positions
    /// belong to the deployment's protocol.
    #[serde(default, rename = "pub")]
    pub publish: u8,
    /// Moderation capabilities, as a bitmask likewise.
    #[serde(default, rename = "cap")]
    pub capabilities: u32,
    /// The holder owns the room.
    #[serde(default, rename = "own", skip_serializing_if = "is_false")]
    pub owner: bool,
    /// The holder is backstage.
    #[serde(default, rename = "bs", skip_serializing_if = "is_false")]
    pub backstage: bool,
    /// The holder passed an age check.
    #[serde(default, rename = "age", skip_serializing_if = "is_false")]
    pub age_verified: bool,
    /// The holder is another relay's link to this one.
    #[serde(default, rename = "rly", skip_serializing_if = "is_false")]
    pub relay: bool,
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde's signature
const fn is_false(value: &bool) -> bool {
    !*value
}

/// Whether `thumbprint` is an RFC 7638 SHA-256 thumbprint: 43 characters of
/// canonical unpadded base64url, decoding to 32 bytes. A token bound to
/// anything else is bound to no key at all, since no proof of possession can
/// match it, so a signer refuses to mint one and a verifier to accept one
/// ([`Error::Thumbprint`]).
#[must_use]
pub fn valid_thumbprint(thumbprint: &str) -> bool {
    thumbprint.len() == 43
        && URL_SAFE_NO_PAD
            .decode(thumbprint)
            .is_ok_and(|decoded| decoded.len() == 32)
}

#[derive(Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct Header {
    #[serde(default)]
    pub alg: String,
    #[serde(default)]
    pub typ: String,
    #[serde(default)]
    pub kid: String,
}

/// JSON as the Go implementation writes it: no insignificant whitespace, HTML
/// characters left alone, and U+2028 and U+2029 escaped. The sign vectors pin
/// the bytes.
struct Canonical;

impl serde_json::ser::Formatter for Canonical {
    fn write_string_fragment<W: ?Sized + io::Write>(
        &mut self,
        writer: &mut W,
        fragment: &str,
    ) -> io::Result<()> {
        let mut rest = fragment;
        while let Some(at) = rest.find(['\u{2028}', '\u{2029}']) {
            writer.write_all(&rest.as_bytes()[..at])?;
            let separator = rest[at..].chars().next().unwrap_or_default();
            write!(writer, "\\u{:04x}", u32::from(separator))?;
            rest = &rest[at + separator.len_utf8()..];
        }
        writer.write_all(rest.as_bytes())
    }
}

fn segment(value: &impl Serialize) -> String {
    let mut encoded = Vec::new();
    let mut serializer = serde_json::Serializer::with_formatter(&mut encoded, Canonical);
    value
        .serialize(&mut serializer)
        .expect("strings, integers and booleans always serialise");
    URL_SAFE_NO_PAD.encode(encoded)
}

impl Claims {
    /// The signing input for these claims under key `kid` with `alg`, checked
    /// as [`crate::Signer::sign`] checks it.
    pub(crate) fn signing_input(&self, alg: &str, kid: &str) -> Result<String, Error> {
        if self.sub.is_empty() || self.tenant.is_empty() || self.cnf.jkt.is_empty() {
            return Err(Error::Incomplete);
        }
        if !valid_thumbprint(&self.cnf.jkt) {
            return Err(Error::Thumbprint);
        }
        let lifetime = self.exp.saturating_sub(self.iat);
        if self.iat == 0 || lifetime <= 0 || lifetime.unsigned_abs() > MAX_LIFETIME.as_secs() {
            return Err(Error::Lifetime);
        }
        let header = Header {
            alg: alg.to_owned(),
            typ: TOKEN_TYPE.to_owned(),
            kid: kid.to_owned(),
        };
        Ok(format!("{}.{}", segment(&header), segment(self)))
    }
}
