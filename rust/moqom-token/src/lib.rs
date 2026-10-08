// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

//! moqom-token: mint and verify the credential a MOQOM client joins a relay with.
//!
//! A token is a compact JWS (RFC 7515) over JSON claims, typed `MOQT`, signed
//! with ML-DSA-65 (FIPS 204, JOSE `ML-DSA-65`, JWK `kty` `AKP`). Ed25519
//! (`EdDSA`) keys verify and never sign, so tokens issued before the move to
//! ML-DSA stay good until they expire. The key a token names by `kid` decides
//! the algorithm it is verified with; the header's `alg` must agree and is never
//! trusted on its own.
//!
//! [`Signer::sign`] and [`Verifier::verify`] are the whole API. Verification
//! checks the signature before it reads a claim, and returns [`Claims`] only from
//! a token whose signature verified and whose claims passed every check.
//!
//! The same library exists in Go (`github.com/moqom-cloud/moqom-security/go/token`)
//! and Swift (`MoqomToken`), and all three pass the vectors in `vectors/token`.
//!
//! # Minting and verifying
//!
//! ```
//! use std::time::{SystemTime, UNIX_EPOCH};
//!
//! use moqom_token::{Claims, Confirmation, Grant, PublicKey, Signer, Verifier};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Generate a key once and keep its 32-byte seed in your secret store.
//! let seed = *Signer::generate()?.seed();
//!
//! // Load it under the key ID your JWK set publishes.
//! let signer = Signer::from_seed(&seed)?.with_id("2026-10");
//!
//! let now = SystemTime::now();
//! let iat = i64::try_from(now.duration_since(UNIX_EPOCH)?.as_secs())?;
//! let jws = signer.sign(&Claims {
//!     iss: "https://api.example.com".into(),
//!     sub: "ada".into(),
//!     tenant: "acme".into(),
//!     jti: "c6c1f2d0".into(),
//!     iat,
//!     exp: iat + 600,
//!     // The RFC 7638 thumbprint of the device's key, from moqom-proof.
//!     cnf: Confirmation { jkt: "MpXqvQAmv7Y3Kk9dHnJpLwRtUvXyZaBcDeFgHiJkLmM".into() },
//!     grant: Grant { room: "room-42".into(), publish: 3, owner: true, ..Grant::default() },
//!     ..Claims::default()
//! })?;
//!
//! // A relay reads the published JWK set and verifies.
//! let document = format!(r#"{{"keys":[{}]}}"#, signer.public_key().jwk());
//! let keys = PublicKey::parse_set(&document)?;
//! let verifier = Verifier::new("https://api.example.com", keys).for_tenant("acme");
//! let claims = verifier.verify(jws.as_bytes(), SystemTime::now())?;
//! assert_eq!((claims.sub.as_str(), claims.grant.room.as_str()), ("ada", "room-42"));
//! # Ok(())
//! # }
//! ```
//!
//! # Expired tokens and the wrong key
//!
//! ```
//! use std::time::{Duration, SystemTime, UNIX_EPOCH};
//!
//! use moqom_token::{Claims, Confirmation, Error, Signer, Verifier};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let signer = Signer::generate()?;
//! let now = SystemTime::now();
//! let iat = i64::try_from(now.duration_since(UNIX_EPOCH)?.as_secs())?;
//! let jws = signer.sign(&Claims {
//!     sub: "ada".into(),
//!     tenant: "acme".into(),
//!     iat,
//!     exp: iat + 600,
//!     cnf: Confirmation { jkt: "MpXqvQAmv7Y3Kk9dHnJpLwRtUvXyZaBcDeFgHiJkLmM".into() },
//!     ..Claims::default()
//! })?;
//! let verifier = Verifier::new("", [signer.public_key()]);
//!
//! // Eleven minutes on, the ten-minute token is past its expiry and the 30-second skew.
//! let later = now + Duration::from_secs(11 * 60);
//! let expired = verifier.verify(jws.as_bytes(), later).unwrap_err();
//! assert_eq!((expired, expired.class()), (Error::Expired, "expired"));
//!
//! // A verifier that does not hold the token's key ID.
//! let other = Signer::generate()?;
//! let unknown = Verifier::new("", [other.public_key()]).verify(jws.as_bytes(), now);
//! assert_eq!(unknown, Err(Error::UnknownKey));
//!
//! // Another key published under the same key ID.
//! let impostor = other.with_id(signer.id()).public_key();
//! let forged = Verifier::new("", [impostor]).verify(jws.as_bytes(), now);
//! assert_eq!(forged, Err(Error::BadSignature));
//! # Ok(())
//! # }
//! ```

mod claims;
mod keys;
mod verify;

pub use claims::{Claims, Confirmation, Grant, valid_thumbprint};
pub use keys::{Algorithm, PublicKey, Signer, key_id};
pub use verify::Verifier;

use std::time::Duration;

/// The JWS `typ` every token carries, so a JWS minted for anything else in a
/// deployment cannot be replayed at a relay.
pub const TOKEN_TYPE: &str = "MOQT";

/// The longest a token is good for, from `iat` to `exp`, enforced when signing
/// and when verifying. A caller asking for longer is refused, not clamped.
pub const MAX_LIFETIME: Duration = Duration::from_secs(15 * 60);

/// How much disagreement between the minting and verifying clocks is tolerated.
pub const CLOCK_SKEW: Duration = Duration::from_secs(30);

/// A token may not be larger than this, checked before anything is decoded. A
/// real one is about five kilobytes, nearly all of it the ML-DSA-65 signature.
pub const MAX_TOKEN_BYTES: usize = 8192;

/// Why a token was refused, to sign or to verify.
///
/// Each is one of the error classes the shared vectors name; see
/// [`Error::class`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Not a well-formed token, or claims that cannot be encoded.
    #[error("token is malformed: {0}")]
    Malformed(&'static str),
    /// Not a MOQT token, or naming an algorithm other than its key's.
    #[error("token algorithm or type is not supported")]
    Unsupported,
    /// Signed by a key the verifier does not hold.
    #[error("token was signed by an unknown key")]
    UnknownKey,
    /// The signature does not verify.
    #[error("token signature does not verify")]
    BadSignature,
    /// Past its expiry by more than the skew.
    #[error("token has expired")]
    Expired,
    /// Issued in the future by more than the skew.
    #[error("token is not valid yet")]
    NotYetValid,
    /// `iat` and `exp` unset, out of order, or further apart than [`MAX_LIFETIME`].
    #[error("token lifetime is out of range")]
    Lifetime,
    /// Issued by another deployment.
    #[error("token was issued by another deployment")]
    WrongIssuer,
    /// For a tenant the verifier is not pinned to.
    #[error("token is for another tenant")]
    WrongTenant,
    /// Does not name a subject, a tenant and a device.
    #[error("token does not name a complete identity")]
    Incomplete,
    /// `cnf.jkt` is not an RFC 7638 SHA-256 thumbprint. Signing only.
    #[error("token is not bound to an RFC 7638 SHA-256 thumbprint")]
    Thumbprint,
}

impl Error {
    /// The vector error class.
    #[must_use]
    pub const fn class(self) -> &'static str {
        match self {
            Self::Malformed(_) => "malformed",
            Self::Unsupported => "unsupported",
            Self::UnknownKey => "unknown_key",
            Self::BadSignature => "bad_signature",
            Self::Expired => "expired",
            Self::NotYetValid => "not_yet_valid",
            Self::Lifetime => "lifetime",
            Self::WrongIssuer => "wrong_issuer",
            Self::WrongTenant => "wrong_tenant",
            Self::Incomplete => "incomplete",
            Self::Thumbprint => "thumbprint",
        }
    }
}
