// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

//! moqom-proof: device-bound proof of possession for MoQ sessions.
//!
//! A device holds a signing key; a join token names it by JWK thumbprint in
//! `cnf.jkt`. At connect, and again on every in-session renewal, the device
//! signs a single-use proof shaped like an RFC 9449 `DPoP` proof: a compact JWS,
//! typed `MOQT-POP`, carrying the public key and committing to the token by
//! hash (`ath`), to the peer's leaf certificate by hash (`rel`), to a time
//! (`iat`) and to a nonce (`jti`) the checker accepts once.
//!
//! Two algorithms: ML-DSA-65 (JOSE `ML-DSA-65`, JWK `kty` `AKP`), the default,
//! and `ES256` on P-256, accepted while devices holding older keys roll over.
//!
//! [`Prover`] makes proofs; [`Checker`] checks them against a caller-supplied
//! [`NonceStore`]. See `docs/moqom-proof.md` for the wire format.
//!
//! # Proving and checking
//!
//! A device proves it holds the key its token names, and a relay checks the
//! proof against its own certificate and spends the nonce.
//!
//! ```
//! use std::time::{Duration, SystemTime};
//!
//! use aws_lc_rs::digest::{SHA256, digest};
//! use moqom_proof::{Algorithm, Checker, Error, MemoryNonceStore, Prover, nonce};
//!
//! # fn main() -> Result<(), Error> {
//! // On the device.
//! let device = Prover::generate(Algorithm::MlDsa65)?;
//! let jkt = device.thumbprint().to_owned(); // the control plane puts this in cnf.jkt
//! let token = b"eyJhbGciOiJNTC1EU0EtNjUi...";
//! let relay_certificate = digest(&SHA256, b"the relay's leaf certificate, DER");
//! let now = SystemTime::now();
//! let proof = device.prove(token, relay_certificate.as_ref(), &nonce()?, now)?;
//!
//! // On the relay.
//! let checker = Checker::new(MemoryNonceStore::default());
//! let expiry = now + Duration::from_secs(15 * 60);
//! let check = || checker.check(&proof, token, Some(relay_certificate.as_ref()), &jkt, now, expiry);
//! assert_eq!(check(), Ok(()));
//! assert_eq!(check(), Err(Error::Replayed));
//! # Ok(())
//! # }
//! ```
//!
//! # Storing a device key
//!
//! [`Prover::to_pkcs8`] stores an ML-DSA-65 key as its seed, and
//! [`Prover::from_pkcs8`] loads it again with the same thumbprint.
//!
//! ```
//! use moqom_proof::{Algorithm, Error, Prover};
//!
//! # fn main() -> Result<(), Error> {
//! let device = Prover::generate(Algorithm::MlDsa65)?;
//! let stored = device.to_pkcs8()?;
//! let loaded = Prover::from_pkcs8(&stored)?;
//! assert_eq!(loaded.algorithm(), Algorithm::MlDsa65);
//! assert_eq!(loaded.thumbprint(), device.thumbprint());
//!
//! let from_seed = Prover::ml_dsa_65_from_seed(&[7; 32])?;
//! assert_eq!(from_seed.thumbprint(), "e6Z96eT_vmFBoPYfx8wJ1B6r6stkERsYhS4iadvZec4");
//! # Ok(())
//! # }
//! ```
//!
//! # Refusals
//!
//! Each refusal names the check that failed.
//!
//! ```
//! use std::time::{Duration, SystemTime};
//!
//! use aws_lc_rs::digest::{SHA256, digest};
//! use moqom_proof::{Algorithm, Checker, Error, MemoryNonceStore, Prover, nonce};
//!
//! # fn main() -> Result<(), Error> {
//! let device = Prover::generate(Algorithm::MlDsa65)?;
//! let stranger = Prover::generate(Algorithm::MlDsa65)?;
//! let token = b"eyJhbGciOiJNTC1EU0EtNjUi...";
//! let relay = digest(&SHA256, b"relay A's leaf certificate");
//! let other = digest(&SHA256, b"relay B's leaf certificate");
//! let now = SystemTime::now();
//! let expiry = now + Duration::from_secs(15 * 60);
//! let checker = Checker::new(MemoryNonceStore::default());
//! let check = |proof: &[u8]| {
//!     checker.check(proof, token, Some(relay.as_ref()), device.thumbprint(), now, expiry)
//! };
//!
//! let proof = device.prove(b"another token", relay.as_ref(), &nonce()?, now)?;
//! assert_eq!(check(&proof), Err(Error::WrongToken));
//! let proof = device.prove(token, other.as_ref(), &nonce()?, now)?;
//! assert_eq!(check(&proof), Err(Error::WrongCertificate));
//! let proof = stranger.prove(token, relay.as_ref(), &nonce()?, now)?;
//! assert_eq!(check(&proof), Err(Error::WrongKey));
//! let ten_minutes_ago = now - Duration::from_secs(10 * 60);
//! let proof = device.prove(token, relay.as_ref(), &nonce()?, ten_minutes_ago)?;
//! assert_eq!(check(&proof), Err(Error::Expired));
//! assert_eq!(Error::Expired.class(), "expired");
//! # Ok(())
//! # }
//! ```
//!
//! # ES256 during rollover
//!
//! An ES256 key from an older SDK is accepted by default and refused by a
//! checker limited to ML-DSA-65.
//!
//! ```
//! use std::time::{Duration, SystemTime};
//!
//! use aws_lc_rs::digest::{SHA256, digest};
//! use moqom_proof::{Algorithm, Checker, Error, MemoryNonceStore, Prover, nonce};
//!
//! # fn main() -> Result<(), Error> {
//! let older = Prover::generate(Algorithm::Es256)?;
//! let token = b"eyJhbGciOiJNTC1EU0EtNjUi...";
//! let relay = digest(&SHA256, b"the relay's leaf certificate, DER");
//! let now = SystemTime::now();
//! let expiry = now + Duration::from_secs(15 * 60);
//! let proof = older.prove(token, relay.as_ref(), &nonce()?, now)?;
//!
//! let both = Checker::new(MemoryNonceStore::default());
//! let strict = Checker::new(MemoryNonceStore::default()).with_algorithms(&[Algorithm::MlDsa65]);
//! let thumbprint = older.thumbprint();
//! assert_eq!(both.check(&proof, token, Some(relay.as_ref()), thumbprint, now, expiry), Ok(()));
//! assert_eq!(
//!     strict.check(&proof, token, Some(relay.as_ref()), thumbprint, now, expiry),
//!     Err(Error::Unsupported)
//! );
//! # Ok(())
//! # }
//! ```
//!
//! # Sharing a nonce store
//!
//! Checkers that share a store share what has been spent, so a proof accepted
//! on one connection is refused on every other. [`NonceStore`] is implemented
//! for `Arc<S>`.
//!
//! ```
//! use std::sync::Arc;
//! use std::time::{Duration, SystemTime};
//!
//! use aws_lc_rs::digest::{SHA256, digest};
//! use moqom_proof::{Algorithm, Checker, Error, MemoryNonceStore, Prover, nonce};
//!
//! # fn main() -> Result<(), Error> {
//! let store = Arc::new(MemoryNonceStore::default());
//! let first = Checker::new(Arc::clone(&store));
//! let second = Checker::new(Arc::clone(&store));
//!
//! let device = Prover::generate(Algorithm::MlDsa65)?;
//! let token = b"eyJhbGciOiJNTC1EU0EtNjUi...";
//! let relay = digest(&SHA256, b"the relay's leaf certificate, DER");
//! let now = SystemTime::now();
//! let expiry = now + Duration::from_secs(15 * 60);
//! let proof = device.prove(token, relay.as_ref(), &nonce()?, now)?;
//!
//! let jkt = device.thumbprint();
//! assert_eq!(first.check(&proof, token, Some(relay.as_ref()), jkt, now, expiry), Ok(()));
//! assert_eq!(
//!     second.check(&proof, token, Some(relay.as_ref()), jkt, now, expiry),
//!     Err(Error::Replayed)
//! );
//! assert_eq!(store.remembered(), 1);
//! # Ok(())
//! # }
//! ```

mod checker;
mod error;
mod jwk;
mod prover;
mod store;

pub use checker::{Checker, DEFAULT_WINDOW, MAX_PROOF_BYTES};
pub use error::Error;
pub use jwk::{Algorithm, Jwk};
pub use prover::{PROOF_TYPE, Prover, nonce};
pub use store::{DEFAULT_CAPACITY, MemoryNonceStore, NonceStore};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Strict base64url: no padding, and the unused bits of the last character
/// must be zero, so one value has one spelling.
fn unb64(value: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(value).ok()
}

fn sha256_b64(bytes: &[u8]) -> String {
    b64(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, bytes).as_ref())
}

/// Compare without leaking where two values first differ.
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    aws_lc_rs::constant_time::verify_slices_are_equal(left, right).is_ok()
}
