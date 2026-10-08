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
