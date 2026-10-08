// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

/// Why a proof or a key was refused, or a proof could not be made.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Not a well-formed proof or key.
    #[error("proof is malformed: {0}")]
    Malformed(&'static str),
    /// An algorithm, type or key kind this checker does not accept.
    #[error("proof algorithm, type or key is not supported")]
    Unsupported,
    /// The signature does not verify under the key the proof carries.
    #[error("proof signature does not verify")]
    BadSignature,
    /// It verified, under a key the token was not issued to.
    #[error("proof is signed by a key the token was not issued to")]
    WrongKey,
    /// It verified, and commits to a different token.
    #[error("proof was made for a different token")]
    WrongToken,
    /// It verified, and was made for another peer certificate.
    #[error("proof was made for another peer certificate")]
    WrongCertificate,
    /// Its `iat` is further in the past than the window.
    #[error("proof was issued too long ago")]
    Expired,
    /// Its `iat` is further in the future than the window.
    #[error("proof is issued in the future")]
    NotYetValid,
    /// Its nonce has been spent.
    #[error("proof nonce has already been spent")]
    Replayed,
    /// The nonce store cannot remember another. Fails closed.
    #[error("nonce store is full")]
    Overloaded,
    /// The key or the system random source refused to sign.
    #[error("signing the proof failed")]
    Signing,
}

impl Error {
    /// The error class the shared vectors name.
    #[must_use]
    pub const fn class(self) -> &'static str {
        match self {
            Self::Malformed(_) => "malformed",
            Self::Unsupported => "unsupported",
            Self::BadSignature => "bad_signature",
            Self::WrongKey => "wrong_key",
            Self::WrongToken => "wrong_token",
            Self::WrongCertificate => "wrong_certificate",
            Self::Expired => "expired",
            Self::NotYetValid => "not_yet_valid",
            Self::Replayed => "replayed",
            Self::Overloaded => "overloaded",
            Self::Signing => "signing",
        }
    }
}
