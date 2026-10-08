// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

/// Why an MLS operation failed. Each variant is one of the failure classes
/// the shared vectors name; see [`Error::class`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("malformed: {0}")]
    Malformed(&'static str),
    #[error("unsupported: {0}")]
    Unsupported(&'static str),
    #[error("invalid key package: {0}")]
    InvalidKeyPackage(&'static str),
    #[error("bad signature: {0}")]
    BadSignature(&'static str),
    #[error("confirmation mismatch")]
    ConfirmationMismatch,
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("wrong epoch: expected {expected}, got {got}")]
    WrongEpoch { expected: u64, got: u64 },
    #[error("wrong group")]
    WrongGroup,
    #[error("invalid proposal: {0}")]
    InvalidProposal(&'static str),
    #[error("unknown sender: leaf {0}")]
    UnknownSender(u32),
    #[error("not addressed to this member")]
    NotAddressed,
    #[error("cipher suite mismatch: group {group:#06x}, key package {key_package:#06x}")]
    CipherSuiteMismatch { group: u16, key_package: u16 },
    #[error("crypto failure")]
    CryptoFailure,
}

impl Error {
    /// The failure class as the shared vectors write it.
    #[must_use]
    pub fn class(&self) -> &'static str {
        match self {
            Self::Malformed(_) => "malformed",
            Self::Unsupported(_) => "unsupported",
            Self::InvalidKeyPackage(_) => "invalid-key-package",
            Self::BadSignature(_) => "bad-signature",
            Self::ConfirmationMismatch => "confirmation-mismatch",
            Self::DecryptionFailed => "decryption-failed",
            Self::WrongEpoch { .. } => "wrong-epoch",
            Self::WrongGroup => "wrong-group",
            Self::InvalidProposal(_) => "invalid-proposal",
            Self::UnknownSender(_) => "unknown-sender",
            Self::NotAddressed => "not-addressed",
            Self::CipherSuiteMismatch { .. } => "cipher-suite-mismatch",
            Self::CryptoFailure => "crypto-failure",
        }
    }
}

pub type Result<T> = core::result::Result<T, Error>;
