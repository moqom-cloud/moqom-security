// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

use crate::codec::{PROTOCOL_VERSION, Reader, Writer};
use crate::error::{Error, Result};
use crate::group::Leaf;
use crate::suite::CipherSuite;

/// What a device publishes so that it can be added: signed by its own
/// signature key, and naming its cipher suite, which is the only suite of
/// group it can join. Two KEM keys of that suite, as in the RFC: the init key
/// is used once, to receive a Welcome, and the encryption key becomes the leaf
/// key commit secrets are sealed to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyPackage {
    pub cipher_suite: CipherSuite,
    /// The MOQOM identity, username/device, as UTF-8.
    pub identity: Vec<u8>,
    pub signature_key: Vec<u8>,
    pub init_key: Vec<u8>,
    pub encryption_key: Vec<u8>,
    pub signature: Vec<u8>,
}

impl KeyPackage {
    fn to_be_signed(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.u16(PROTOCOL_VERSION);
        w.u16(self.cipher_suite.0);
        w.vector(&self.identity);
        w.vector(&self.signature_key);
        w.vector(&self.init_key);
        w.vector(&self.encryption_key);
        w.into_bytes()
    }

    /// The package as it travels.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer(self.to_be_signed());
        w.vector(&self.signature);
        w.into_bytes()
    }

    /// Reads a key package without verifying it.
    ///
    /// # Errors
    /// [`Error::Unsupported`] for a version or suite not implemented,
    /// [`Error::Malformed`] for anything else that does not decode.
    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut r = Reader(data);
        let package = Self {
            cipher_suite: r.cipher_suite()?,
            identity: r.vector()?.to_vec(),
            signature_key: r.vector()?.to_vec(),
            init_key: r.vector()?.to_vec(),
            encryption_key: r.vector()?.to_vec(),
            signature: r.vector()?.to_vec(),
        };
        r.finish()?;
        Ok(package)
    }

    /// Decodes and verifies a key package.
    ///
    /// # Errors
    /// As [`Self::decode`] and [`Self::verify`].
    pub fn parse(data: &[u8]) -> Result<Self> {
        let package = Self::decode(data)?;
        package.verify()?;
        Ok(package)
    }

    /// Checks the package's keys are the size and shape its suite says
    /// ([`Error::InvalidKeyPackage`] if not) and that it is signed by the key
    /// it carries ([`Error::BadSignature`] if not).
    ///
    /// # Errors
    /// As above.
    pub fn verify(&self) -> Result<()> {
        let s = self.cipher_suite;
        if self.signature_key.len() != s.signature_key_length() {
            return Err(Error::InvalidKeyPackage("signature key length"));
        }
        if !s.is_valid_public_key(&self.init_key) || !s.is_valid_public_key(&self.encryption_key) {
            return Err(Error::InvalidKeyPackage("KEM key"));
        }
        if self.init_key == self.encryption_key {
            return Err(Error::InvalidKeyPackage(
                "init key reused as encryption key",
            ));
        }
        if !s.verify_with_label(
            &self.signature_key,
            "KeyPackageTBS",
            &self.to_be_signed(),
            &self.signature,
        ) {
            return Err(Error::BadSignature("key package"));
        }
        Ok(())
    }

    /// KeyPackageRef, RFC 9420 §5.2.
    #[must_use]
    pub fn reference(&self) -> Vec<u8> {
        self.cipher_suite
            .ref_hash("MLS 1.0 KeyPackage Reference", &self.encode())
    }

    pub(crate) fn leaf(&self) -> Leaf {
        Leaf {
            identity: self.identity.clone(),
            signature_key: self.signature_key.clone(),
            encryption_key: self.encryption_key.clone(),
        }
    }
}

/// A key package and the private keys behind it. Fresh per session, and never
/// published.
#[derive(Clone)]
pub struct KeyPackageBundle {
    pub key_package: KeyPackage,
    pub(crate) init_private: Vec<u8>,
    pub(crate) encryption_private: Vec<u8>,
    pub(crate) signature_private: Vec<u8>,
}

impl KeyPackageBundle {
    /// A key package for `identity` in `suite`, which is the only suite of
    /// group it can be added to.
    ///
    /// # Errors
    /// [`Error::Unsupported`] for a suite this crate cannot make keys in.
    pub fn generate(identity: &str, suite: CipherSuite) -> Result<Self> {
        if !suite.is_known() {
            return Err(Error::Unsupported("cipher suite"));
        }
        let (signature_private, signature_key) = suite.generate_signature_key_pair()?;
        let (init_private, init_key) = suite.generate_key_pair()?;
        let (encryption_private, encryption_key) = suite.generate_key_pair()?;
        let mut key_package = KeyPackage {
            cipher_suite: suite,
            identity: identity.as_bytes().to_vec(),
            signature_key,
            init_key,
            encryption_key,
            signature: Vec::new(),
        };
        key_package.signature = suite.sign_with_label(
            &signature_private,
            "KeyPackageTBS",
            &key_package.to_be_signed(),
        )?;
        Ok(Self {
            key_package,
            init_private,
            encryption_private,
            signature_private,
        })
    }

    /// Reassembles a bundle from a key package and its private keys, in the
    /// forms [`CipherSuite::generate_key_pair`] and
    /// [`CipherSuite::generate_signature_key_pair`] return.
    #[must_use]
    pub fn new(
        key_package: KeyPackage,
        init_private: Vec<u8>,
        encryption_private: Vec<u8>,
        signature_private: Vec<u8>,
    ) -> Self {
        Self {
            key_package,
            init_private,
            encryption_private,
            signature_private,
        }
    }

    /// The private keys (init, encryption, signature), for a caller that
    /// persists the bundle.
    #[must_use]
    pub fn private_keys(&self) -> (&[u8], &[u8], &[u8]) {
        (
            &self.init_private,
            &self.encryption_private,
            &self.signature_private,
        )
    }
}
