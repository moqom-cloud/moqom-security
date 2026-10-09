// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

//! ML-KEM-1024 keys from their 64-byte seed (FIPS 203's d || z), which is how
//! RFC 9180 serialises the private key and how Swift and Go hold it.
//! aws-lc-rs takes only the expanded 3,168-byte key, so the seed goes in
//! through AWS-LC's PKCS#8 parser, which accepts the seed form of RFC 9935
//! and runs FIPS 203's KeyGen on it. See "Unsafe code" in docs/moqom-mls.md.

use core::ffi::c_int;
use core::ptr::NonNull;

use aws_lc_rs::kem;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::hpke::{MLKEM1024_PUBLIC_KEY_LENGTH, MLKEM1024_SEED_LENGTH};

const MLKEM1024_PRIVATE_KEY_LENGTH: usize = 3168;

/// PrivateKeyInfo { version 0, id-alg-ml-kem-1024, OCTET STRING { [0] seed } }.
const PKCS8_SEED_PREFIX: [u8; 22] = [
    0x30, 0x54, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
    0x04, 0x03, 0x04, 0x42, 0x80, 0x40,
];

/// An `EVP_PKEY` this module owns: freed once, on drop.
struct Pkey(NonNull<aws_lc_sys::EVP_PKEY>);

impl Pkey {
    /// Parses exactly one PKCS#8 PrivateKeyInfo spanning all of `der`.
    fn parse_pkcs8(der: &[u8]) -> Option<Self> {
        let mut cbs = aws_lc_sys::CBS {
            data: core::ptr::null(),
            len: 0,
        };
        // SAFETY: `cbs` borrows `der`, which outlives it; AWS-LC only reads
        // through it and returns a new key that it does not tie to `der`.
        unsafe {
            aws_lc_sys::CBS_init(&mut cbs, der.as_ptr(), der.len());
            let key = NonNull::new(aws_lc_sys::EVP_parse_private_key(&mut cbs)).map(Self);
            if aws_lc_sys::CBS_len(&cbs) != 0 {
                return None;
            }
            key
        }
    }

    /// Copies out a raw key that must be exactly `out.len()` bytes.
    fn raw(
        &self,
        out: &mut [u8],
        get: unsafe extern "C" fn(*const aws_lc_sys::EVP_PKEY, *mut u8, *mut usize) -> c_int,
    ) -> Result<()> {
        let mut length = out.len();
        // SAFETY: `self.0` is a live key; AWS-LC writes at most `length` bytes
        // to `out` and stores the number written in `length`.
        let ok = unsafe { get(self.0.as_ptr(), out.as_mut_ptr(), &mut length) } == 1;
        if ok && length == out.len() {
            Ok(())
        } else {
            Err(Error::CryptoFailure)
        }
    }
}

impl Drop for Pkey {
    fn drop(&mut self) {
        // SAFETY: the key came from EVP_parse_private_key, is owned by `self`
        // alone, and is freed nowhere else.
        unsafe { aws_lc_sys::EVP_PKEY_free(self.0.as_ptr()) }
    }
}

/// The decapsulation key and the encapsulation key for a seed.
pub(crate) fn from_seed(seed: &[u8]) -> Result<(kem::DecapsulationKey, Vec<u8>)> {
    if seed.len() != MLKEM1024_SEED_LENGTH {
        return Err(Error::CryptoFailure);
    }
    aws_lc_rs::init();
    let mut der = Zeroizing::new(Vec::with_capacity(PKCS8_SEED_PREFIX.len() + seed.len()));
    der.extend_from_slice(&PKCS8_SEED_PREFIX);
    der.extend_from_slice(seed);
    let key = Pkey::parse_pkcs8(&der).ok_or(Error::CryptoFailure)?;
    let mut private = Zeroizing::new(vec![0u8; MLKEM1024_PRIVATE_KEY_LENGTH]);
    let mut public = vec![0u8; MLKEM1024_PUBLIC_KEY_LENGTH];
    key.raw(&mut private, aws_lc_sys::EVP_PKEY_get_raw_private_key)?;
    key.raw(&mut public, aws_lc_sys::EVP_PKEY_get_raw_public_key)?;
    let decapsulation = kem::DecapsulationKey::new(&kem::ML_KEM_1024, &private)
        .map_err(|_| Error::CryptoFailure)?;
    Ok((decapsulation, public))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_every_other_length() {
        for length in [0, 1, 32, 63, 65, 96, MLKEM1024_PRIVATE_KEY_LENGTH] {
            assert!(from_seed(&vec![7; length]).is_err(), "{length} bytes");
        }
    }

    #[test]
    fn any_64_bytes_is_a_key() {
        for seed in [[0u8; 64], [0xff; 64]] {
            let (private, public) = from_seed(&seed).unwrap();
            assert_eq!(from_seed(&seed).unwrap().1, public);
            let (ciphertext, shared) = kem::EncapsulationKey::new(&kem::ML_KEM_1024, &public)
                .unwrap()
                .encapsulate()
                .unwrap();
            let opened = private.decapsulate(ciphertext.as_ref().into()).unwrap();
            assert_eq!(opened.as_ref(), shared.as_ref());
        }
    }

    #[test]
    fn another_seed_is_another_key() {
        let (one, _) = from_seed(&[1; 64]).unwrap();
        let (_, two) = from_seed(&[2; 64]).unwrap();
        let (ciphertext, shared) = kem::EncapsulationKey::new(&kem::ML_KEM_1024, &two)
            .unwrap()
            .encapsulate()
            .unwrap();
        let opened = one.decapsulate(ciphertext.as_ref().into()).unwrap();
        assert_ne!(opened.as_ref(), shared.as_ref());
    }

    #[test]
    fn refuses_trailing_bytes_and_other_forms() {
        let mut der = [&PKCS8_SEED_PREFIX[..], &[3; 64]].concat();
        assert!(Pkey::parse_pkcs8(&der).is_some());
        der.push(0);
        assert!(Pkey::parse_pkcs8(&der).is_none());
        assert!(Pkey::parse_pkcs8(&der[..der.len() - 2]).is_none());
        assert!(Pkey::parse_pkcs8(&[]).is_none());
    }
}
