// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

//! ML-KEM-768 keys from their 64-byte seed (FIPS 203's d || z), which is how
//! RFC 9180 serialises the private key and how Swift and Go hold it.
//! aws-lc-rs takes only the expanded 2,400-byte key, so the seed goes in
//! through AWS-LC's PKCS#8 parser, which accepts the seed form of
//! draft-ietf-lamps-kyber-certificates and runs FIPS 203's KeyGen on it.

use crate::error::{Error, Result};
use crate::hpke::MLKEM768_SEED_LENGTH;

/// PrivateKeyInfo { version 0, id-alg-ml-kem-768, OCTET STRING { [0] seed } }.
const PKCS8_SEED_PREFIX: [u8; 22] = [
    0x30, 0x54, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
    0x04, 0x02, 0x04, 0x42, 0x80, 0x40,
];

/// The expanded decapsulation key and the encapsulation key for a seed.
pub(crate) fn from_seed(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    if seed.len() != MLKEM768_SEED_LENGTH {
        return Err(Error::CryptoFailure);
    }
    let der = [&PKCS8_SEED_PREFIX[..], seed].concat();
    // SAFETY: AWS-LC reads at most `der.len()` bytes from `der`, writes at most
    // the lengths passed in, and the key is freed on every path.
    unsafe {
        let mut input = der.as_ptr();
        let key = aws_lc_sys::d2i_AutoPrivateKey(core::ptr::null_mut(), &mut input, der.len() as _);
        if key.is_null() {
            return Err(Error::CryptoFailure);
        }
        let mut private = vec![0u8; 2400];
        let mut public = vec![0u8; 1184];
        let (mut private_length, mut public_length) = (private.len(), public.len());
        let ok = aws_lc_sys::EVP_PKEY_get_raw_private_key(
            key,
            private.as_mut_ptr(),
            &mut private_length,
        ) == 1
            && aws_lc_sys::EVP_PKEY_get_raw_public_key(
                key,
                public.as_mut_ptr(),
                &mut public_length,
            ) == 1;
        aws_lc_sys::EVP_PKEY_free(key);
        if !ok || private_length != private.len() || public_length != public.len() {
            return Err(Error::CryptoFailure);
        }
        Ok((private, public))
    }
}
