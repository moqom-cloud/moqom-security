// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

//! X-Wing (draft-connolly-cfrg-xwing-kem), HPKE KEM 0x647a: ML-KEM-768 and
//! X25519 under a SHA3-256 combiner. The private key is the 32-byte seed, as
//! CryptoKit's `XWingMLKEM768X25519` and Go's `crypto/hpke` hold it; the
//! public key is ML-KEM-768's then X25519's, and so is the ciphertext.
//! aws-lc-rs has SHA3-256 but not SHAKE256, which expands the seed; that is
//! RustCrypto's `sha3`.

use aws_lc_rs::{agreement, digest, kem};
use sha3::Shake256;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::hpke::{MLKEM768_CIPHERTEXT_LENGTH, MLKEM768_PUBLIC_KEY_LENGTH, MLKEM768_SEED_LENGTH};

pub(crate) const SEED_LENGTH: usize = 32;
const X25519_LENGTH: usize = 32;
pub(crate) const PUBLIC_KEY_LENGTH: usize = MLKEM768_PUBLIC_KEY_LENGTH + X25519_LENGTH;
pub(crate) const CIPHERTEXT_LENGTH: usize = MLKEM768_CIPHERTEXT_LENGTH + X25519_LENGTH;

/// XWingLabel, the ASCII art `\.//^\`.
const LABEL: &[u8] = br"\.//^\";

struct PrivateKey {
    ml_kem: kem::DecapsulationKey,
    x25519: agreement::PrivateKey,
    public: Vec<u8>,
}

impl PrivateKey {
    /// expandDecapsulationKey: SHAKE256(seed, 96) is ML-KEM-768's d || z, then
    /// the X25519 scalar.
    fn expand(seed: &[u8]) -> Result<Self> {
        if seed.len() != SEED_LENGTH {
            return Err(Error::CryptoFailure);
        }
        let mut expanded = Zeroizing::new([0u8; MLKEM768_SEED_LENGTH + X25519_LENGTH]);
        Shake256::default()
            .chain(seed)
            .finalize_xof()
            .read(&mut expanded[..]);
        let (ml_kem, mut public) = crate::mlkem::from_seed(&expanded[..MLKEM768_SEED_LENGTH])?;
        let x25519 = agreement::PrivateKey::from_private_key(
            &agreement::X25519,
            &expanded[MLKEM768_SEED_LENGTH..],
        )
        .map_err(|_| Error::CryptoFailure)?;
        public.extend_from_slice(
            x25519
                .compute_public_key()
                .map_err(|_| Error::CryptoFailure)?
                .as_ref(),
        );
        Ok(Self {
            ml_kem,
            x25519,
            public,
        })
    }
}

/// The combiner: SHA3-256(ss_M || ss_X || ct_X || pk_X || XWingLabel).
fn combine(ss_m: &[u8], ss_x: &[u8], ct_x: &[u8], pk_x: &[u8]) -> Vec<u8> {
    let mut hash = digest::Context::new(&digest::SHA3_256);
    for part in [ss_m, ss_x, ct_x, pk_x, LABEL] {
        hash.update(part);
    }
    hash.finish().as_ref().to_vec()
}

pub(crate) fn public_key(seed: &[u8]) -> Result<Vec<u8>> {
    Ok(PrivateKey::expand(seed)?.public)
}

/// The shared secret and the ciphertext ct_M || ct_X.
pub(crate) fn encapsulate(public: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    if public.len() != PUBLIC_KEY_LENGTH {
        return Err(Error::CryptoFailure);
    }
    let (pk_m, pk_x) = public.split_at(MLKEM768_PUBLIC_KEY_LENGTH);
    let (ct_m, ss_m) = kem::EncapsulationKey::new(&kem::ML_KEM_768, pk_m)
        .and_then(|key| key.encapsulate().map_err(Into::into))
        .map_err(|_| Error::CryptoFailure)?;
    let ephemeral =
        agreement::PrivateKey::generate(&agreement::X25519).map_err(|_| Error::CryptoFailure)?;
    let ct_x = ephemeral
        .compute_public_key()
        .map_err(|_| Error::CryptoFailure)?;
    let shared = agreement::agree(
        &ephemeral,
        agreement::UnparsedPublicKey::new(&agreement::X25519, pk_x),
        Error::CryptoFailure,
        |ss_x| Ok(combine(ss_m.as_ref(), ss_x, ct_x.as_ref(), pk_x)),
    )?;
    Ok((shared, [ct_m.as_ref(), ct_x.as_ref()].concat()))
}

/// AWS-LC refuses an X25519 share whose output is all zero, as Go does; the
/// draft does not require the check.
pub(crate) fn decapsulate(ciphertext: &[u8], seed: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.len() != CIPHERTEXT_LENGTH {
        return Err(Error::DecryptionFailed);
    }
    let key = PrivateKey::expand(seed).map_err(|_| Error::DecryptionFailed)?;
    let (ct_m, ct_x) = ciphertext.split_at(MLKEM768_CIPHERTEXT_LENGTH);
    let ss_m = key
        .ml_kem
        .decapsulate(ct_m.into())
        .map_err(|_| Error::DecryptionFailed)?;
    let pk_x = &key.public[MLKEM768_PUBLIC_KEY_LENGTH..];
    agreement::agree(
        &key.x25519,
        agreement::UnparsedPublicKey::new(&agreement::X25519, ct_x),
        Error::DecryptionFailed,
        |ss_x| Ok(combine(ss_m.as_ref(), ss_x, ct_x, pk_x)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn published(file: &str) -> Vec<serde_json::Value> {
        let path = format!("{}/../../vectors/mls/{file}", env!("CARGO_MANIFEST_DIR"));
        let document: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect(&path)).expect(&path);
        document["cases"].as_array().expect("cases").clone()
    }

    fn hex(v: &serde_json::Value, key: &str) -> Vec<u8> {
        let s = v[key].as_str().expect(key);
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect(key))
            .collect()
    }

    #[test]
    fn draft_vectors() {
        for v in published("xwing-draft.json") {
            let name = v["name"].as_str().unwrap();
            assert_eq!(public_key(&hex(&v, "sk")).unwrap(), hex(&v, "pk"), "{name}");
            assert_eq!(
                decapsulate(&hex(&v, "ct"), &hex(&v, "sk")).unwrap(),
                hex(&v, "ss"),
                "{name}"
            );
        }
    }

    #[test]
    fn hpke_working_group_vector() {
        for v in published("hpkewg-xwing.json") {
            assert_eq!(public_key(&hex(&v, "skRm")).unwrap(), hex(&v, "pkRm"));
            assert_eq!(
                decapsulate(&hex(&v, "enc"), &hex(&v, "skRm")).unwrap(),
                hex(&v, "shared_secret")
            );
        }
    }

    #[test]
    fn round_trip() {
        let seed = [9u8; SEED_LENGTH];
        let public = public_key(&seed).unwrap();
        assert_eq!(public.len(), PUBLIC_KEY_LENGTH);
        let (shared, ciphertext) = encapsulate(&public).unwrap();
        assert_eq!(ciphertext.len(), CIPHERTEXT_LENGTH);
        assert_eq!(decapsulate(&ciphertext, &seed).unwrap(), shared);
        assert_ne!(decapsulate(&ciphertext, &[8; SEED_LENGTH]).unwrap(), shared);
    }

    #[test]
    fn refuses_wrong_lengths() {
        for length in [0, 31, 33, 64] {
            assert!(public_key(&vec![1; length]).is_err(), "seed of {length}");
        }
        let public = public_key(&[1; SEED_LENGTH]).unwrap();
        assert!(encapsulate(&public[1..]).is_err());
        let (_, ciphertext) = encapsulate(&public).unwrap();
        assert!(decapsulate(&ciphertext[1..], &[1; SEED_LENGTH]).is_err());
        assert!(decapsulate(&ciphertext, &[1; 64]).is_err());
    }

    #[test]
    fn refuses_a_low_order_x25519_share() {
        let seed = [5u8; SEED_LENGTH];
        let (_, mut ciphertext) = encapsulate(&public_key(&seed).unwrap()).unwrap();
        ciphertext[MLKEM768_CIPHERTEXT_LENGTH..].fill(0);
        assert_eq!(
            decapsulate(&ciphertext, &seed),
            Err(Error::DecryptionFailed)
        );
    }
}
