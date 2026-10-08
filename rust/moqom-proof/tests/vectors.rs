// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

//! Every case in `vectors/proof`.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use moqom_proof::{Algorithm, Checker, Jwk, MemoryNonceStore, NonceStore as _, Prover};
use serde::Deserialize;

const KEYS: &str = include_str!("../../../vectors/proof/keys.json");
const THUMBPRINTS: &str = include_str!("../../../vectors/proof/thumbprints.json");
const PROOFS: &str = include_str!("../../../vectors/proof/proofs.json");

#[derive(Deserialize)]
struct File<T> {
    #[serde(default)]
    window_seconds: u64,
    cases: Vec<T>,
}

#[derive(Deserialize)]
struct KeyCase {
    name: String,
    alg: String,
    #[serde(default)]
    seed_hex: String,
    #[serde(default)]
    pkcs8_hex: String,
    jwk: Jwk,
    thumbprint: String,
}

#[derive(Deserialize)]
struct ThumbprintCase {
    name: String,
    jwk: Jwk,
    #[serde(default)]
    thumbprint: String,
    #[serde(default)]
    error: String,
}

#[derive(Deserialize)]
struct ProofCase {
    name: String,
    token: String,
    certificate_hash_hex: String,
    thumbprint: String,
    now: u64,
    until: u64,
    #[serde(default)]
    spent: Vec<String>,
    #[serde(default)]
    require_certificate: bool,
    proof: String,
    #[serde(default)]
    error: String,
}

fn hex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).expect("hex"))
        .collect()
}

fn at(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds)
}

fn read<T: for<'de> Deserialize<'de>>(json: &str) -> File<T> {
    let file: File<T> = serde_json::from_str(json).expect("the vectors parse");
    assert!(!file.cases.is_empty(), "no cases");
    file
}

#[test]
fn keys() {
    for case in read::<KeyCase>(KEYS).cases {
        let prover = match Algorithm::from_jose(&case.alg) {
            Some(Algorithm::MlDsa65) => Prover::ml_dsa_65_from_seed(&hex(&case.seed_hex)),
            Some(Algorithm::Es256) => Prover::from_pkcs8(&hex(&case.pkcs8_hex)),
            None => panic!("{}: unknown alg", case.name),
        }
        .unwrap_or_else(|e| panic!("{}: {e}", case.name));
        assert_eq!(prover.jwk(), &case.jwk, "{}", case.name);
        assert_eq!(prover.thumbprint(), case.thumbprint, "{}", case.name);

        let stored = Prover::from_pkcs8(&prover.to_pkcs8().expect("pkcs8")).expect("reloads");
        assert_eq!(stored.thumbprint(), case.thumbprint, "{}: pkcs8", case.name);
    }
}

#[test]
fn thumbprints() {
    for case in read::<ThumbprintCase>(THUMBPRINTS).cases {
        match case.jwk.thumbprint() {
            Ok(got) => assert!(
                case.error.is_empty() && got == case.thumbprint,
                "{}: got {got}, want {} {}",
                case.name,
                case.thumbprint,
                case.error
            ),
            Err(e) => assert_eq!(e.class(), case.error, "{}: {e}", case.name),
        }
    }
}

#[test]
fn proofs() {
    let file = read::<ProofCase>(PROOFS);
    for case in file.cases {
        let (now, until) = (at(case.now), at(case.until));
        let checker = Checker::new(MemoryNonceStore::default())
            .with_window(Duration::from_secs(file.window_seconds))
            .with_certificate_required(case.require_certificate);
        for nonce in &case.spent {
            checker.store().spend(nonce, until, now).expect("spent");
        }
        let certificate = hex(&case.certificate_hash_hex);
        let check = || {
            checker.check(
                case.proof.as_bytes(),
                case.token.as_bytes(),
                (!certificate.is_empty()).then_some(certificate.as_slice()),
                &case.thumbprint,
                now,
                until,
            )
        };
        let got = check().err().map_or("", |e| e.class());
        assert_eq!(got, case.error, "{}: {:?}", case.name, check());

        if case.error.is_empty() {
            assert_eq!(checker.store().remembered(), case.spent.len() + 1, "{}", case.name);
            assert_eq!(check().err().map(|e| e.class()), Some("replayed"), "{}", case.name);
        } else {
            assert_eq!(
                checker.store().remembered(),
                case.spent.len(),
                "{}: a refused proof spent its nonce",
                case.name
            );
        }
    }
}
