// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

use std::time::{Duration, SystemTime};

use moqom_proof::{
    Algorithm, Checker, DEFAULT_CAPACITY, DEFAULT_WINDOW, Error, MAX_PROOF_BYTES, MemoryNonceStore,
    NonceStore as _, Prover, nonce,
};

const CERTIFICATE: [u8; 32] = [0x2a; 32];

fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

fn until() -> SystemTime {
    now() + Duration::from_mins(10)
}

#[test]
fn a_proof_round_trips_in_each_algorithm() {
    for algorithm in Algorithm::ALL {
        let prover = Prover::generate(algorithm).expect("a key");
        assert_eq!(prover.algorithm(), algorithm);
        let proof = prover
            .prove(b"a.token", &CERTIFICATE, &nonce().unwrap(), now())
            .expect("a proof");
        let checker = Checker::new(MemoryNonceStore::default());
        let check = || {
            checker.check(
                &proof,
                b"a.token",
                Some(&CERTIFICATE),
                prover.thumbprint(),
                now(),
                until(),
            )
        };
        assert_eq!(check(), Ok(()), "{algorithm:?}");
        assert_eq!(check(), Err(Error::Replayed), "{algorithm:?}");
    }
}

#[test]
fn a_key_survives_pkcs8() {
    for algorithm in Algorithm::ALL {
        let prover = Prover::generate(algorithm).expect("a key");
        let reloaded = Prover::from_pkcs8(&prover.to_pkcs8().unwrap()).expect("reloads");
        assert_eq!(reloaded.thumbprint(), prover.thumbprint());
        assert_eq!(reloaded.jwk_json(), prover.jwk_json());
    }
    assert!(matches!(
        Prover::from_pkcs8(b"not a key"),
        Err(Error::Malformed(_))
    ));
}

#[test]
fn an_ml_dsa_proof_fits_the_limit() {
    let prover = Prover::generate(Algorithm::MlDsa65).unwrap();
    let proof = prover
        .prove(&[b't'; 5000], &CERTIFICATE, &nonce().unwrap(), now())
        .unwrap();
    assert!(
        proof.len() < MAX_PROOF_BYTES * 3 / 4,
        "{} bytes",
        proof.len()
    );
}

#[test]
fn a_checker_can_refuse_es256() {
    let prover = Prover::generate(Algorithm::Es256).unwrap();
    let proof = prover.prove(b"t", &CERTIFICATE, "n", now()).unwrap();
    let checker = Checker::new(MemoryNonceStore::default())
        .with_algorithms(&[Algorithm::MlDsa65])
        .unwrap();
    assert_eq!(
        checker.check(
            &proof,
            b"t",
            Some(&CERTIFICATE),
            prover.thumbprint(),
            now(),
            until()
        ),
        Err(Error::Unsupported)
    );
}

#[test]
fn no_certificate_leaves_the_binding_unchecked() {
    let prover = Prover::generate(Algorithm::MlDsa65).unwrap();
    let proof = prover.prove(b"t", &[], "n", now()).unwrap();
    let checker = Checker::new(MemoryNonceStore::default());
    assert_eq!(
        checker.check(&proof, b"t", None, prover.thumbprint(), now(), until()),
        Ok(())
    );
}

#[test]
fn the_store_sweeps_expired_nonces_and_fails_closed() {
    let store = MemoryNonceStore::new(2).unwrap();
    store.spend("a", now(), now()).unwrap();
    store.spend("b", now(), now()).unwrap();
    let later = now() + Duration::from_secs(1);
    assert_eq!(store.spend("c", until(), later), Ok(()));
    assert_eq!(store.spend("d", until(), later), Ok(()));
    assert_eq!(store.spend("e", until(), later), Err(Error::Overloaded));
}

#[test]
fn nonces_are_fresh_and_a_proof_needs_one() {
    assert_ne!(nonce().unwrap(), nonce().unwrap());
    let prover = Prover::generate(Algorithm::MlDsa65).unwrap();
    assert!(matches!(
        prover.prove(b"t", &CERTIFICATE, "", now()),
        Err(Error::Malformed(_))
    ));
}

#[test]
fn settings_that_cannot_work_are_refused_at_construction() {
    let configuration = |result: Result<(), Error>| {
        assert!(matches!(result, Err(Error::Configuration(_))), "{result:?}");
        assert_eq!(result.unwrap_err().class(), "configuration");
    };
    configuration(MemoryNonceStore::new(0).map(drop));
    configuration(
        Checker::new(MemoryNonceStore::default())
            .with_window(Duration::ZERO)
            .map(drop),
    );
    configuration(
        Checker::new(MemoryNonceStore::default())
            .with_algorithms(&[])
            .map(drop),
    );

    let checker = Checker::new(MemoryNonceStore::default());
    assert_eq!(checker.algorithms(), Algorithm::ALL);
    assert_eq!(checker.window(), DEFAULT_WINDOW);
    assert!(!checker.certificate_required());
    assert_eq!(checker.store().capacity(), DEFAULT_CAPACITY);
}

/// A caller that passes an `until` earlier than the end of the proof's window
/// must not get the proof accepted twice once the store sweeps.
#[test]
fn a_short_until_cannot_reopen_replay() {
    let prover = Prover::generate(Algorithm::MlDsa65).unwrap();
    let checker = Checker::new(MemoryNonceStore::new(2).unwrap());
    let proof = prover
        .prove(b"a.token", &CERTIFICATE, &nonce().unwrap(), now())
        .unwrap();
    let check = |at: SystemTime| {
        checker.check(
            &proof,
            b"a.token",
            Some(&CERTIFICATE),
            prover.thumbprint(),
            at,
            at,
        )
    };
    assert_eq!(check(now()), Ok(()));
    // Fill the store so that the next spend sweeps whatever has expired.
    checker.store().spend("filler", now(), now()).unwrap();
    assert_eq!(check(now() + DEFAULT_WINDOW), Err(Error::Replayed));
    assert_eq!(checker.store().remembered(), 1);
}
