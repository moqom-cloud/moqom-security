// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

//! Every case in `vectors/token`, which the Go implementation generates.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use moqom_token::{Algorithm, Claims, KeyError, PublicKey, Signer, Verifier, key_id};
use serde::Deserialize;

#[derive(Deserialize)]
struct File<C> {
    keys: Vec<Key>,
    cases: Vec<C>,
}

#[derive(Deserialize)]
struct Key {
    kid: String,
    alg: String,
    seed_hex: String,
    public_hex: String,
    kid_derived: bool,
}

#[derive(Deserialize)]
struct VerifyCase {
    name: String,
    token: String,
    now: u64,
    issuer: String,
    #[serde(default)]
    tenant: String,
    keys: Vec<String>,
    claims: Option<Claims>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct SignCase {
    name: String,
    kid: String,
    claims: Claims,
    signing_input: Option<String>,
    token: Option<String>,
    error: Option<String>,
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
        .collect()
}

fn at(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds)
}

fn read<C: for<'de> Deserialize<'de>>(
    name: &str,
) -> (Vec<C>, HashMap<String, PublicKey>, HashMap<String, Signer>) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors/token")
        .join(name);
    let file: File<C> =
        serde_json::from_slice(&std::fs::read(&path).expect("the vectors")).expect("JSON");
    let mut public = HashMap::new();
    let mut signers = HashMap::new();
    for key in file.keys {
        let raw = hex(&key.public_hex);
        let seed: [u8; 32] = hex(&key.seed_hex).try_into().expect("a 32-byte seed");
        if key.kid_derived {
            assert_eq!(key_id(&raw), key.kid, "kid derivation");
        }
        match key.alg.as_str() {
            "ML-DSA-65" => {
                let signer = Signer::from_seed(&seed)
                    .expect("seed")
                    .with_id(key.kid.clone());
                assert_eq!(
                    signer.public_key().bytes,
                    raw,
                    "{}: seed and public key",
                    key.kid
                );
                public.insert(key.kid.clone(), PublicKey::ml_dsa_65(key.kid.clone(), raw));
                signers.insert(key.kid, signer);
            }
            "EdDSA" => {
                let pair = Ed25519KeyPair::from_seed_unchecked(&seed).expect("seed");
                assert_eq!(pair.public_key().as_ref(), raw.as_slice());
                public.insert(key.kid.clone(), PublicKey::ed25519(key.kid, raw));
            }
            other => panic!("algorithm {other}"),
        }
    }
    (file.cases, public, signers)
}

#[test]
fn every_verify_vector() {
    let (cases, public, _) = read::<VerifyCase>("verify.json");
    assert!(cases.len() > 40);
    for case in cases {
        let keys = case.keys.iter().map(|kid| public[kid].clone());
        let verifier = Verifier::new(case.issuer, keys).for_tenant(case.tenant);
        let result = verifier.verify(case.token.as_bytes(), at(case.now));
        match (&case.error, &case.claims) {
            (Some(class), _) => assert_eq!(
                result.as_ref().map_err(|e| e.class()).err(),
                Some(class.as_str()),
                "{}: {result:?}",
                case.name
            ),
            (None, Some(claims)) => assert_eq!(result.as_ref(), Ok(claims), "{}", case.name),
            (None, None) => panic!("{}: neither claims nor an error", case.name),
        }
    }
}

#[test]
fn every_sign_vector() {
    let (cases, public, signers) = read::<SignCase>("sign.json");
    for case in cases {
        let signer = &signers[&case.kid];
        let signed = signer.sign(&case.claims);
        if let Some(class) = &case.error {
            assert_eq!(
                signed.map_err(|e| e.class()).err(),
                Some(class.as_str()),
                "{}",
                case.name
            );
            continue;
        }
        let signed = signed.unwrap_or_else(|e| panic!("{}: {e}", case.name));
        let input = &signed[..signed.rfind('.').expect("three segments")];
        assert_eq!(Some(input), case.signing_input.as_deref(), "{}", case.name);

        let verifier = Verifier::new("", [public[&case.kid].clone()]);
        let now = at(u64::try_from(case.claims.iat).expect("after the epoch"));
        for token in [case.token.as_deref().expect("a token"), signed.as_str()] {
            assert_eq!(
                verifier.verify(token.as_bytes(), now),
                Ok(case.claims.clone()),
                "{}",
                case.name
            );
        }
    }
}

#[test]
fn a_jwk_set_round_trips() {
    let signer = Signer::from_seed(&[1; 32]).expect("seed");
    let legacy = PublicKey::ed25519("old", vec![7; 32]);
    let document =
        serde_json::json!({ "keys": [signer.public_key().jwk(), legacy.jwk()] }).to_string();
    assert_eq!(
        PublicKey::parse_set(&document),
        Ok(vec![signer.public_key(), legacy])
    );
    assert_eq!(signer.public_key().algorithm, Algorithm::MlDsa65);

    for refused in [
        r#"[{"kty":"AKP","alg":"ML-DSA-44","kid":"k","pub":"AAAA"}]"#,
        r#"[{"kty":"AKP","alg":"ML-DSA-65","kid":"k","pub":"AAAA"}]"#,
        r#"[{"kty":"OKP","crv":"P-256","kid":"k","x":"AAAA"}]"#,
        r#"["not an object"]"#,
    ] {
        assert!(PublicKey::parse_set(refused).is_err(), "{refused}");
    }
}

#[derive(Deserialize)]
struct KeySetCase {
    name: String,
    document: String,
    kids: Option<Vec<String>>,
    error: Option<String>,
}

#[test]
fn every_key_set_vector() {
    let (cases, _, _) = read::<KeySetCase>("keysets.json");
    assert!(cases.len() > 30);
    for case in cases {
        let result = PublicKey::parse_set(&case.document);
        match (&case.error, &case.kids) {
            (Some(class), _) => assert_eq!(
                result.as_ref().map_err(KeyError::class).err(),
                Some(class.as_str()),
                "{}: {result:?}",
                case.name
            ),
            (None, Some(kids)) => {
                let got: Vec<&str> = result
                    .as_ref()
                    .unwrap_or_else(|e| panic!("{}: {e}", case.name))
                    .iter()
                    .map(|key| key.id.as_str())
                    .collect();
                assert_eq!(got, *kids, "{}", case.name);
            }
            (None, None) => panic!("{}: neither kids nor an error", case.name),
        }
    }
}

#[test]
fn a_verifier_looks_up_its_keys() {
    let signer = Signer::from_seed(&[1; 32]).expect("seed");
    assert!(Verifier::new("", []).is_empty());
    let verifier = Verifier::new("", [signer.public_key()]);
    assert!(!verifier.is_empty());
    assert_eq!(verifier.key(signer.id()), Some(&signer.public_key()));
    assert_eq!(verifier.key("other"), None);
}
