// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

//! Every file in vectors/mls, run through this crate.

use moqom_mls::{
    CipherSuite, CommitMessage, EpochSecrets, Error, Group, GroupContext, HpkeCiphertext,
    KeyPackage, KeyPackageBundle, Processed, Welcome, audience, welcome_secret,
};
use serde_json::Value;

fn cases(file: &str) -> Vec<Value> {
    let path = format!("{}/../../vectors/mls/{file}", env!("CARGO_MANIFEST_DIR"));
    let document: Value =
        serde_json::from_str(&std::fs::read_to_string(&path).expect(&path)).expect(&path);
    let cases = document["cases"].as_array().expect("cases").clone();
    assert!(!cases.is_empty(), "{file}: no cases");
    cases
}

fn hex(v: &Value, key: &str) -> Vec<u8> {
    let s = v[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} is not a string"));
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect(key))
        .collect()
}

fn string<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} is not a string"))
}

fn int(v: &Value, key: &str) -> usize {
    v[key]
        .as_u64()
        .unwrap_or_else(|| panic!("{key} is not a number")) as usize
}

fn name(v: &Value) -> &str {
    v["name"].as_str().unwrap_or("")
}

fn expected_error(v: &Value) -> &str {
    v["error"].as_str().unwrap_or("")
}

fn class<T>(result: &Result<T, Error>) -> &'static str {
    result.as_ref().err().map_or("", Error::class)
}

/// The published cases in suite 5, which is SHA-512's: what 0xF0AC's KDF is
/// held to. Suite 1's are skipped; it is an AES-128 suite, not implemented.
fn published_cases(file: &str) -> Vec<Value> {
    cases(file)
        .into_iter()
        .filter(|v| int(v, "cipher_suite") == 5)
        .collect()
}

#[test]
fn published_crypto_basics() {
    for v in published_cases("mlswg-crypto-basics.json") {
        let suite = CipherSuite::MLDSA;
        let e = &v["ref_hash"];
        assert_eq!(
            suite.ref_hash(string(e, "label"), &hex(e, "value")),
            hex(e, "out"),
            "{}: ref_hash",
            name(&v)
        );
        let e = &v["expand_with_label"];
        assert_eq!(
            suite.expand_with_label(
                &hex(e, "secret"),
                string(e, "label"),
                &hex(e, "context"),
                int(e, "length")
            ),
            Ok(hex(e, "out"))
        );
        let e = &v["derive_secret"];
        assert_eq!(
            suite.derive_secret(&hex(e, "secret"), string(e, "label")),
            hex(e, "out")
        );
        let e = &v["derive_tree_secret"];
        let generation = (int(e, "generation") as u32).to_be_bytes();
        assert_eq!(
            suite.expand_with_label(
                &hex(e, "secret"),
                string(e, "label"),
                &generation,
                int(e, "length")
            ),
            Ok(hex(e, "out"))
        );
    }
}

const SECRETS: [&str; 11] = [
    "joiner_secret",
    "welcome_secret",
    "sender_data_secret",
    "encryption_secret",
    "exporter_secret",
    "external_secret",
    "confirmation_key",
    "membership_key",
    "resumption_psk",
    "epoch_authenticator",
    "init_secret",
];

fn secret<'a>(s: &'a EpochSecrets, key: &str) -> &'a [u8] {
    match key {
        "joiner_secret" => &s.joiner_secret,
        "welcome_secret" => &s.welcome_secret,
        "epoch_secret" => &s.epoch_secret,
        "sender_data_secret" => &s.sender_data_secret,
        "encryption_secret" => &s.encryption_secret,
        "exporter_secret" => &s.exporter_secret,
        "external_secret" => &s.external_secret,
        "confirmation_key" => &s.confirmation_key,
        "membership_key" => &s.membership_key,
        "resumption_psk" => &s.resumption_psk,
        "epoch_authenticator" => &s.epoch_authenticator,
        "init_secret" => &s.init_secret,
        _ => unreachable!(),
    }
}

#[test]
fn published_key_schedule() {
    for v in published_cases("mlswg-key-schedule.json") {
        let suite = CipherSuite::MLDSA;
        let mut init = hex(&v, "initial_init_secret");
        for (index, e) in v["epochs"].as_array().unwrap().iter().enumerate() {
            let psk = hex(e, "psk_secret");
            let s = EpochSecrets::derive_encoded(
                suite,
                &init,
                &hex(e, "commit_secret"),
                Some(&psk),
                &hex(e, "group_context"),
            );
            for key in SECRETS {
                assert_eq!(
                    secret(&s, key),
                    hex(e, key),
                    "{} epoch {index}: {key}",
                    name(&v)
                );
            }
            assert_eq!(
                welcome_secret(suite, &s.joiner_secret, Some(&psk)),
                hex(e, "welcome_secret")
            );
            let x = &e["exporter"];
            assert_eq!(
                s.exporter(string(x, "label"), &hex(x, "context"), int(x, "length"))
                    .unwrap(),
                hex(x, "secret")
            );
            init = s.init_secret.clone();
        }
    }
}

#[test]
fn crypto() {
    for v in [
        cases("mls-crypto.json"),
        cases("mls-crypto-go.json"),
        cases("mls-crypto-rust.json"),
    ]
    .concat()
    {
        let suite = v["cipher_suite"]
            .as_u64()
            .map_or(CipherSuite::MLDSA, |s| CipherSuite(s as u16));
        let want = expected_error(&v);
        match string(&v, "op") {
            "expand_with_label" => assert_eq!(
                suite.expand_with_label(
                    &hex(&v, "secret_hex"),
                    string(&v, "label"),
                    &hex(&v, "context_hex"),
                    int(&v, "length")
                ),
                Ok(hex(&v, "out_hex")),
                "{}",
                name(&v)
            ),
            "derive_secret" => {
                assert_eq!(
                    suite.derive_secret(&hex(&v, "secret_hex"), string(&v, "label")),
                    hex(&v, "out_hex"),
                    "{}",
                    name(&v)
                );
            }
            "ref_hash" => {
                assert_eq!(
                    suite.ref_hash(string(&v, "label"), &hex(&v, "value_hex")),
                    hex(&v, "out_hex"),
                    "{}",
                    name(&v)
                );
            }
            "sign_with_label" => {
                let (public, label, content) = (
                    hex(&v, "public_key_hex"),
                    string(&v, "label"),
                    hex(&v, "content_hex"),
                );
                let ok =
                    suite.verify_with_label(&public, label, &content, &hex(&v, "signature_hex"));
                assert_eq!(ok, want.is_empty(), "{}", name(&v));
                if want.is_empty() {
                    let ours = suite
                        .sign_with_label(&hex(&v, "seed_hex"), label, &content)
                        .unwrap();
                    assert!(
                        suite.verify_with_label(&public, label, &content, &ours),
                        "{}: own signature",
                        name(&v)
                    );
                }
            }
            "encrypt_with_label" => {
                let public = suite.kem_public_key(&hex(&v, "seed_hex")).unwrap();
                assert_eq!(
                    public,
                    hex(&v, "public_key_hex"),
                    "{}: public key from seed",
                    name(&v)
                );
                let sealed = HpkeCiphertext {
                    kem_output: hex(&v, "kem_output_hex"),
                    ciphertext: hex(&v, "ciphertext_hex"),
                };
                let opened = suite.decrypt_with_label(
                    &hex(&v, "seed_hex"),
                    string(&v, "label"),
                    &hex(&v, "context_hex"),
                    &sealed,
                );
                assert_eq!(class(&opened), want, "{}", name(&v));
                if want.is_empty() {
                    assert_eq!(opened.unwrap(), hex(&v, "plaintext_hex"), "{}", name(&v));
                }
            }
            op => panic!("unknown op {op}"),
        }
    }
}

#[test]
fn key_schedule() {
    for v in cases("mls-key-schedule.json") {
        let mut init = hex(&v, "initial_init_secret_hex");
        for (index, e) in v["epochs"].as_array().unwrap().iter().enumerate() {
            let context = GroupContext {
                cipher_suite: CipherSuite(int(&v, "cipher_suite") as u16),
                group_id: hex(&v, "group_id_hex"),
                epoch: index as u64,
                tree_hash: hex(e, "tree_hash_hex"),
                confirmed_transcript_hash: hex(e, "confirmed_transcript_hash_hex"),
            };
            assert_eq!(
                context.encode(),
                hex(e, "group_context_hex"),
                "epoch {index}"
            );
            let s = EpochSecrets::derive(&init, &hex(e, "commit_secret_hex"), None, &context);
            for key in SECRETS.iter().copied().chain(["epoch_secret"]) {
                assert_eq!(
                    secret(&s, key),
                    hex(e, &format!("{key}_hex")),
                    "epoch {index}: {key}"
                );
            }
            for x in e["exporters"].as_array().unwrap() {
                assert_eq!(
                    s.exporter(string(x, "label"), &hex(x, "context_hex"), int(x, "length"))
                        .unwrap(),
                    hex(x, "out_hex"),
                    "epoch {index}: exporter {}",
                    string(x, "label")
                );
            }
            init = s.init_secret.clone();
        }
    }
}

#[test]
fn key_packages() {
    for v in cases("mls-key-packages.json") {
        let parsed = KeyPackage::parse(&hex(&v, "key_package_hex"));
        assert_eq!(class(&parsed), expected_error(&v), "{}", name(&v));
        let Ok(k) = parsed else { continue };
        let e = &v["expect"];
        assert_eq!(
            k.cipher_suite.0 as usize,
            int(e, "cipher_suite"),
            "{}",
            name(&v)
        );
        assert_eq!(k.identity, string(e, "identity").as_bytes());
        assert_eq!(k.signature_key, hex(e, "signature_key_hex"));
        assert_eq!(k.init_key, hex(e, "init_key_hex"));
        assert_eq!(k.encryption_key, hex(e, "encryption_key_hex"));
        assert_eq!(k.reference(), hex(e, "reference_hex"));
        assert_eq!(k.encode(), hex(&v, "key_package_hex"));
    }
}

#[test]
fn groups() {
    for v in [cases("mls-group.json"), cases("mls-group-go.json")].concat() {
        let m = &v["member"];
        let bundle = KeyPackageBundle::new(
            KeyPackage::decode(&hex(m, "key_package_hex")).unwrap(),
            hex(m, "init_private_hex"),
            hex(m, "encryption_private_hex"),
            hex(m, "signature_private_hex"),
        );
        let mut group: Option<Group> = None;
        for (index, step) in v["steps"].as_array().unwrap().iter().enumerate() {
            let mut removed = false;
            let result = if step.get("welcome_hex").is_some() {
                Welcome::decode(&hex(step, "welcome_hex"))
                    .and_then(|w| Group::join(&w, &bundle))
                    .map(|g| group = Some(g))
            } else {
                CommitMessage::decode(&hex(step, "commit_hex"))
                    .and_then(|message| group.as_ref().expect("joined").process(&message))
                    .map(|processed| match processed {
                        Processed::Advanced(next) => group = Some(*next),
                        Processed::Removed => removed = true,
                    })
            };
            assert_eq!(
                class(&result),
                expected_error(step),
                "{} step {index}",
                name(&v)
            );
            assert_eq!(
                removed,
                step.get("removed").is_some(),
                "{} step {index}: removed",
                name(&v)
            );
            if let Some(e) = step.get("expect") {
                check_state(
                    group.as_ref().unwrap(),
                    e,
                    &format!("{} step {index}", name(&v)),
                );
            }
        }
    }
}

fn check_state(group: &Group, e: &Value, at: &str) {
    assert_eq!(group.epoch() as usize, int(e, "epoch"), "{at}: epoch");
    assert_eq!(
        group.own_leaf() as usize,
        int(e, "own_leaf"),
        "{at}: own leaf"
    );
    let members: Vec<Option<&str>> = group
        .members()
        .iter()
        .map(|leaf| {
            leaf.as_ref()
                .map(|leaf| std::str::from_utf8(&leaf.identity).unwrap())
        })
        .collect();
    let want: Vec<Option<&str>> = e["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(Value::as_str)
        .collect();
    assert_eq!(members, want, "{at}: members");
    assert_eq!(
        group.epoch_authenticator(),
        hex(e, "epoch_authenticator_hex"),
        "{at}: epoch authenticator"
    );
    for x in e["exporters"].as_array().unwrap() {
        assert_eq!(
            group
                .exporter(string(x, "label"), &hex(x, "context_hex"), int(x, "length"))
                .unwrap(),
            hex(x, "out_hex"),
            "{at}: exporter {}",
            string(x, "label")
        );
    }
}

#[test]
fn audience_envelopes() {
    for v in cases("mls-audience.json") {
        let public = audience::SUITE
            .kem_public_key(&hex(&v, "private_key_hex"))
            .unwrap();
        assert_eq!(
            public,
            hex(&v, "public_key_hex"),
            "{}: public key from seed",
            name(&v)
        );
        let opened = audience::open(
            &hex(&v, "envelope_hex"),
            &hex(&v, "private_key_hex"),
            &hex(&v, "group_id_hex"),
            int(&v, "epoch") as u64,
        );
        assert_eq!(class(&opened), expected_error(&v), "{}", name(&v));
        if let Ok(base) = opened {
            assert_eq!(base, hex(&v, "base_key_hex"), "{}", name(&v));
        }
    }
}

#[test]
fn round_trip() {
    {
        let suite = CipherSuite::MLDSA;
        let alice =
            Group::create(b"g", &KeyPackageBundle::generate("alice", suite).unwrap()).unwrap();
        let bob = KeyPackageBundle::generate("bob", suite).unwrap();
        let carol = KeyPackageBundle::generate("carol", suite).unwrap();
        let add = alice
            .commit(&[bob.key_package.clone(), carol.key_package.clone()], &[])
            .unwrap();
        let welcome = Welcome::decode(&add.welcome.as_ref().unwrap().encode()).unwrap();
        let bob_group = Group::join(&welcome, &bob).unwrap();
        let carol_group = Group::join(&welcome, &carol).unwrap();
        let alice = add.next;
        for g in [&bob_group, &carol_group] {
            assert_eq!(
                g.epoch_authenticator(),
                alice.epoch_authenticator(),
                "{suite}"
            );
            assert_eq!(
                g.exporter(moqom_mls::SFRAME_EXPORTER_LABEL, &[], 16)
                    .unwrap(),
                alice
                    .exporter(moqom_mls::SFRAME_EXPORTER_LABEL, &[], 16)
                    .unwrap()
            );
        }

        let remove = bob_group.commit(&[], &[0]).unwrap();
        let message = CommitMessage::decode(&remove.message.encode()).unwrap();
        assert!(
            matches!(alice.process(&message), Ok(Processed::Removed)),
            "{suite}: alice was not removed"
        );
        let Ok(Processed::Advanced(carol_group)) = carol_group.process(&message) else {
            panic!("{suite}: carol did not follow")
        };
        assert_eq!(
            carol_group.epoch_authenticator(),
            remove.next.epoch_authenticator()
        );
        assert_eq!(carol_group.members().len(), 3);
        assert!(matches!(
            carol_group.process(&message),
            Err(Error::WrongEpoch { .. })
        ));
    }

    let (private, public) = audience::generate_key_pair().unwrap();
    let envelope = audience::seal(&[7; 32], &public, b"g", 3).unwrap();
    assert_eq!(
        audience::open(&envelope, &private, b"g", 3).unwrap(),
        [7; 32]
    );
    assert_eq!(
        audience::open(&envelope, &private, b"g", 4),
        Err(Error::DecryptionFailed)
    );
    assert!(audience::seal(&[7; 32], &public[..32], b"g", 3).is_err());
}

#[test]
fn exporter_length_limit() {
    {
        let suite = CipherSuite::MLDSA;
        let group =
            Group::create(b"g", &KeyPackageBundle::generate("alice", suite).unwrap()).unwrap();
        let max = 255 * suite.hash_length();
        assert_eq!(group.exporter("x", &[], max).unwrap().len(), max, "{suite}");
        let over = group.exporter("x", &[], max + 1);
        assert_eq!(
            over,
            Err(Error::InvalidLength {
                length: max + 1,
                max
            }),
            "{suite}"
        );
        assert_eq!(class(&over), "invalid-length");
        assert_eq!(
            class(&group.exporter("x", &[], usize::MAX)),
            "invalid-length",
            "{suite}"
        );
    }
}

#[test]
fn expand_with_label_length_limit() {
    {
        let suite = CipherSuite::MLDSA;
        let secret = vec![1; suite.hash_length()];
        let max = 255 * suite.hash_length();
        for length in [0, max] {
            assert_eq!(
                suite
                    .expand_with_label(&secret, "x", &[], length)
                    .unwrap()
                    .len(),
                length,
                "{suite}"
            );
        }
        let over = suite.expand_with_label(&secret, "x", &[], max + 1);
        assert_eq!(
            over,
            Err(Error::InvalidLength {
                length: max + 1,
                max
            }),
            "{suite}"
        );
        assert_eq!(class(&over), "invalid-length");
        for length in [1 << 16, usize::MAX] {
            assert_eq!(
                class(&suite.expand_with_label(&secret, "x", &[], length)),
                "invalid-length",
                "{suite}"
            );
        }
    }
}

#[test]
fn debug_redacts_secrets() {
    let alice = KeyPackageBundle::generate("alice", CipherSuite::FOUNDING).unwrap();
    let bob = KeyPackageBundle::generate("bob", CipherSuite::FOUNDING).unwrap();
    let add = Group::create(b"g", &alice)
        .unwrap()
        .commit(std::slice::from_ref(&bob.key_package), &[])
        .unwrap();
    let bob_group = Group::join(add.welcome.as_ref().unwrap(), &bob).unwrap();
    let update = add.next.commit(&[], &[]).unwrap();
    let processed = bob_group.process(&update.message).unwrap();

    let secrets = [
        format!("{:?}", alice.private_keys().2),
        format!("{:?}", bob.private_keys().1),
        format!("{:?}", bob.private_keys().2),
        format!("{:?}", add.next.epoch_authenticator()),
        format!("{:?}", add.next.exporter("x", &[], 32).unwrap()),
    ];
    for printed in [format!("{add:?}"), format!("{processed:?}")] {
        assert!(printed.contains("<redacted>"), "{printed}");
        for secret in &secrets {
            assert!(!printed.contains(secret.trim_matches(['[', ']'])));
        }
    }
    assert!(format!("{processed:?}").contains("Advanced"));
}

#[test]
fn other_suites_are_refused() {
    for id in [0x0001, 0xF0A1, 0xF0AA, 0xF0AB] {
        let suite = CipherSuite(id);
        assert!(!suite.is_known(), "{id:#06x}");
        assert!(
            KeyPackageBundle::generate("alice", suite).is_err(),
            "{id:#06x}"
        );
    }
}
