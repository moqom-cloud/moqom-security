// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

//! Behaviour the vectors do not pin: counter ownership, rekeying, key removal
//! and resolution, base key lengths and track binding.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use moqom_sframe::{
    CipherSuite, Context, Error, Header, Key, Metadata, Property, Receiver, Sender, Track,
    epoch_tag, mls_key_id,
};

fn key(key_id: u64, base: &[u8]) -> Key {
    Key::new(key_id, base, CipherSuite::default()).unwrap()
}

fn pair(key_id: u64) -> (Sender, Receiver) {
    let key = key(key_id, &[0x2A; 32]);
    let receiver = Receiver::default();
    receiver.add(key.clone());
    (Sender::new(key), receiver)
}

fn alice() -> Track {
    Track::new(["moqom", "demo", "alice"], "video")
}

#[test]
fn counters_never_repeat() {
    let (sender, receiver) = pair(1);
    let mut counters = HashSet::new();
    for i in 0..200u8 {
        let sealed = sender.protect_raw(&[i], &[]).unwrap();
        counters.insert(Header::read(&sealed).unwrap().0.counter);
        assert_eq!(receiver.unprotect_raw(&sealed, &[]).unwrap(), [i]);
    }
    assert_eq!(counters.len(), 200);
    assert_eq!(sender.issued_counters(), 200);
}

#[test]
fn no_key_refuses() {
    let sender = Sender::empty();
    assert_eq!(sender.protect_raw(&[1], &[]), Err(Error::NoKey));
    sender.rekey(Key::new(17, &[1; 16], CipherSuite::Aes128GcmSha256).unwrap());
    let sealed = sender.protect_raw(&[1], &[]).unwrap();
    assert_eq!(
        Header::read(&sealed).unwrap().0,
        Header {
            key_id: 17,
            counter: 0
        }
    );
    sender.clear_key();
    assert!(sender.key().is_none());
    assert_eq!(sender.protect_raw(&[1], &[]), Err(Error::NoKey));
}

#[test]
fn unknown_key_resolver_and_removal() {
    let base = [0x33; 32];
    let kid = mls_key_id(2, 21);
    let sealed = Sender::new(key(kid, &base)).protect_raw(&[7], &[]).unwrap();

    let receiver = Receiver::default();
    assert_eq!(
        receiver.unprotect_raw(&sealed, &[]),
        Err(Error::UnknownKey(kid))
    );

    receiver.set_resolver(move |id| (epoch_tag(id) == 5).then(|| key(id, &base)));
    assert_eq!(receiver.unprotect_raw(&sealed, &[]).unwrap(), [7]);
    assert_eq!(receiver.key_ids(), [kid]);
    assert_eq!(
        receiver.unprotect_raw(&sealed, &[]),
        Err(Error::Replay { counter: 0 })
    );

    receiver.clear_resolver();
    receiver.remove(kid);
    assert_eq!(
        receiver.unprotect_raw(&sealed, &[]),
        Err(Error::UnknownKey(kid))
    );
}

#[test]
fn resolved_key_kept_only_after_authentication() {
    let base = [0x33; 32];
    let receiver = Receiver::default();
    receiver.set_resolver(move |id| Some(key(id, &base)));
    let mut forged = Sender::new(key(40, &base)).protect_raw(&[7], &[]).unwrap();
    *forged.last_mut().unwrap() ^= 1;
    assert_eq!(
        receiver.unprotect_raw(&forged, &[]),
        Err(Error::AuthenticationFailure)
    );
    assert!(receiver.key_ids().is_empty());
}

#[test]
fn concurrent_duplicates_open_once() {
    let (sender, _) = pair(1);
    let sealed = Arc::new(sender.protect_raw(&[1], &[]).unwrap());
    for _ in 0..50 {
        let receiver = Arc::new(pair(1).1);
        let opened = Arc::new(AtomicUsize::new(0));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let (receiver, sealed, opened) = (
                    Arc::clone(&receiver),
                    Arc::clone(&sealed),
                    Arc::clone(&opened),
                );
                std::thread::spawn(move || {
                    if receiver.unprotect_raw(&sealed, &[]).is_ok() {
                        opened.fetch_add(1, Ordering::Relaxed);
                    }
                })
            })
            .collect();
        threads.into_iter().for_each(|t| t.join().unwrap());
        assert_eq!(opened.load(Ordering::Relaxed), 1);
    }
}

#[test]
fn metadata_overloads_bind_the_same_bytes() {
    let (sender, receiver) = pair(3);
    let metadata = Metadata {
        track: alice(),
        group: 5,
        object: 2,
        priority: 64,
        properties: vec![Property::integer(0x78, 1000)],
    };
    let sealed = sender.protect_object(&[0xAB], &metadata).unwrap();
    assert_eq!(
        receiver
            .unprotect_raw(&sealed, &metadata.encode().unwrap())
            .unwrap(),
        [0xAB]
    );

    let invalid = Metadata {
        properties: vec![Property::bytes(0x78, vec![])],
        ..metadata
    };
    assert_eq!(
        sender.protect_object(&[0xAB], &invalid),
        Err(Error::InvalidMetadata)
    );
}

#[test]
fn track_is_bound() {
    let (sender, receiver) = pair(1);
    let metadata = Metadata {
        track: alice(),
        group: 5,
        object: 2,
        priority: 64,
        properties: vec![],
    };
    let sealed = sender.protect_object(&[0xAB], &metadata).unwrap();
    for track in [
        Track::new(["moqom", "demo", "bob"], "video"),
        Track::new(["moqom", "demoalice"], "video"),
    ] {
        let moved = Metadata {
            track,
            ..metadata.clone()
        };
        assert_eq!(
            receiver.unprotect_object(&sealed, &moved),
            Err(Error::AuthenticationFailure)
        );
    }
    let moved = Metadata {
        track: Track::new(Vec::<&str>::new(), "video"),
        ..metadata.clone()
    };
    assert_eq!(
        receiver.unprotect_object(&sealed, &moved),
        Err(Error::InvalidMetadata)
    );
    assert_eq!(
        receiver.unprotect_object(&sealed, &metadata).unwrap(),
        [0xAB]
    );
}

#[test]
fn rekey_same_key_resumes() {
    let (key5, key6) = (key(5, &[0x2A; 32]), key(6, &[0x2A; 32]));
    let sender = Sender::new(key5.clone());
    let mut counters = vec![];
    let mut seal = |s: &Sender| {
        counters.push(
            Header::read(&s.protect_raw(&[], &[]).unwrap())
                .unwrap()
                .0
                .counter,
        )
    };
    seal(&sender);
    seal(&sender);
    sender.rekey(key5.clone());
    seal(&sender);
    sender.clear_key();
    sender.rekey(key6);
    seal(&sender);
    sender.rekey(key5);
    seal(&sender);
    assert_eq!(counters, [0, 1, 2, 0, 3]);
}

#[test]
fn base_key_length() {
    for suite in CipherSuite::ALL {
        for length in [0, 16, 32, 48] {
            let base = vec![0; length];
            let valid = length == suite.key_length();
            assert_eq!(Key::new(1, &base, suite).is_ok(), valid);
            assert_eq!(Context::new(suite, 1, &base).is_ok(), valid);
            if !valid {
                assert_eq!(
                    Key::new(1, &base, suite).unwrap_err(),
                    Error::InvalidBaseKey
                );
            }
        }
    }
    assert_eq!(Error::InvalidBaseKey.class(), "invalid_base_key");
    let context = Context::new(CipherSuite::default(), 9, &[0; 32]).unwrap();
    assert_eq!(context.key().key_id(), 9);
}

#[test]
fn unsupported_suite() {
    assert_eq!(
        CipherSuite::try_from(0x0001),
        Err(Error::UnsupportedSuite(1))
    );
}
