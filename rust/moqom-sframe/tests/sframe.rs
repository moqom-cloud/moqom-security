// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

//! Behaviour the vectors do not pin: counter ownership, rekeying, key removal
//! and resolution.

use std::collections::HashSet;

use moqom_sframe::{
    CipherSuite, Error, Header, Key, Metadata, Property, Receiver, Sender, epoch_tag, mls_key_id,
};

fn pair(key_id: u64) -> (Sender, Receiver) {
    let receiver = Receiver::default();
    receiver.add(Key::new(key_id, &[0x2A; 32], CipherSuite::default()));
    (
        Sender::new(Key::new(key_id, &[0x2A; 32], CipherSuite::default())),
        receiver,
    )
}

#[test]
fn counters_never_repeat() {
    let (sender, receiver) = pair(1);
    let mut counters = HashSet::new();
    for i in 0..200u8 {
        let sealed = sender.protect(&[i], &[]).unwrap();
        counters.insert(Header::read(&sealed).unwrap().0.counter);
        assert_eq!(receiver.unprotect(&sealed, &[]).unwrap(), [i]);
    }
    assert_eq!(counters.len(), 200);
    assert_eq!(sender.issued_counters(), 200);
}

#[test]
fn no_key_refuses() {
    let sender = Sender::empty();
    assert_eq!(sender.protect(&[1], &[]), Err(Error::NoKey));
    sender.rekey(Key::new(17, &[1; 16], CipherSuite::Aes128GcmSha256));
    let sealed = sender.protect(&[1], &[]).unwrap();
    assert_eq!(
        Header::read(&sealed).unwrap().0,
        Header {
            key_id: 17,
            counter: 0
        }
    );
    sender.clear_key();
    assert!(sender.key().is_none());
    assert_eq!(sender.protect(&[1], &[]), Err(Error::NoKey));
}

#[test]
fn unknown_key_resolver_and_removal() {
    let base = [0x33; 32];
    let kid = mls_key_id(2, 21);
    let sealed = Sender::new(Key::new(kid, &base, CipherSuite::default()))
        .protect(&[7], &[])
        .unwrap();

    let receiver = Receiver::default();
    assert_eq!(
        receiver.unprotect(&sealed, &[]),
        Err(Error::UnknownKey(kid))
    );

    receiver.set_resolver(Some(move |id| {
        (epoch_tag(id) == 5).then(|| Key::new(id, &base, CipherSuite::default()))
    }));
    assert_eq!(receiver.unprotect(&sealed, &[]).unwrap(), [7]);
    assert_eq!(receiver.key_ids(), [kid]);
    assert_eq!(
        receiver.unprotect(&sealed, &[]),
        Err(Error::Replay { counter: 0 })
    );

    receiver.set_resolver(None::<fn(u64) -> Option<Key>>);
    receiver.remove(kid);
    assert_eq!(
        receiver.unprotect(&sealed, &[]),
        Err(Error::UnknownKey(kid))
    );
}

#[test]
fn metadata_overloads_bind_the_same_bytes() {
    let (sender, receiver) = pair(3);
    let metadata = Metadata {
        group: 5,
        object: 2,
        priority: 64,
        properties: vec![Property::integer(0x78, 1000)],
    };
    let sealed = sender.protect_object(&[0xAB], &metadata).unwrap();
    assert_eq!(
        receiver
            .unprotect(&sealed, &metadata.encode().unwrap())
            .unwrap(),
        [0xAB]
    );

    let invalid = Metadata {
        properties: vec![Property::bytes(0x78, vec![])],
        ..Metadata::default()
    };
    assert_eq!(
        sender.protect_object(&[0xAB], &invalid),
        Err(Error::InvalidMetadata)
    );
}

#[test]
fn unsupported_suite() {
    assert_eq!(
        CipherSuite::try_from(0x0001),
        Err(Error::UnsupportedSuite(1))
    );
}
