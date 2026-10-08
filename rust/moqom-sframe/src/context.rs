// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

use crate::{CipherSuite, DEFAULT_REPLAY_WINDOW, Error, Key, Metadata, Receiver, Sender};

/// Seals and opens MoQ objects under one key. Sealing owns the counter and
/// opening keeps the replay window, as [`Sender`] and [`Receiver`] do; a room
/// with a key per sender uses those directly.
#[derive(Debug)]
pub struct Context {
    sender: Sender,
    receiver: Receiver,
}

impl Context {
    /// Derive the key for `key_id` from `base_key`, with the default replay window.
    #[must_use]
    pub fn new(suite: CipherSuite, key_id: u64, base_key: &[u8]) -> Self {
        Self::with_replay_window(suite, key_id, base_key, DEFAULT_REPLAY_WINDOW)
    }

    #[must_use]
    pub fn with_replay_window(
        suite: CipherSuite,
        key_id: u64,
        base_key: &[u8],
        replay_window: u64,
    ) -> Self {
        let receiver = Receiver::new(replay_window);
        receiver.add(Key::new(key_id, base_key, suite));
        Self {
            sender: Sender::new(Key::new(key_id, base_key, suite)),
            receiver,
        }
    }

    /// The SFrame object: header, ciphertext, tag.
    pub fn seal(&self, payload: &[u8], metadata: &Metadata) -> Result<Vec<u8>, Error> {
        self.sender.protect_object(payload, metadata)
    }

    /// The payload, if `object` authenticates under this key with `metadata`
    /// and its counter has not been seen.
    pub fn open(&self, object: &[u8], metadata: &Metadata) -> Result<Vec<u8>, Error> {
        self.receiver.unprotect_object(object, metadata)
    }
}
