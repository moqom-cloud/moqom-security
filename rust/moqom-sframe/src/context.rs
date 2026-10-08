// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

use crate::{CipherSuite, DEFAULT_REPLAY_WINDOW, Error, Key, Metadata, Receiver, Sender};

/// Seals and opens MoQ objects under one key. Sealing owns the counter and
/// opening keeps the replay window, as [`Sender`] and [`Receiver`] do; a room
/// with a key per sender uses those directly.
///
/// The counter starts at 0 for every new context. Never create two contexts
/// that seal under the same base key and KID, including one after a restart;
/// see [`Sender`].
#[derive(Debug)]
pub struct Context {
    key: Key,
    sender: Sender,
    receiver: Receiver,
}

impl Context {
    /// Derive the key for `key_id` from `base_key`, with the default replay window.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidBaseKey`] unless `base_key` is the suite's
    /// [`CipherSuite::key_length`].
    pub fn new(suite: CipherSuite, key_id: u64, base_key: &[u8]) -> Result<Self, Error> {
        Self::with_replay_window(suite, key_id, base_key, DEFAULT_REPLAY_WINDOW)
    }

    /// [`Context::new`] with a replay window of its own.
    ///
    /// # Errors
    ///
    /// As [`Context::new`].
    pub fn with_replay_window(
        suite: CipherSuite,
        key_id: u64,
        base_key: &[u8],
        replay_window: u64,
    ) -> Result<Self, Error> {
        let key = Key::new(key_id, base_key, suite)?;
        let receiver = Receiver::new(replay_window);
        receiver.add(key.clone());
        Ok(Self {
            sender: Sender::new(key.clone()),
            key,
            receiver,
        })
    }

    /// The context's key.
    #[must_use]
    pub const fn key(&self) -> &Key {
        &self.key
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
