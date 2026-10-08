// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use crate::{Error, Header, Key, Metadata};

/// Encrypts, owning the counter: there is no API that lets a caller choose one,
/// because a repeated GCM nonce leaks the XOR of two plaintexts and the
/// authentication subkey.
///
/// One sender per (key, media stream). Two senders under one key will collide.
#[derive(Debug, Default)]
pub struct Sender {
    state: Mutex<(Option<Arc<Key>>, u64)>,
}

impl Sender {
    #[must_use]
    pub fn new(key: Key) -> Self {
        Self {
            state: Mutex::new((Some(Arc::new(key)), 0)),
        }
    }

    /// A sender with no key, which refuses to encrypt until [`Sender::rekey`].
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// The key in force, if any.
    #[must_use]
    pub fn key(&self) -> Option<Arc<Key>> {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .0
            .clone()
    }

    /// Counters issued under the current key.
    #[must_use]
    pub fn issued_counters(&self) -> u64 {
        self.state.lock().unwrap_or_else(PoisonError::into_inner).1
    }

    /// Switch to a new key and restart the counter.
    pub fn rekey(&self, key: Key) {
        *self.state.lock().unwrap_or_else(PoisonError::into_inner) = (Some(Arc::new(key)), 0);
    }

    /// Go back to refusing to encrypt.
    pub fn clear_key(&self) {
        *self.state.lock().unwrap_or_else(PoisonError::into_inner) = (None, 0);
    }

    /// Encrypt one MoQ object, binding its metadata into the tag.
    pub fn protect_object(&self, plaintext: &[u8], metadata: &Metadata) -> Result<Vec<u8>, Error> {
        self.protect(plaintext, &metadata.encode()?)
    }

    /// Encrypt one frame. `metadata` is authenticated and not encrypted.
    pub fn protect(&self, plaintext: &[u8], metadata: &[u8]) -> Result<Vec<u8>, Error> {
        let (key, issued) = {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            let key = state.0.clone().ok_or(Error::NoKey)?;
            let issued = state.1;
            if issued == u64::MAX {
                return Err(Error::CounterExhausted);
            }
            state.1 += 1;
            (key, issued)
        };
        let mut out = Header {
            key_id: key.key_id(),
            counter: issued,
        }
        .encode();
        let mut aad = out.clone();
        aad.extend_from_slice(metadata);
        out.extend(key.seal(plaintext, issued, &aad)?);
        Ok(out)
    }
}

/// What [`Receiver::new`] is usually given. The bitmap is one word, so any
/// window above 64 behaves as 64.
pub const DEFAULT_REPLAY_WINDOW: u64 = 1024;

type Resolver = Box<dyn Fn(u64) -> Option<Key> + Send + Sync>;

/// Decrypts, holding keys for any number of KIDs and rejecting replays.
pub struct Receiver {
    window: u64,
    state: Mutex<ReceiverState>,
    resolver: Mutex<Option<Arc<Resolver>>>,
}

#[derive(Default)]
struct ReceiverState {
    keys: HashMap<u64, Arc<Key>>,
    seen: HashMap<u64, ReplayWindow>,
}

impl std::fmt::Debug for Receiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Receiver")
            .field("window", &self.window)
            .field("key_ids", &self.key_ids())
            .finish()
    }
}

impl Default for Receiver {
    fn default() -> Self {
        Self::new(DEFAULT_REPLAY_WINDOW)
    }
}

impl Receiver {
    /// A receiver tolerating reordering up to `window` counters.
    #[must_use]
    pub fn new(window: u64) -> Self {
        Self {
            window,
            state: Mutex::default(),
            resolver: Mutex::default(),
        }
    }

    /// Asked for a key the receiver does not hold, for schemes where a receiver
    /// derives a sender's key rather than being sent it. A key it returns is
    /// added as though by [`Receiver::add`].
    pub fn set_resolver(
        &self,
        resolve: Option<impl Fn(u64) -> Option<Key> + Send + Sync + 'static>,
    ) {
        *self.resolver.lock().unwrap_or_else(PoisonError::into_inner) =
            resolve.map(|r| Arc::new(Box::new(r) as Resolver));
    }

    /// Load a key, resetting its replay window.
    pub fn add(&self, key: Key) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state
            .seen
            .insert(key.key_id(), ReplayWindow::new(self.window));
        state.keys.insert(key.key_id(), Arc::new(key));
    }

    /// Forget a key: anything still in flight under it stops decrypting.
    pub fn remove(&self, key_id: u64) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.keys.remove(&key_id);
        state.seen.remove(&key_id);
    }

    /// The KIDs currently loaded.
    #[must_use]
    pub fn key_ids(&self) -> Vec<u64> {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .keys
            .keys()
            .copied()
            .collect()
    }

    /// Decrypt one MoQ object against the metadata it arrived with.
    pub fn unprotect_object(&self, data: &[u8], metadata: &Metadata) -> Result<Vec<u8>, Error> {
        self.unprotect(data, &metadata.encode()?)
    }

    /// Decrypt one frame.
    pub fn unprotect(&self, data: &[u8], metadata: &[u8]) -> Result<Vec<u8>, Error> {
        let (header, length) = Header::read(data)?;

        let held = self
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .keys
            .contains_key(&header.key_id);
        if !held {
            let resolver = self
                .resolver
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            if let Some(key) = resolver.and_then(|resolve| resolve(header.key_id))
                && key.key_id() == header.key_id
            {
                let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
                if !state.keys.contains_key(&header.key_id) {
                    state
                        .seen
                        .insert(header.key_id, ReplayWindow::new(self.window));
                    state.keys.insert(header.key_id, Arc::new(key));
                }
            }
        }

        let key = {
            let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            let key = state
                .keys
                .get(&header.key_id)
                .cloned()
                .ok_or(Error::UnknownKey(header.key_id))?;
            if !state
                .seen
                .get(&header.key_id)
                .is_none_or(|w| w.accepts(header.counter))
            {
                return Err(Error::Replay {
                    counter: header.counter,
                });
            }
            key
        };

        let mut aad = data[..length].to_vec();
        aad.extend_from_slice(metadata);
        let plaintext = key.open(&data[length..], header.counter, &aad)?;

        // Recorded only after authentication, so a forged object cannot knock
        // out the real one behind it.
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if state
            .keys
            .get(&header.key_id)
            .is_some_and(|k| Arc::ptr_eq(k, &key))
            && let Some(window) = state.seen.get_mut(&header.key_id)
        {
            window.record(header.counter);
        }
        Ok(plaintext)
    }
}

/// A sliding window of counters already seen.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ReplayWindow {
    size: u64,
    highest: Option<u64>,
    bitmap: u64,
}

impl ReplayWindow {
    pub(crate) fn new(size: u64) -> Self {
        Self {
            size: size.min(64),
            highest: None,
            bitmap: 0,
        }
    }

    pub(crate) fn accepts(&self, counter: u64) -> bool {
        let Some(highest) = self.highest else {
            return true;
        };
        if counter > highest {
            return true;
        }
        let age = highest - counter;
        age < self.size && self.bitmap & (1 << age) == 0
    }

    pub(crate) fn record(&mut self, counter: u64) {
        match self.highest {
            None => {
                self.highest = Some(counter);
                self.bitmap = 1;
            }
            Some(highest) if counter > highest => {
                let shift = counter - highest;
                self.bitmap = if shift >= 64 { 0 } else { self.bitmap << shift };
                self.bitmap |= 1;
                self.highest = Some(counter);
            }
            Some(highest) => {
                let age = highest - counter;
                if age < 64 {
                    self.bitmap |= 1 << age;
                }
            }
        }
    }
}
