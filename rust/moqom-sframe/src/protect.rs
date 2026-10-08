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

/// What [`Receiver::new`] is usually given. Windows above 65536 behave as
/// 65536.
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

/// The largest window honoured, so a configuration mistake cannot ask for
/// gigabytes of bitmap per KID. 8 KiB per KID at the cap.
pub(crate) const MAX_REPLAY_WINDOW: u64 = 1 << 16;

/// A sliding window of counters already seen.
///
/// The bitmap is a ring of 64-bit words indexed by counter, with one word more
/// than the window needs: advancing clears whole words, and the spare word is
/// what keeps that from clearing a counter still inside the window.
#[derive(Clone, Debug)]
pub(crate) struct ReplayWindow {
    size: u64,
    highest: Option<u64>,
    words: Vec<u64>,
}

impl ReplayWindow {
    pub(crate) fn new(size: u64) -> Self {
        let size = size.min(MAX_REPLAY_WINDOW);
        Self {
            size,
            highest: None,
            words: vec![0; usize::try_from(size.div_ceil(64)).unwrap_or(0) + 1],
        }
    }

    fn slot(&self, counter: u64) -> (usize, u64) {
        let index = (counter / 64) % self.words.len() as u64;
        (usize::try_from(index).unwrap_or(0), 1 << (counter % 64))
    }

    pub(crate) fn accepts(&self, counter: u64) -> bool {
        let Some(highest) = self.highest else {
            return true;
        };
        if counter > highest {
            return true;
        }
        if highest - counter >= self.size {
            return false;
        }
        let (word, bit) = self.slot(counter);
        self.words[word] & bit == 0
    }

    pub(crate) fn record(&mut self, counter: u64) {
        match self.highest {
            None => self.highest = Some(counter),
            Some(highest) if counter > highest => {
                let length = self.words.len() as u64;
                if counter / 64 - highest / 64 >= length {
                    self.words.fill(0);
                } else {
                    for block in highest / 64 + 1..=counter / 64 {
                        self.words[usize::try_from(block % length).unwrap_or(0)] = 0;
                    }
                }
                self.highest = Some(counter);
            }
            Some(highest) if highest - counter >= self.size => return,
            Some(_) => {}
        }
        let (word, bit) = self.slot(counter);
        self.words[word] |= bit;
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_REPLAY_WINDOW, ReplayWindow};

    #[test]
    fn window_across_words() {
        let mut window = ReplayWindow::new(1024);
        for counter in (3977..=5000).rev() {
            assert!(window.accepts(counter), "{counter}");
            window.record(counter);
        }
        assert!((3976..=5000).all(|counter| !window.accepts(counter)));
        window.record(5063);
        assert!(window.accepts(5001) && !window.accepts(4040) && !window.accepts(4039));
        window.record(5000 + 2048);
        assert!(window.accepts(6100) && !window.accepts(5063));
        assert_eq!(ReplayWindow::new(u64::MAX).size, MAX_REPLAY_WINDOW);
    }
}
