// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use crate::{Error, Header, Key, Metadata};

/// Encrypts, owning the counter: there is no API that lets a caller choose one,
/// because a repeated GCM nonce leaks the XOR of two plaintexts and the
/// authentication subkey.
///
/// One sender per key. Two senders under one key will collide. The counter is
/// held in memory and starts at 0 for every sender and every key, and a key is
/// fixed by its base key, KID and suite, so deriving the same one again — in a
/// second sender, on a second device, or in the same process after a restart —
/// repeats nonces. Every new sender needs a base key or KID that has never
/// sealed before: a new MLS epoch, or a fresh random KID.
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

    /// Encrypt one MoQ object, binding its track, position and properties into
    /// the tag.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidMetadata`], [`Error::NoKey`] or [`Error::CounterExhausted`].
    pub fn protect_object(&self, plaintext: &[u8], metadata: &Metadata) -> Result<Vec<u8>, Error> {
        self.protect_raw(plaintext, &metadata.encode()?)
    }

    /// Encrypt one frame with arbitrary AAD after the header, as RFC 9605's own
    /// vectors do. Not for MoQ objects, which bind their track through
    /// [`Sender::protect_object`].
    ///
    /// # Errors
    ///
    /// [`Error::NoKey`] or [`Error::CounterExhausted`].
    pub fn protect_raw(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
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
        let mut full = out.clone();
        full.extend_from_slice(aad);
        out.extend(key.seal(plaintext, issued, &full)?);
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
    /// added as though by [`Receiver::add`], once an object has authenticated
    /// under it; a key for any other KID is ignored. Called without the
    /// receiver's lock held, possibly concurrently.
    pub fn set_resolver(&self, resolve: impl Fn(u64) -> Option<Key> + Send + Sync + 'static) {
        *self.resolver.lock().unwrap_or_else(PoisonError::into_inner) =
            Some(Arc::new(Box::new(resolve) as Resolver));
    }

    /// Remove the resolver.
    pub fn clear_resolver(&self) {
        *self.resolver.lock().unwrap_or_else(PoisonError::into_inner) = None;
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

    /// Decrypt one MoQ object against the track, position and properties it
    /// arrived with.
    ///
    /// # Errors
    ///
    /// Any [`Error`] but [`Error::NoKey`], [`Error::CounterExhausted`] and the
    /// key errors, in the order the checks run: metadata, header, key, replay
    /// window, tag.
    pub fn unprotect_object(&self, data: &[u8], metadata: &Metadata) -> Result<Vec<u8>, Error> {
        self.unprotect_raw(data, &metadata.encode()?)
    }

    /// Decrypt one frame sealed by [`Sender::protect_raw`].
    ///
    /// # Errors
    ///
    /// As [`Receiver::unprotect_object`], less the metadata check.
    pub fn unprotect_raw(&self, data: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
        let (header, length) = Header::read(data)?;
        let kid = header.key_id;
        let replay = Error::Replay {
            counter: header.counter,
        };

        let held = self
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .keys
            .get(&kid)
            .cloned();
        // A resolved key is held aside until an object authenticates under it,
        // so objects under made-up KIDs cannot fill the receiver with keys.
        let (key, resolved) = match held {
            Some(key) => (key, None),
            None => {
                let resolver = self
                    .resolver
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .clone();
                let key = resolver
                    .and_then(|resolve| resolve(kid))
                    .filter(|key| key.key_id() == kid)
                    .ok_or(Error::UnknownKey(kid))?;
                (Arc::new(key), Some(ReplayWindow::new(self.window)))
            }
        };

        if resolved.is_none() {
            let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            if !state
                .seen
                .get(&kid)
                .is_none_or(|w| w.accepts(header.counter))
            {
                return Err(replay);
            }
        }

        let mut full = data[..length].to_vec();
        full.extend_from_slice(aad);
        let plaintext = key.open(&data[length..], header.counter, &full)?;

        // Recorded only after authentication, so a forged object cannot knock
        // out the real one behind it. Checked again, because another copy of
        // this object may have opened meanwhile.
        let was_resolved = resolved.is_some();
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let ReceiverState { keys, seen } = &mut *state;
        if let Some(window) = resolved
            && !keys.contains_key(&kid)
        {
            keys.insert(kid, Arc::clone(&key));
            seen.insert(kid, window);
        }
        if (was_resolved || keys.get(&kid).is_some_and(|k| Arc::ptr_eq(k, &key)))
            && let Some(window) = seen.get_mut(&kid)
        {
            if !window.accepts(header.counter) {
                return Err(replay);
            }
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
