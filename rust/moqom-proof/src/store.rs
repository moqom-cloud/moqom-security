// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::Mutex;
use std::time::SystemTime;

use crate::Error;

/// Remembers which proof nonces have been spent.
///
/// A store shared by every checker of one certificate is what makes a proof
/// single-use across connections.
pub trait NonceStore: Send + Sync {
    /// Record `nonce` as spent until `until`.
    ///
    /// Called only for a proof that passed every other check.
    ///
    /// # Errors
    /// [`Error::Replayed`] if it already is; [`Error::Overloaded`] if the store
    /// cannot remember another.
    fn spend(&self, nonce: &str, until: SystemTime, now: SystemTime) -> Result<(), Error>;
}

impl<S: NonceStore + ?Sized> NonceStore for std::sync::Arc<S> {
    fn spend(&self, nonce: &str, until: SystemTime, now: SystemTime) -> Result<(), Error> {
        (**self).spend(nonce, until, now)
    }
}

/// How many unexpired nonces a [`MemoryNonceStore`] holds by default: one per
/// session in a token lifetime, far past what one relay serves, and under ten
/// megabytes.
pub const DEFAULT_CAPACITY: usize = 100_000;

/// An in-process [`NonceStore`].
///
/// It forgets everything on restart, so a proof captured and never delivered
/// could be replayed after one, within its window and its token's lifetime.
/// When full it refuses rather than evicts: evicting would choose which proof
/// becomes replayable.
#[derive(Debug)]
pub struct MemoryNonceStore {
    capacity: usize,
    spent: Mutex<HashMap<String, SystemTime>>,
}

impl Default for MemoryNonceStore {
    fn default() -> Self {
        Self::new(DEFAULT_CAPACITY)
    }
}

impl MemoryNonceStore {
    /// A store holding up to `capacity` unexpired nonces.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            spent: Mutex::new(HashMap::new()),
        }
    }

    /// How many nonces are held, for tests and metrics.
    #[must_use]
    pub fn remembered(&self) -> usize {
        self.spent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }
}

impl NonceStore for MemoryNonceStore {
    /// Expired entries are swept when the store is full, the only moment they
    /// can matter.
    fn spend(&self, nonce: &str, until: SystemTime, now: SystemTime) -> Result<(), Error> {
        let mut spent = self
            .spent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if spent.len() >= self.capacity {
            spent.retain(|_, expires| *expires > now);
        }
        if spent.len() >= self.capacity {
            return Err(Error::Overloaded);
        }
        match spent.entry(nonce.to_owned()) {
            Entry::Occupied(_) => Err(Error::Replayed),
            Entry::Vacant(slot) => {
                slot.insert(until);
                Ok(())
            }
        }
    }
}
