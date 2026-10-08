// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

package proof

import (
	"fmt"
	"sync"
	"time"
)

// NonceStore remembers which proof nonces have been spent.
//
// Spend records nonce as spent until until, returning [ErrReplayed] if it
// already is and [ErrOverloaded] if it cannot remember another. It is called
// only for a proof that passed every other check, with until no earlier than
// one second past the end of that proof's window. A store shared by every
// checker of one certificate is what makes a proof single-use across
// connections. Spend may be called concurrently, and must check and record a
// nonce as one step.
type NonceStore interface {
	Spend(nonce string, until, now time.Time) error
}

// DefaultCapacity is how many unexpired nonces [NewDefaultMemoryNonceStore]
// holds: one per session in a token lifetime, far past what one relay serves.
const DefaultCapacity = 100_000

// MemoryNonceStore is an in-process [NonceStore]. Make one with
// [NewMemoryNonceStore] or [NewDefaultMemoryNonceStore]; the zero value
// refuses every nonce with [ErrConfiguration].
//
// It forgets everything on restart, so a proof captured and never delivered
// could be replayed after one within its window and its token's lifetime.
// When full it refuses rather than evicts: evicting would choose which proof
// becomes replayable.
type MemoryNonceStore struct {
	mu       sync.Mutex
	capacity int
	spent    map[string]time.Time
}

// NewMemoryNonceStore holds up to capacity unexpired nonces. A capacity that
// is not positive is [ErrConfiguration].
func NewMemoryNonceStore(capacity int) (*MemoryNonceStore, error) {
	if capacity <= 0 {
		return nil, fmt.Errorf("%w: capacity %d is not positive", ErrConfiguration, capacity)
	}
	return &MemoryNonceStore{capacity: capacity, spent: map[string]time.Time{}}, nil
}

// NewDefaultMemoryNonceStore holds up to [DefaultCapacity] unexpired nonces.
func NewDefaultMemoryNonceStore() *MemoryNonceStore {
	return &MemoryNonceStore{capacity: DefaultCapacity, spent: map[string]time.Time{}}
}

// Capacity is how many unexpired nonces the store holds before refusing.
func (m *MemoryNonceStore) Capacity() int { return m.capacity }

// Spend implements [NonceStore]. Expired entries are swept when the store is
// full, the only moment they can matter.
func (m *MemoryNonceStore) Spend(nonce string, until, now time.Time) error {
	if m == nil || m.spent == nil {
		return fmt.Errorf("%w: a MemoryNonceStore must come from NewMemoryNonceStore", ErrConfiguration)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.spent) >= m.capacity {
		for n, expires := range m.spent {
			if !expires.After(now) {
				delete(m.spent, n)
			}
		}
	}
	if len(m.spent) >= m.capacity {
		return ErrOverloaded
	}
	if _, ok := m.spent[nonce]; ok {
		return ErrReplayed
	}
	m.spent[nonce] = until
	return nil
}

// Remembered is how many nonces are held, for tests and metrics.
func (m *MemoryNonceStore) Remembered() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.spent)
}
