// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

package sframe

import (
	"bytes"
	"errors"
	"testing"
)

func pair(t *testing.T, keyID uint64) (*Sender, *Receiver) {
	t.Helper()
	key, err := NewKey(keyID, bytes.Repeat([]byte{0x2A}, 32), AES256GCMSHA512)
	if err != nil {
		t.Fatal(err)
	}
	r := NewReceiver(DefaultReplayWindow)
	r.Add(key)
	return NewSender(key), r
}

func TestCountersNeverRepeat(t *testing.T) {
	s, r := pair(t, 1)
	seen := map[uint64]bool{}
	for i := range 200 {
		sealed, err := s.Protect([]byte{byte(i)}, nil)
		if err != nil {
			t.Fatal(err)
		}
		h, _, _ := ReadHeader(sealed)
		seen[h.Counter] = true
		if _, err := r.Unprotect(sealed, nil); err != nil {
			t.Fatal(err)
		}
	}
	if len(seen) != 200 || s.IssuedCounters() != 200 {
		t.Fatalf("%d counters, %d issued", len(seen), s.IssuedCounters())
	}
}

func TestProtectDoesNotAliasHeader(t *testing.T) {
	s, r := pair(t, 300)
	metadata := []byte{0x01, 0x02}
	sealed, _ := s.Protect([]byte("payload"), metadata)
	if !bytes.Equal(metadata, []byte{0x01, 0x02}) {
		t.Fatal("metadata was written to")
	}
	pt, err := r.Unprotect(sealed, metadata)
	if err != nil || string(pt) != "payload" {
		t.Fatalf("%q %v", pt, err)
	}
}

func TestNoKeyRefuses(t *testing.T) {
	s := NewSender(nil)
	if _, err := s.Protect([]byte{1}, nil); !errors.Is(err, ErrNoKey) {
		t.Fatal(err)
	}
	key, _ := NewKey(2, []byte{1}, AES128GCMSHA256)
	s.Rekey(key)
	if _, err := s.Protect([]byte{1}, nil); err != nil {
		t.Fatal(err)
	}
	s.ClearKey()
	if _, err := s.Protect([]byte{1}, nil); !errors.Is(err, ErrNoKey) {
		t.Fatal(err)
	}
}

func TestUnknownKeyAndResolver(t *testing.T) {
	base := bytes.Repeat([]byte{0x33}, 32)
	kid := MLSKeyID(2, 21)
	key, _ := NewKey(kid, base, AES256GCMSHA512)
	sealed, _ := NewSender(key).Protect([]byte{7}, nil)

	r := NewReceiver(DefaultReplayWindow)
	var unknown *UnknownKeyError
	if _, err := r.Unprotect(sealed, nil); !errors.As(err, &unknown) || unknown.KeyID != kid {
		t.Fatal(err)
	}
	r.SetResolver(func(id uint64) *Key {
		if EpochTag(id) != 5 {
			return nil
		}
		k, _ := NewKey(id, base, AES256GCMSHA512)
		return k
	})
	if pt, err := r.Unprotect(sealed, nil); err != nil || !bytes.Equal(pt, []byte{7}) {
		t.Fatal(err)
	}
	var replay *ReplayError
	if _, err := r.Unprotect(sealed, nil); !errors.As(err, &replay) || replay.Counter != 0 {
		t.Fatal(err)
	}
	r.Remove(kid)
	r.SetResolver(nil)
	if _, err := r.Unprotect(sealed, nil); Class(err) != "unknown_key" {
		t.Fatal(err)
	}
}

func TestUnsupportedSuite(t *testing.T) {
	if _, err := NewContext(0x0001, 1, []byte{1}); !errors.Is(err, ErrUnsupportedSuite) {
		t.Fatal(err)
	}
}
