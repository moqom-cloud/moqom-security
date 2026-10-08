// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

package sframe

import (
	"bytes"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
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
		sealed, err := s.ProtectRaw([]byte{byte(i)}, nil)
		if err != nil {
			t.Fatal(err)
		}
		h, _, _ := ReadHeader(sealed)
		seen[h.Counter] = true
		if _, err := r.UnprotectRaw(sealed, nil); err != nil {
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
	sealed, _ := s.ProtectRaw([]byte("payload"), metadata)
	if !bytes.Equal(metadata, []byte{0x01, 0x02}) {
		t.Fatal("metadata was written to")
	}
	pt, err := r.UnprotectRaw(sealed, metadata)
	if err != nil || string(pt) != "payload" {
		t.Fatalf("%q %v", pt, err)
	}
}

func TestNoKeyRefuses(t *testing.T) {
	s := NewSender(nil)
	if _, err := s.ProtectRaw([]byte{1}, nil); !errors.Is(err, ErrNoKey) {
		t.Fatal(err)
	}
	key, _ := NewKey(2, bytes.Repeat([]byte{1}, 16), AES128GCMSHA256)
	s.Rekey(key)
	if _, err := s.ProtectRaw([]byte{1}, nil); err != nil {
		t.Fatal(err)
	}
	s.ClearKey()
	if _, err := s.ProtectRaw([]byte{1}, nil); !errors.Is(err, ErrNoKey) {
		t.Fatal(err)
	}
}

func TestUnknownKeyAndResolver(t *testing.T) {
	base := bytes.Repeat([]byte{0x33}, 32)
	kid := MLSKeyID(2, 21)
	key, _ := NewKey(kid, base, AES256GCMSHA512)
	sealed, _ := NewSender(key).ProtectRaw([]byte{7}, nil)

	r := NewReceiver(DefaultReplayWindow)
	var unknown *UnknownKeyError
	if _, err := r.UnprotectRaw(sealed, nil); !errors.As(err, &unknown) || unknown.KeyID != kid {
		t.Fatal(err)
	}
	r.SetResolver(func(id uint64) *Key {
		if EpochTag(id) != 5 {
			return nil
		}
		k, _ := NewKey(id, base, AES256GCMSHA512)
		return k
	})
	if pt, err := r.UnprotectRaw(sealed, nil); err != nil || !bytes.Equal(pt, []byte{7}) {
		t.Fatal(err)
	}
	var replay *ReplayError
	if _, err := r.UnprotectRaw(sealed, nil); !errors.As(err, &replay) || replay.Counter != 0 {
		t.Fatal(err)
	}
	r.Remove(kid)
	r.SetResolver(nil)
	if _, err := r.UnprotectRaw(sealed, nil); Class(err) != "unknown_key" {
		t.Fatal(err)
	}
}

func TestReplayWindowAcrossWords(t *testing.T) {
	w := newReplayWindow(1024)
	for counter := uint64(5000); counter >= 3977; counter-- {
		if !w.accepts(counter) {
			t.Fatalf("refused fresh %d", counter)
		}
		w.record(counter)
	}
	for counter := uint64(3976); counter <= 5000; counter++ {
		if w.accepts(counter) {
			t.Fatalf("accepted %d again", counter)
		}
	}
	w.record(5063)
	if !w.accepts(5001) || w.accepts(4040) || w.accepts(4039) {
		t.Fatal("window after a short advance")
	}
	w.record(5000 + 2048)
	if !w.accepts(6100) || w.accepts(5063) {
		t.Fatal("window after a long advance")
	}
	if newReplayWindow(^uint64(0)).size != maxReplayWindow {
		t.Fatal("window not capped")
	}
}

func TestUnsupportedSuite(t *testing.T) {
	if _, err := NewContext(0x0001, 1, make([]byte, 16)); !errors.Is(err, ErrUnsupportedSuite) {
		t.Fatal(err)
	}
}

func TestBaseKeyLength(t *testing.T) {
	for _, suite := range []CipherSuite{AES128GCMSHA256, AES256GCMSHA512} {
		for _, n := range []int{0, 16, 32, 48} {
			_, err := NewKey(1, make([]byte, n), suite)
			_, cerr := NewContext(suite, 1, make([]byte, n))
			if want := n == suite.KeyLength(); (err == nil) != want || (cerr == nil) != want {
				t.Fatalf("suite %d, %d bytes: %v %v", suite, n, err, cerr)
			}
			if n != suite.KeyLength() && Class(err) != "invalid_base_key" {
				t.Fatal(err)
			}
		}
	}
	if DefaultCipherSuite != AES256GCMSHA512 {
		t.Fatal(DefaultCipherSuite)
	}
}

func TestResolvedKeyKeptOnlyAfterAuthentication(t *testing.T) {
	base := bytes.Repeat([]byte{0x33}, 32)
	r := NewReceiver(DefaultReplayWindow)
	r.SetResolver(func(id uint64) *Key {
		k, _ := NewKey(id, base, AES256GCMSHA512)
		return k
	})
	key, _ := NewKey(40, base, AES256GCMSHA512)
	forged, _ := NewSender(key).ProtectRaw([]byte{7}, nil)
	forged[len(forged)-1] ^= 1
	if _, err := r.UnprotectRaw(forged, nil); !errors.Is(err, ErrAuthentication) || len(r.KeyIDs()) != 0 {
		t.Fatal(err, r.KeyIDs())
	}
}

func TestTrackIsBound(t *testing.T) {
	s, r := pair(t, 1)
	md := Metadata{Track: TrackOf([]string{"moqom", "demo", "alice"}, "video"), Group: 5, Object: 2, Priority: 64}
	sealed, err := s.ProtectObject([]byte{0xAB}, md)
	if err != nil {
		t.Fatal(err)
	}
	for _, track := range []Track{
		TrackOf([]string{"moqom", "demo", "bob"}, "video"),
		TrackOf([]string{"moqom", "demoalice"}, "video"),
	} {
		moved := md
		moved.Track = track
		if _, err := r.UnprotectObject(sealed, moved); !errors.Is(err, ErrAuthentication) {
			t.Fatal(err)
		}
	}
	moved := md
	moved.Track = Track{Name: []byte("video")}
	if _, err := r.UnprotectObject(sealed, moved); !errors.Is(err, ErrInvalidMetadata) {
		t.Fatal(err)
	}
	if pt, err := r.UnprotectObject(sealed, md); err != nil || !bytes.Equal(pt, []byte{0xAB}) {
		t.Fatal(err)
	}
}

func TestConcurrentDuplicatesOpenOnce(t *testing.T) {
	s, _ := pair(t, 1)
	sealed, _ := s.ProtectRaw([]byte{1}, nil)
	for range 50 {
		_, r := pair(t, 1)
		var opened atomic.Int32
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				if _, err := r.UnprotectRaw(sealed, nil); err == nil {
					opened.Add(1)
				}
			})
		}
		wg.Wait()
		if opened.Load() != 1 {
			t.Fatalf("opened %d times", opened.Load())
		}
	}
}

func TestRekeySameKeyResumes(t *testing.T) {
	key, _ := NewKey(5, bytes.Repeat([]byte{0x2A}, 32), AES256GCMSHA512)
	other, _ := NewKey(6, bytes.Repeat([]byte{0x2A}, 32), AES256GCMSHA512)
	s := NewSender(key)
	var counters []uint64
	seal := func() {
		sealed, err := s.ProtectRaw(nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		h, _, _ := ReadHeader(sealed)
		counters = append(counters, h.Counter)
	}
	seal()
	seal()
	s.Rekey(key)
	seal()
	s.ClearKey()
	s.Rekey(other)
	seal()
	s.Rekey(key)
	seal()
	if !slices.Equal(counters, []uint64{0, 1, 2, 0, 3}) {
		t.Fatal(counters)
	}
}
