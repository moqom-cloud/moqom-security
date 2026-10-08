// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

package sframe

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"hash"
	"math"
	"sync"
)

// CipherSuite is an RFC 9605 §8.1 cipher suite.
type CipherSuite uint16

const (
	// AES128GCMSHA256 is AES-128-GCM with SHA-256. 16-byte tag.
	AES128GCMSHA256 CipherSuite = 0x0004
	// AES256GCMSHA512 is AES-256-GCM with SHA-512. 16-byte tag. The default.
	AES256GCMSHA512 CipherSuite = 0x0005
)

// KeyLength is the AEAD key length, which is also the length of an
// MLS-exported base key. Zero for an unsupported suite.
func (s CipherSuite) KeyLength() int {
	switch s {
	case AES128GCMSHA256:
		return 16
	case AES256GCMSHA512:
		return 32
	}
	return 0
}

// NonceLength is 12 for both suites, as GCM wants.
func (CipherSuite) NonceLength() int { return 12 }

// TagLength is 16 for both suites.
func (CipherSuite) TagLength() int { return 16 }

func (s CipherSuite) hash() func() hash.Hash {
	if s == AES128GCMSHA256 {
		return sha256.New
	}
	return sha512.New
}

// Header is the KID and CTR that precede an SFrame ciphertext.
type Header struct {
	KeyID   uint64
	Counter uint64
}

// Encode is RFC 9605 §4.3: a value below 8 rides in the config byte, anything
// larger follows in the minimum number of big-endian bytes.
func (h Header) Encode() []byte {
	out := make([]byte, 1, 17)
	if h.KeyID < 8 {
		out[0] |= byte(h.KeyID) << 4
	} else {
		n := compactLength(h.KeyID)
		out[0] |= 0x80 | byte(n-1)<<4
		out = appendCompact(out, h.KeyID, n)
	}
	if h.Counter < 8 {
		out[0] |= byte(h.Counter)
	} else {
		n := compactLength(h.Counter)
		out[0] |= 0x08 | byte(n-1)
		out = appendCompact(out, h.Counter, n)
	}
	return out
}

// ReadHeader parses a header and returns how many bytes it took. A value in
// more bytes than it needs is read rather than refused: the tag authenticates
// the header bytes as received.
func ReadHeader(data []byte) (Header, int, error) {
	if len(data) == 0 {
		return Header{}, 0, ErrMalformedHeader
	}
	config := data[0]
	offset := 1
	read := func(extended bool, field byte) (uint64, error) {
		if !extended {
			return uint64(field), nil
		}
		n := int(field) + 1
		if len(data)-offset < n {
			return 0, ErrMalformedHeader
		}
		var v uint64
		for _, b := range data[offset : offset+n] {
			v = v<<8 | uint64(b)
		}
		offset += n
		return v, nil
	}
	kid, err := read(config&0x80 != 0, (config>>4)&0x07)
	if err != nil {
		return Header{}, 0, err
	}
	ctr, err := read(config&0x08 != 0, config&0x07)
	if err != nil {
		return Header{}, 0, err
	}
	return Header{KeyID: kid, Counter: ctr}, offset, nil
}

func compactLength(v uint64) int {
	n := 1
	for v > 0xFF {
		v >>= 8
		n++
	}
	return n
}

func appendCompact(out []byte, v uint64, n int) []byte {
	for i := n - 1; i >= 0; i-- {
		out = append(out, byte(v>>(8*i)))
	}
	return out
}

// EpochBits is E in RFC 9605 §5.2: a receiver holds the current epoch and,
// briefly, the one before it, so sixteen distinguishable epochs is far more
// than is live at once.
const EpochBits = 4

// MLSExporterLabel is the label an MLS group exports an epoch's base_key under,
// with an empty context and KeyLength bytes.
const MLSExporterLabel = "SFrame 1.0 Base Key"

// MLSKeyID is RFC 9605 §5.2's KID for an MLS member with context 0:
// (leaf << E) | (epoch mod 2^E).
func MLSKeyID(leaf uint32, epoch uint64) uint64 {
	return uint64(leaf)<<EpochBits | epoch&(1<<EpochBits-1)
}

// EpochTag is the low bits of an epoch as a KID carries them.
func EpochTag(keyID uint64) uint64 { return keyID & (1<<EpochBits - 1) }

// Key is the AEAD key and salt derived from a base key for one KID.
type Key struct {
	keyID uint64
	suite CipherSuite
	key   []byte
	salt  []byte
	aead  cipher.AEAD
}

// NewKey derives per RFC 9605 §4.4.2. The KID and suite are in the derivation
// labels, so a ciphertext made under one KID or suite never authenticates
// under another.
func NewKey(keyID uint64, baseKey []byte, suite CipherSuite) (*Key, error) {
	if suite.KeyLength() == 0 {
		return nil, ErrUnsupportedSuite
	}
	secret, err := hkdf.Extract(suite.hash(), baseKey, nil)
	if err != nil {
		return nil, err
	}
	key, err := hkdf.Expand(suite.hash(), secret, string(label("SFrame 1.0 Secret key ", keyID, suite)), suite.KeyLength())
	if err != nil {
		return nil, err
	}
	salt, err := hkdf.Expand(suite.hash(), secret, string(label("SFrame 1.0 Secret salt ", keyID, suite)), suite.NonceLength())
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Key{keyID: keyID, suite: suite, key: key, salt: salt, aead: aead}, nil
}

func label(prefix string, keyID uint64, suite CipherSuite) []byte {
	out := append([]byte(prefix), make([]byte, 10)...)
	binary.BigEndian.PutUint64(out[len(prefix):], keyID)
	binary.BigEndian.PutUint16(out[len(prefix)+8:], uint16(suite))
	return out
}

// KeyID is the KID this key seals under.
func (k *Key) KeyID() uint64 { return k.keyID }

// Suite is the cipher suite this key was derived for.
func (k *Key) Suite() CipherSuite { return k.suite }

// nonce is the salt XOR the counter, the counter at the low-order end.
func (k *Key) nonce(counter uint64) []byte {
	n := make([]byte, len(k.salt))
	copy(n, k.salt)
	tail := n[len(n)-8:]
	binary.BigEndian.PutUint64(tail, binary.BigEndian.Uint64(tail)^counter)
	return n
}

func (k *Key) seal(dst, plaintext []byte, counter uint64, aad []byte) []byte {
	return k.aead.Seal(dst, k.nonce(counter), plaintext, aad)
}

func (k *Key) open(ciphertext []byte, counter uint64, aad []byte) ([]byte, error) {
	if len(ciphertext) < k.suite.TagLength() {
		return nil, ErrAuthentication
	}
	out, err := k.aead.Open(nil, k.nonce(counter), ciphertext, aad)
	if err != nil {
		return nil, ErrAuthentication
	}
	return out, nil
}

// Sender encrypts, owning the counter: there is no API that lets a caller
// choose one, because a repeated GCM nonce leaks the XOR of two plaintexts and
// the authentication subkey.
//
// One sender per (key, media stream). Two senders under one key will collide.
type Sender struct {
	mu      sync.Mutex
	current *Key
	counter uint64
}

// NewSender returns a sender under key, or with no key if key is nil, which
// refuses to encrypt until Rekey.
func NewSender(key *Key) *Sender { return &Sender{current: key} }

// Key is the key in force, or nil.
func (s *Sender) Key() *Key {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.current
}

// IssuedCounters is how many counters the current key has used.
func (s *Sender) IssuedCounters() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.counter
}

// Rekey switches to a new key and restarts the counter.
func (s *Sender) Rekey(key *Key) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.current, s.counter = key, 0
}

// ClearKey goes back to refusing to encrypt.
func (s *Sender) ClearKey() { s.Rekey(nil) }

// ProtectObject encrypts one MoQ object, binding its metadata into the tag.
func (s *Sender) ProtectObject(plaintext []byte, metadata Metadata) ([]byte, error) {
	aad, err := metadata.Encode()
	if err != nil {
		return nil, err
	}
	return s.Protect(plaintext, aad)
}

// Protect encrypts one frame. metadata is authenticated and not encrypted.
func (s *Sender) Protect(plaintext, metadata []byte) ([]byte, error) {
	s.mu.Lock()
	key := s.current
	if key == nil {
		s.mu.Unlock()
		return nil, ErrNoKey
	}
	issued := s.counter
	if issued == math.MaxUint64 {
		s.mu.Unlock()
		return nil, ErrCounterExhausted
	}
	s.counter++
	s.mu.Unlock()

	header := Header{KeyID: key.keyID, Counter: issued}.Encode()
	aad := append(header[:len(header):len(header)], metadata...)
	return key.seal(header, plaintext, issued, aad), nil
}

// DefaultReplayWindow is what NewReceiver is usually given. The bitmap is one
// word, so any window above 64 behaves as 64.
const DefaultReplayWindow = 1024

// Receiver decrypts, holding keys for any number of KIDs and rejecting replays.
type Receiver struct {
	window   uint64
	mu       sync.Mutex
	keys     map[uint64]*Key
	seen     map[uint64]*replayWindow
	resolver func(keyID uint64) *Key
}

// NewReceiver returns a receiver tolerating reordering up to window counters.
func NewReceiver(window uint64) *Receiver {
	return &Receiver{window: window, keys: map[uint64]*Key{}, seen: map[uint64]*replayWindow{}}
}

// SetResolver installs a function asked for a key the receiver does not hold,
// for schemes where a receiver derives a sender's key rather than being sent
// it. A key it returns is added as though by Add.
func (r *Receiver) SetResolver(resolve func(keyID uint64) *Key) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.resolver = resolve
}

// Add loads a key, resetting its replay window.
func (r *Receiver) Add(key *Key) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.keys[key.keyID] = key
	r.seen[key.keyID] = newReplayWindow(r.window)
}

// Remove forgets a key: anything still in flight under it stops decrypting.
func (r *Receiver) Remove(keyID uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.keys, keyID)
	delete(r.seen, keyID)
}

// KeyIDs are the KIDs currently loaded.
func (r *Receiver) KeyIDs() []uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	ids := make([]uint64, 0, len(r.keys))
	for id := range r.keys {
		ids = append(ids, id)
	}
	return ids
}

// UnprotectObject decrypts one MoQ object against the metadata it arrived with.
func (r *Receiver) UnprotectObject(data []byte, metadata Metadata) ([]byte, error) {
	aad, err := metadata.Encode()
	if err != nil {
		return nil, err
	}
	return r.Unprotect(data, aad)
}

// Unprotect decrypts one frame.
func (r *Receiver) Unprotect(data, metadata []byte) ([]byte, error) {
	header, length, err := ReadHeader(data)
	if err != nil {
		return nil, err
	}

	r.mu.Lock()
	if r.keys[header.KeyID] == nil && r.resolver != nil {
		resolve := r.resolver
		r.mu.Unlock()
		resolved := resolve(header.KeyID)
		r.mu.Lock()
		if resolved != nil && resolved.keyID == header.KeyID && r.keys[header.KeyID] == nil {
			r.keys[header.KeyID] = resolved
			r.seen[header.KeyID] = newReplayWindow(r.window)
		}
	}
	key := r.keys[header.KeyID]
	if key == nil {
		r.mu.Unlock()
		return nil, &UnknownKeyError{KeyID: header.KeyID}
	}
	window := r.seen[header.KeyID]
	if !window.accepts(header.Counter) {
		r.mu.Unlock()
		return nil, &ReplayError{Counter: header.Counter}
	}
	r.mu.Unlock()

	aad := append(data[:length:length], metadata...)
	plaintext, err := key.open(data[length:], header.Counter, aad)
	if err != nil {
		return nil, err
	}

	// Recorded only after authentication, so a forged object cannot knock out
	// the real one behind it.
	r.mu.Lock()
	if r.seen[header.KeyID] == window {
		window.record(header.Counter)
	}
	r.mu.Unlock()
	return plaintext, nil
}

type replayWindow struct {
	size    uint64
	highest uint64
	any     bool
	bitmap  uint64
}

func newReplayWindow(size uint64) *replayWindow { return &replayWindow{size: min(size, 64)} }

func (w *replayWindow) accepts(counter uint64) bool {
	if !w.any || counter > w.highest {
		return true
	}
	age := w.highest - counter
	return age < w.size && w.bitmap&(1<<age) == 0
}

func (w *replayWindow) record(counter uint64) {
	switch {
	case !w.any:
		w.highest, w.bitmap, w.any = counter, 1, true
	case counter > w.highest:
		if shift := counter - w.highest; shift >= 64 {
			w.bitmap = 0
		} else {
			w.bitmap <<= shift
		}
		w.bitmap |= 1
		w.highest = counter
	default:
		if age := w.highest - counter; age < 64 {
			w.bitmap |= 1 << age
		}
	}
}
