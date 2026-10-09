// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

package sframe

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha512"
	"encoding/binary"
	"hash"
	"math"
	"sync"
)

// CipherSuite is an RFC 9605 §8.1 cipher suite.
type CipherSuite uint16

// AES256GCMSHA512 is AES-256-GCM with SHA-512, 16-byte tag: the only suite.
// AES-128-GCM (0x0004) is deliberately absent, so a peer or object naming it is
// refused rather than negotiated down to.
const AES256GCMSHA512 CipherSuite = 0x0005

// DefaultCipherSuite is the suite Swift and Rust use when none is given.
const DefaultCipherSuite = AES256GCMSHA512

// KeyLength is the AEAD key length, which is also the length of an
// MLS-exported base key. Zero for an unsupported suite.
func (s CipherSuite) KeyLength() int {
	if s == AES256GCMSHA512 {
		return 32
	}
	return 0
}

// NonceLength is 12, as GCM wants.
func (CipherSuite) NonceLength() int { return 12 }

// TagLength is 16.
func (CipherSuite) TagLength() int { return 16 }

func (CipherSuite) hash() func() hash.Hash { return sha512.New }

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
// under another. baseKey must be the suite's KeyLength bytes, the length an
// MLS exporter gives it, or NewKey returns ErrInvalidBaseKey.
func NewKey(keyID uint64, baseKey []byte, suite CipherSuite) (*Key, error) {
	if suite.KeyLength() == 0 {
		return nil, ErrUnsupportedSuite
	}
	if len(baseKey) != suite.KeyLength() {
		return nil, ErrInvalidBaseKey
	}
	return newKey(keyID, baseKey, suite)
}

// newKey derives without checking the base key's length, for RFC 9605's
// Appendix C, which derives suite 0x0005 keys from a 16-byte base key.
func newKey(keyID uint64, baseKey []byte, suite CipherSuite) (*Key, error) {
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
// One sender per key. Two senders under one key will collide. The counter is
// held in memory and starts at 0 for every sender and every key, and a key is
// fixed by its base key, KID and suite, so deriving the same one again — in a
// second sender, on a second device, or in the same process after a restart —
// repeats nonces. Every new sender needs a base key or KID that has never
// sealed before: a new MLS epoch, or a fresh random KID.
//
// Rekey starts the counter at 0 for a KID this sender has not sealed under.
// For one it has, the counter carries on where it stopped, so installing the
// same key again, or going back to it after ClearKey, never reissues a
// counter.
type Sender struct {
	mu      sync.Mutex
	current *Key
	counter uint64
	resume  map[uint64]uint64 // the next counter for each KID sealed under before
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

// Rekey switches to a new key, or to none if key is nil.
func (s *Sender) Rekey(key *Key) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current != nil {
		if s.resume == nil {
			s.resume = map[uint64]uint64{}
		}
		s.resume[s.current.keyID] = max(s.resume[s.current.keyID], s.counter)
	}
	s.current, s.counter = key, 0
	if key != nil {
		s.counter = s.resume[key.keyID]
	}
}

// ClearKey goes back to refusing to encrypt.
func (s *Sender) ClearKey() { s.Rekey(nil) }

// ProtectObject encrypts one MoQ object, binding its track, position and
// properties into the tag.
func (s *Sender) ProtectObject(plaintext []byte, metadata Metadata) ([]byte, error) {
	aad, err := metadata.Encode()
	if err != nil {
		return nil, err
	}
	return s.ProtectRaw(plaintext, aad)
}

// ProtectRaw encrypts one frame with arbitrary AAD after the header, as RFC
// 9605's own vectors do. Not for MoQ objects, which bind their track through
// ProtectObject.
func (s *Sender) ProtectRaw(plaintext, metadata []byte) ([]byte, error) {
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

// DefaultReplayWindow is what NewReceiver is usually given. Windows above
// 65536 behave as 65536.
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
// it. A key it returns is added as though by Add, once an object has
// authenticated under it; a key for any other KID is ignored. It is called
// without the receiver's lock held, possibly concurrently.
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

// UnprotectObject decrypts one MoQ object against the track, position and
// properties it arrived with.
func (r *Receiver) UnprotectObject(data []byte, metadata Metadata) ([]byte, error) {
	aad, err := metadata.Encode()
	if err != nil {
		return nil, err
	}
	return r.UnprotectRaw(data, aad)
}

// UnprotectRaw decrypts one frame sealed by ProtectRaw.
func (r *Receiver) UnprotectRaw(data, metadata []byte) ([]byte, error) {
	header, length, err := ReadHeader(data)
	if err != nil {
		return nil, err
	}
	kid := header.KeyID

	r.mu.Lock()
	key, window := r.keys[kid], r.seen[kid]
	var resolve func(uint64) *Key
	if key == nil {
		resolve = r.resolver
	}
	r.mu.Unlock()

	// A resolved key is held aside until an object authenticates under it, so
	// objects under made-up KIDs cannot fill the receiver with keys.
	resolved := false
	if resolve != nil {
		if candidate := resolve(kid); candidate != nil && candidate.keyID == kid {
			key, window, resolved = candidate, newReplayWindow(r.window), true
		}
	}
	if key == nil {
		return nil, &UnknownKeyError{KeyID: kid}
	}

	r.mu.Lock()
	fresh := window.accepts(header.Counter)
	r.mu.Unlock()
	if !fresh {
		return nil, &ReplayError{Counter: header.Counter}
	}

	aad := append(data[:length:length], metadata...)
	plaintext, err := key.open(data[length:], header.Counter, aad)
	if err != nil {
		return nil, err
	}

	// Recorded only after authentication, so a forged object cannot knock out
	// the real one behind it. Checked again, because another copy of this
	// object may have opened meanwhile.
	r.mu.Lock()
	defer r.mu.Unlock()
	if resolved && r.keys[kid] == nil {
		r.keys[kid], r.seen[kid] = key, window
	}
	if current := r.seen[kid]; current != nil && (current == window || resolved) {
		if !current.accepts(header.Counter) {
			return nil, &ReplayError{Counter: header.Counter}
		}
		current.record(header.Counter)
	}
	return plaintext, nil
}

// maxReplayWindow is the largest window honoured, so a configuration mistake
// cannot ask for gigabytes of bitmap per KID. 8 KiB per KID at the cap.
const maxReplayWindow = 1 << 16

// replayWindow is a ring of 64-bit words indexed by counter, with one word
// more than the window needs: advancing clears whole words, and the spare word
// is what keeps that from clearing a counter still inside the window.
type replayWindow struct {
	size    uint64
	highest uint64
	any     bool
	words   []uint64
}

func newReplayWindow(size uint64) *replayWindow {
	size = min(size, maxReplayWindow)
	return &replayWindow{size: size, words: make([]uint64, (size+63)/64+1)}
}

func (w *replayWindow) slot(counter uint64) (int, uint64) {
	return int((counter / 64) % uint64(len(w.words))), 1 << (counter % 64)
}

func (w *replayWindow) accepts(counter uint64) bool {
	if !w.any || counter > w.highest {
		return true
	}
	if w.highest-counter >= w.size {
		return false
	}
	word, bit := w.slot(counter)
	return w.words[word]&bit == 0
}

func (w *replayWindow) record(counter uint64) {
	switch {
	case !w.any:
		w.highest, w.any = counter, true
	case counter > w.highest:
		if advanced := counter/64 - w.highest/64; advanced >= uint64(len(w.words)) {
			clear(w.words)
		} else {
			for block := w.highest/64 + 1; block <= counter/64; block++ {
				w.words[block%uint64(len(w.words))] = 0
			}
		}
		w.highest = counter
	case w.highest-counter >= w.size:
		return
	}
	word, bit := w.slot(counter)
	w.words[word] |= bit
}
