// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

package token

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// A sealed token is a signed token encrypted for its verifiers, so its claims
// are opaque bytes to everyone else, the holder included:
//
//	base64url( version | key ID | nonce | AES-256-GCM(segments) )
//
// with the version (one byte, SealVersion) and the key ID (SealKeyIDSize
// bytes) as the additional data, and segments being the JWS's header, claims
// and signature as raw bytes, each of the first two after a two-byte length.
// Sealing the raw segments rather than the JWS text keeps a sealed token within
// about fifty bytes of the signed one.
//
// Sealing adds confidentiality and nothing else: what a token grants is still
// decided by its signature, checked after it is opened, so a verifier that
// holds a seal key cannot mint.

// SealVersion is the first byte of every sealed token.
const SealVersion = 0x01

// SealKeyIDSize is the length of a seal key's ID. Random rather than chosen, so
// the one thing a sealed token shows in the clear says nothing about whose it
// is.
const SealKeyIDSize = 8

const (
	sealKeySize   = 32
	sealNonceSize = 12
	sealTagSize   = 16
	sealPrefix    = 1 + SealKeyIDSize
)

// SealKey is an AES-256 key tokens are sealed with, held by the issuer and by
// every verifier, and by nobody else.
//
// GCM with a random nonce: rotate the key well before it has sealed 2³²
// tokens, the limit NIST SP 800-38D sets for random nonces. A verifier holds
// several, by ID, so rotation overlaps as it does for signing keys.
type SealKey struct {
	id     [SealKeyIDSize]byte
	secret [sealKeySize]byte
	aead   cipher.AEAD
}

// NewSealKey loads a seal key from its ID and 32-byte secret.
func NewSealKey(id, secret []byte) (SealKey, error) {
	if len(id) != SealKeyIDSize || len(secret) != sealKeySize {
		return SealKey{}, fmt.Errorf("%w: a seal key is an %d-byte ID and a %d-byte secret", ErrKeyInvalid, SealKeyIDSize, sealKeySize)
	}
	block, err := aes.NewCipher(secret)
	if err != nil {
		return SealKey{}, fmt.Errorf("%w: %v", ErrKeyInvalid, err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return SealKey{}, err
	}
	key := SealKey{aead: aead}
	copy(key.id[:], id)
	copy(key.secret[:], secret)
	return key, nil
}

// GenerateSealKey makes a new random seal key with a random ID.
func GenerateSealKey() (SealKey, error) {
	material := make([]byte, SealKeyIDSize+sealKeySize)
	if _, err := rand.Read(material); err != nil {
		return SealKey{}, err
	}
	return NewSealKey(material[:SealKeyIDSize], material[SealKeyIDSize:])
}

// ID is the key's ID, as sealed tokens carry it.
func (k SealKey) ID() []byte { return bytes.Clone(k.id[:]) }

// KeyID is the ID as a JWK `kid`: unpadded base64url.
func (k SealKey) KeyID() string { return base64.RawURLEncoding.EncodeToString(k.id[:]) }

// Secret is the 32-byte AES key, for storing it.
func (k SealKey) Secret() []byte { return bytes.Clone(k.secret[:]) }

// Seal encrypts a signed token for the verifiers holding this key.
func (k SealKey) Seal(token string) (string, error) {
	nonce := make([]byte, sealNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return k.seal(token, nonce)
}

// seal is Seal with the nonce given, so the vectors reproduce byte for byte.
func (k SealKey) seal(token string, nonce []byte) (string, error) {
	if k.aead == nil {
		return "", fmt.Errorf("%w: the zero seal key", ErrKeyInvalid)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("%w: expected three segments", ErrMalformed)
	}
	var segments []byte
	for i, part := range parts {
		raw, err := decodeBase64URL(part)
		if err != nil {
			return "", fmt.Errorf("%w: segment %d is not base64url", ErrMalformed, i)
		}
		if i < 2 {
			if len(raw) > 0xFFFF {
				return "", fmt.Errorf("%w: segment %d is too long", ErrMalformed, i)
			}
			segments = binary.BigEndian.AppendUint16(segments, uint16(len(raw)))
		}
		segments = append(segments, raw...)
	}
	sealed := make([]byte, 0, sealPrefix+sealNonceSize+len(segments)+sealTagSize)
	sealed = append(sealed, SealVersion)
	sealed = append(sealed, k.id[:]...)
	sealed = append(sealed, nonce...)
	sealed = k.aead.Seal(sealed, nonce, segments, sealed[:sealPrefix])
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

// IsSealed reports whether token is in the sealed form rather than a JWS. It
// says nothing about whether it opens.
func IsSealed(token string) bool { return token != "" && !strings.Contains(token, ".") }

// Open decrypts a sealed token with whichever of keys sealed it, and returns
// the signed token inside, still to be verified.
//
// Refused: a token that is not the sealed form or is cut short (ErrMalformed),
// another version (ErrUnsupported), a key ID none of keys has (ErrUnknownKey),
// and anything that does not authenticate under the key it names
// (ErrBadSignature).
func Open(token string, keys ...SealKey) (string, error) {
	if len(token) == 0 || len(token) > MaxTokenBytes {
		return "", fmt.Errorf("%w: token length is out of range", ErrMalformed)
	}
	sealed, err := decodeBase64URL(token)
	if err != nil {
		return "", fmt.Errorf("%w: sealed token is not base64url", ErrMalformed)
	}
	if len(sealed) < sealPrefix+sealNonceSize+sealTagSize {
		return "", fmt.Errorf("%w: sealed token is too short", ErrMalformed)
	}
	if sealed[0] != SealVersion {
		return "", fmt.Errorf("%w: sealed token version %d", ErrUnsupported, sealed[0])
	}
	var key *SealKey
	for i := range keys {
		if bytes.Equal(keys[i].id[:], sealed[1:sealPrefix]) && keys[i].aead != nil {
			key = &keys[i]
			break
		}
	}
	if key == nil {
		return "", fmt.Errorf("%w: seal key %s", ErrUnknownKey, base64.RawURLEncoding.EncodeToString(sealed[1:sealPrefix]))
	}
	nonce := sealed[sealPrefix : sealPrefix+sealNonceSize]
	segments, err := key.aead.Open(nil, nonce, sealed[sealPrefix+sealNonceSize:], sealed[:sealPrefix])
	if err != nil {
		return "", fmt.Errorf("%w: sealed token does not authenticate", ErrBadSignature)
	}
	var parts [3]string
	for i := range 2 {
		if len(segments) < 2 {
			return "", fmt.Errorf("%w: sealed segments are cut short", ErrMalformed)
		}
		n := int(binary.BigEndian.Uint16(segments))
		if len(segments) < 2+n {
			return "", fmt.Errorf("%w: sealed segments are cut short", ErrMalformed)
		}
		parts[i] = base64.RawURLEncoding.EncodeToString(segments[2 : 2+n])
		segments = segments[2+n:]
	}
	parts[2] = base64.RawURLEncoding.EncodeToString(segments)
	return parts[0] + "." + parts[1] + "." + parts[2], nil
}

// errSealKeyShape says what a seal key set member must be.
var errSealKeyShape = errors.New("seal keys are kty oct, alg A256GCM, an 8-byte kid and a 32-byte k")

type sealJWK struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	K   string `json:"k"`
}

// JWK is the key as an RFC 7517 `oct` JWK, secret included: for the issuer's
// secret store and a verifier's configuration, never for publishing.
func (k SealKey) JWK() ([]byte, error) {
	return json.Marshal(sealJWK{Kty: "oct", Alg: "A256GCM", Kid: k.KeyID(), K: base64.RawURLEncoding.EncodeToString(k.secret[:])})
}

// ParseSealKeySet reads seal keys from a JWK set, as a bare array or wrapped
// in {"keys": [...]}.
func ParseSealKeySet(document []byte) ([]SealKey, error) {
	trimmed := bytes.TrimSpace(document)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var wrapped struct {
			Keys json.RawMessage `json:"keys"`
		}
		if err := strict(trimmed); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrKeySetMalformed, err)
		}
		if err := json.Unmarshal(trimmed, &wrapped); err != nil || wrapped.Keys == nil {
			return nil, ErrKeySetMalformed
		}
		trimmed = wrapped.Keys
	}
	if err := strict(trimmed); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeySetMalformed, err)
	}
	var members []sealJWK
	if err := json.Unmarshal(trimmed, &members); err != nil {
		return nil, ErrKeySetMalformed
	}
	keys := make([]SealKey, 0, len(members))
	seen := map[string]bool{}
	for _, member := range members {
		if member.Kty != "oct" || member.Alg != "A256GCM" {
			return nil, fmt.Errorf("%w: %v", ErrKeyUnsupported, errSealKeyShape)
		}
		id, idErr := decodeBase64URL(member.Kid)
		secret, secretErr := decodeBase64URL(member.K)
		if idErr != nil || secretErr != nil {
			return nil, fmt.Errorf("%w: %v", ErrKeyInvalid, errSealKeyShape)
		}
		key, err := NewSealKey(id, secret)
		if err != nil {
			return nil, err
		}
		if seen[member.Kid] {
			return nil, fmt.Errorf("%w: %s", ErrDuplicateKeyID, member.Kid)
		}
		seen[member.Kid] = true
		keys = append(keys, key)
	}
	return keys, nil
}
