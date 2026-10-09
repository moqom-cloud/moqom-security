// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

package token

import (
	"bytes"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Algorithm is a JOSE `alg`, and belongs to a key rather than to a token.
//
// That is the defence against algorithm confusion: a verifier that dispatches
// on the token's own `alg` can be told to use "none", or an HMAC keyed with the
// public key. A token must name its key's algorithm and is verified with that
// one and no other.
type Algorithm string

// MLDSA87 is ML-DSA-87, which every token is signed and verified with.
const MLDSA87 Algorithm = "ML-DSA-87"

// KeyID is the identifier a key gets when nobody names it: the first eight
// bytes of the SHA-256 of the raw public key, base64url. A function of the key,
// so a key has one name on every side of a restart and cannot be republished
// under a second one as if it were a rotation.
func KeyID(public []byte) string {
	digest := sha256.Sum256(public)
	return base64.RawURLEncoding.EncodeToString(digest[:8])
}

// PublicKey is a key tokens may be verified with.
type PublicKey struct {
	id        string
	algorithm Algorithm
	mldsa     *mldsa.PublicKey
}

// Failures loading a key, a key set or a seed. Each is one of the error
// classes the key set vectors name, given by Class.
var (
	// ErrKeySetMalformed is a document that is not a JWK set: not JSON, not an
	// array or {"keys": [...]}, a key that is not an object, a member that is
	// null, of the wrong type or named twice, or a key with no `kty` or no
	// `kid`.
	ErrKeySetMalformed = errors.New("not a JWK set")
	// ErrKeyUnsupported is a key that is not ML-DSA-87.
	ErrKeyUnsupported = errors.New("key type is not supported")
	// ErrKeyInvalid is key material that is not base64url or not the
	// algorithm's length, or a seed that is not 32 bytes.
	ErrKeyInvalid = errors.New("key is not valid")
	// ErrDuplicateKeyID is a set naming one `kid` twice. Which of the two a
	// token's `kid` would select is the kind of question a verifier must not
	// answer by accident, so the set is refused.
	ErrDuplicateKeyID = errors.New("key ID appears twice in the set")
)

// NewPublicKey reads a raw ML-DSA-87 public key, 2,592 bytes. An empty id is
// KeyID of the key.
func NewPublicKey(algorithm Algorithm, id string, raw []byte) (PublicKey, error) {
	if id == "" {
		id = KeyID(raw)
	}
	if algorithm != MLDSA87 {
		return PublicKey{}, fmt.Errorf("%w: key %s: algorithm %q", ErrKeyUnsupported, id, algorithm)
	}
	public, err := mldsa.NewPublicKey(mldsa.MLDSA87(), raw)
	if err != nil {
		return PublicKey{}, fmt.Errorf("%w: key %s: %v", ErrKeyInvalid, id, err)
	}
	return PublicKey{id: id, algorithm: MLDSA87, mldsa: public}, nil
}

// ID is the `kid` naming the key.
func (k PublicKey) ID() string { return k.id }

// Algorithm is what the key verifies with.
func (k PublicKey) Algorithm() Algorithm { return k.algorithm }

// Bytes is the raw public key.
func (k PublicKey) Bytes() []byte {
	if k.mldsa == nil {
		return nil
	}
	return k.mldsa.Bytes()
}

// Verify reports whether signature is this key's over message, by this key's
// own algorithm.
func (k PublicKey) Verify(message, signature []byte) bool {
	return k.mldsa != nil && mldsa.Verify(k.mldsa, message, signature, nil) == nil
}

type jwk struct {
	Kty string `json:"kty"`
	Alg string `json:"alg,omitempty"`
	Kid string `json:"kid"`
	Pub string `json:"pub,omitempty"`
}

// JWK renders the key as a JWK: AKP with alg ML-DSA-87, per the JOSE ML-DSA
// draft.
func (k PublicKey) JWK() ([]byte, error) {
	if k.mldsa == nil {
		return nil, errors.New("token: the zero PublicKey has no JWK")
	}
	return json.Marshal(jwk{Kty: "AKP", Alg: string(MLDSA87), Kid: k.id, Pub: base64.RawURLEncoding.EncodeToString(k.Bytes())})
}

// ParseJWKSet reads a JWK set, as a bare array or wrapped in {"keys": [...]}.
//
// The whole document is read first (ErrKeySetMalformed), then each key in
// order: it must be AKP/ML-DSA-87 (ErrKeyUnsupported), its public key must be
// canonical base64url of the right length (ErrKeyInvalid), and its `kid` must
// not repeat one before it (ErrDuplicateKeyID). A key that fails is refused
// rather than skipped, because a set that silently lost a key verifies fewer
// tokens than its author thinks. Member names are exact, and members a key
// does not need (`use`, `key_ops`, `crv`, `x`) are ignored.
func ParseJWKSet(document []byte) ([]PublicKey, error) {
	jwks, err := decodeJWKSet(document)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeySetMalformed, err)
	}
	keys := make([]PublicKey, 0, len(jwks))
	seen := make(map[string]bool, len(jwks))
	for _, key := range jwks {
		if key.Kty != "AKP" || key.Alg != string(MLDSA87) {
			return nil, fmt.Errorf("%w: key %s: only AKP/ML-DSA-87 is supported, got %s/%s",
				ErrKeyUnsupported, key.Kid, key.Kty, key.Alg)
		}
		raw, err := decodeBase64URL(key.Pub)
		if err != nil {
			return nil, fmt.Errorf("%w: key %s: pub is not base64url", ErrKeyInvalid, key.Kid)
		}
		public, err := NewPublicKey(MLDSA87, key.Kid, raw)
		if err != nil {
			return nil, err
		}
		if seen[key.Kid] {
			return nil, fmt.Errorf("%w: %s", ErrDuplicateKeyID, key.Kid)
		}
		seen[key.Kid] = true
		keys = append(keys, public)
	}
	return keys, nil
}

func decodeJWKSet(document []byte) ([]jwk, error) {
	if err := strict(document); err != nil {
		return nil, err
	}
	var entries []json.RawMessage
	if bytes.HasPrefix(bytes.TrimLeft(document, " \t\r\n"), []byte("{")) {
		fields, err := object(document)
		if err != nil {
			return nil, err
		}
		raw, ok := fields["keys"]
		if !ok {
			return nil, errors.New(`no "keys" member`)
		}
		if err := fieldsInto(map[string]json.RawMessage{"keys": raw}, map[string]any{"keys": &entries}, false); err != nil {
			return nil, err
		}
	} else if err := json.Unmarshal(document, &entries); err != nil {
		return nil, err
	} else if entries == nil {
		return nil, errors.New("null")
	}
	jwks := make([]jwk, len(entries))
	for i, entry := range entries {
		fields, err := object(entry)
		if err != nil {
			return nil, fmt.Errorf("key %d: %w", i, err)
		}
		key := &jwks[i]
		if err := fieldsInto(fields, map[string]any{
			"kty": &key.Kty, "alg": &key.Alg, "kid": &key.Kid, "pub": &key.Pub,
		}, false); err != nil {
			return nil, fmt.Errorf("key %d: %w", i, err)
		}
		if _, ok := fields["kty"]; !ok {
			return nil, fmt.Errorf("key %d has no kty", i)
		}
		if key.Kid == "" {
			return nil, fmt.Errorf("key %d has no kid", i)
		}
	}
	return jwks, nil
}

// decodeBase64URL is strict unpadded base64url. encoding/base64 skips line
// breaks even in strict mode, which the other two implementations do not, so
// they are refused here first.
func decodeBase64URL(text string) ([]byte, error) {
	if strings.ContainsAny(text, "\r\n") {
		return nil, errors.New("line break in base64url")
	}
	return base64.RawURLEncoding.Strict().DecodeString(text)
}

// Signer mints tokens with an ML-DSA-87 key.
type Signer struct {
	private *mldsa.PrivateKey
	public  PublicKey
}

// NewSigner loads an ML-DSA-87 key from its 32-byte FIPS 204 seed, named by
// KeyID of its public half.
func NewSigner(seed []byte) (*Signer, error) {
	private, err := mldsa.NewPrivateKey(mldsa.MLDSA87(), seed)
	if err != nil {
		return nil, fmt.Errorf("%w: ML-DSA-87 seed: %v", ErrKeyInvalid, err)
	}
	return signerFor(private), nil
}

// GenerateSigner makes a new random ML-DSA-87 key.
func GenerateSigner() (*Signer, error) {
	private, err := mldsa.GenerateKey(mldsa.MLDSA87())
	if err != nil {
		return nil, err
	}
	return signerFor(private), nil
}

func signerFor(private *mldsa.PrivateKey) *Signer {
	public := private.PublicKey()
	raw := public.Bytes()
	return &Signer{
		private: private,
		public:  PublicKey{id: KeyID(raw), algorithm: MLDSA87, mldsa: public},
	}
}

// WithID is the same key under another `kid`, for a deployment that names its
// keys itself.
func (s *Signer) WithID(id string) *Signer {
	public := s.public
	public.id = id
	return &Signer{private: s.private, public: public}
}

// ID is the `kid` tokens from this signer carry.
func (s *Signer) ID() string { return s.public.id }

// PublicKey is the half a verifier needs.
func (s *Signer) PublicKey() PublicKey { return s.public }

// Seed is the 32-byte FIPS 204 seed, for storing the key.
func (s *Signer) Seed() []byte { return s.private.Bytes() }

// Sign mints a token carrying claims, exactly as given.
//
// Refused rather than repaired: claims with no subject, tenant or thumbprint
// (ErrIncomplete), a thumbprint that is not RFC 7638 SHA-256 (ErrThumbprint),
// or `iat` and `exp` unset, out of order or more than MaxLifetime apart
// (ErrLifetime). The signature is hedged, as FIPS 204 recommends.
func (s *Signer) Sign(claims Claims) (string, error) {
	return s.sign(claims, func(message []byte) ([]byte, error) {
		return s.private.Sign(rand.Reader, message, nil)
	})
}

// signDeterministic is Sign with FIPS 204 deterministic signing, so the
// vectors reproduce byte for byte.
func (s *Signer) signDeterministic(claims Claims) (string, error) {
	return s.sign(claims, func(message []byte) ([]byte, error) {
		return s.private.SignDeterministic(message, nil)
	})
}

func (s *Signer) sign(claims Claims, signature func([]byte) ([]byte, error)) (string, error) {
	input, err := signingInput(MLDSA87, s.public.id, claims)
	if err != nil {
		return "", err
	}
	signed, err := signature([]byte(input))
	if err != nil {
		return "", err
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signed), nil
}

// SignMessage signs message with the token key, for a protocol that shares it.
//
// The caller owns the domain separation: message must never be a valid JWS
// signing input, or the signature could be spliced into a token. Starting it
// with a fixed context string that is not base64url is enough.
func (s *Signer) SignMessage(message []byte) ([]byte, error) {
	return s.private.Sign(rand.Reader, message, nil)
}
