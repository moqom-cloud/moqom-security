// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

package proof

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/mldsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"math/big"
	"slices"
	"time"
)

// MaxProofBytes bounds a proof before any parsing. An ML-DSA-65 proof, key
// included, is about 8 KB.
const MaxProofBytes = 16 * 1024

// DefaultWindow is how far a proof's `iat` may be from the checker's clock,
// either way, unless [WithWindow] says otherwise.
const DefaultWindow = 5 * time.Minute

// Checker checks proofs and spends their nonces. Make one with [NewChecker];
// the zero value refuses every proof with [ErrConfiguration].
type Checker struct {
	store              NonceStore
	algorithms         []Algorithm
	window             time.Duration
	requireCertificate bool
}

// A CheckerOption changes one setting of a [Checker] from its default.
type CheckerOption func(*Checker) error

// WithAlgorithms accepts only algorithms, instead of every one in
// [Algorithms]. Naming none, or one this package does not know, is
// [ErrConfiguration].
func WithAlgorithms(algorithms ...Algorithm) CheckerOption {
	return func(c *Checker) error {
		if len(algorithms) == 0 {
			return fmt.Errorf("%w: a checker must accept at least one algorithm", ErrConfiguration)
		}
		for _, alg := range algorithms {
			if !slices.Contains(Algorithms, alg) {
				return fmt.Errorf("%w: unknown algorithm %q", ErrConfiguration, alg)
			}
		}
		c.algorithms = slices.Clone(algorithms)
		return nil
	}
}

// WithWindow lets `iat` be up to window from the checker's clock, either way,
// instead of [DefaultWindow]. A window that is not positive is
// [ErrConfiguration].
func WithWindow(window time.Duration) CheckerOption {
	return func(c *Checker) error {
		if window <= 0 {
			return fmt.Errorf("%w: window %v is not positive", ErrConfiguration, window)
		}
		c.window = window
		return nil
	}
}

// WithCertificateRequired refuses every proof when Check is given no
// certificate hash, rather than accepting only proofs that name none.
func WithCertificateRequired(required bool) CheckerOption {
	return func(c *Checker) error {
		c.requireCertificate = required
		return nil
	}
}

// NewChecker makes a checker that spends nonces in store and accepts every
// algorithm in [Algorithms] within [DefaultWindow], unless options say
// otherwise. A nil store is [ErrConfiguration]: without one a proof is not
// single-use.
func NewChecker(store NonceStore, options ...CheckerOption) (*Checker, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: a Checker needs a NonceStore", ErrConfiguration)
	}
	c := &Checker{store: store, algorithms: slices.Clone(Algorithms), window: DefaultWindow}
	for _, option := range options {
		if option == nil {
			return nil, fmt.Errorf("%w: a nil option", ErrConfiguration)
		}
		if err := option(c); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// Store is the nonce store the checker spends in.
func (c *Checker) Store() NonceStore { return c.store }

// Algorithms are the algorithms the checker accepts.
func (c *Checker) Algorithms() []Algorithm { return slices.Clone(c.algorithms) }

// Window is how far `iat` may be from the checker's clock, either way.
func (c *Checker) Window() time.Duration { return c.window }

// CertificateRequired reports whether the checker refuses every proof when it
// is given no certificate hash.
func (c *Checker) CertificateRequired() bool { return c.requireCertificate }

type header struct {
	alg, typ string
	jwk      *JWK
	// names are the members of jwk, which [JWK] does not keep.
	names []string
}

type claims struct {
	ath, jti, rel string
	iat           *int64
}

// Check verifies that proof was signed by the key whose thumbprint is
// thumbprint (the token's `cnf.jkt`), over token, for the certificate whose
// SHA-256 is certificateHash, at a time within the window of now, and spends
// its nonce until until (normally the token's expiry), or until one second
// past the end of the proof's window if that is later.
//
// An empty certificateHash means the checker has no certificate of its own.
// The proof must then name no certificate either, since one it names cannot be
// checked, and a checker with [WithCertificateRequired] refuses it.
//
// The signature is verified before any claim is read, and the nonce is spent
// only once every other check has passed, so a corrupted proof cannot burn a
// genuine one's nonce.
func (c *Checker) Check(proof, token, certificateHash []byte, thumbprint string, now, until time.Time) error {
	if c == nil || c.store == nil {
		return fmt.Errorf("%w: a Checker must come from NewChecker", ErrConfiguration)
	}
	if len(proof) == 0 || len(proof) > MaxProofBytes {
		return fmt.Errorf("%w: proof length is out of range", ErrMalformed)
	}
	headerSegment, claimsSegment, signed, signature, err := split(proof)
	if err != nil {
		return err
	}

	h, err := decodeHeader(headerSegment)
	if err != nil {
		return fmt.Errorf("%w: header: %v", ErrMalformed, err)
	}
	if h.typ != Type || !slices.Contains(c.algorithms, Algorithm(h.alg)) {
		return fmt.Errorf("%w: alg %q, typ %q", ErrUnsupported, h.alg, h.typ)
	}
	if h.jwk == nil {
		return fmt.Errorf("%w: header carries no key", ErrMalformed)
	}
	for _, name := range privateMembers {
		if slices.Contains(h.names, name) {
			return fmt.Errorf("%w: the key carries private member %q", ErrMalformed, name)
		}
	}
	if alg, err := h.jwk.Algorithm(); err != nil {
		return err
	} else if alg != Algorithm(h.alg) {
		return fmt.Errorf("%w: alg %q with a %s key", ErrUnsupported, h.alg, alg)
	}
	_, key, err := h.jwk.publicKey()
	if err != nil {
		return err
	}
	if err := verify(key, signed, signature); err != nil {
		return err
	}

	// Without this, anybody could sign with a key of their own beside a stolen
	// token.
	presented, err := h.jwk.Thumbprint()
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(presented), []byte(thumbprint)) != 1 {
		return ErrWrongKey
	}

	cl, err := decodeClaims(claimsSegment)
	if err != nil {
		return fmt.Errorf("%w: claims: %v", ErrMalformed, err)
	}
	ath := sha256.Sum256(token)
	if subtle.ConstantTimeCompare([]byte(cl.ath), []byte(b64.EncodeToString(ath[:]))) != 1 {
		return ErrWrongToken
	}
	if len(certificateHash) == 0 && c.requireCertificate {
		return fmt.Errorf("%w: the checker requires a certificate and has none", ErrWrongCertificate)
	}
	if subtle.ConstantTimeCompare([]byte(cl.rel), []byte(b64.EncodeToString(certificateHash))) != 1 {
		return ErrWrongCertificate
	}
	if cl.iat == nil {
		return fmt.Errorf("%w: no iat", ErrMalformed)
	}
	issued := time.Unix(*cl.iat, 0)
	if issued.Before(now.Add(-c.window)) {
		return ErrExpired
	}
	if issued.After(now.Add(c.window)) {
		return ErrNotYetValid
	}
	if cl.jti == "" {
		return fmt.Errorf("%w: no jti to spend", ErrMalformed)
	}
	// The proof is accepted until issued+window, inclusive, and a store keeps
	// a nonce while its until is after now. A shorter until would let the
	// same proof in again once the store forgot it.
	if remember := issued.Add(c.window + time.Second); until.Before(remember) {
		until = remember
	}
	return c.store.Spend(cl.jti, until, now)
}

// split takes a compact JWS apart, keeping the signed bytes exactly as they
// arrived: the signature is over bytes, and a decode and re-encode need not
// reproduce them.
func split(jws []byte) (header, claims, signed, signature []byte, err error) {
	parts := bytes.Split(jws, []byte{'.'})
	if len(parts) != 3 {
		return nil, nil, nil, nil, fmt.Errorf("%w: expected three segments", ErrMalformed)
	}
	signature, decodeErr := b64.DecodeString(string(parts[2]))
	if decodeErr != nil {
		return nil, nil, nil, nil, fmt.Errorf("%w: signature is not base64url", ErrMalformed)
	}
	return parts[0], parts[1], jws[:len(parts[0])+1+len(parts[1])], signature, nil
}

func decodeHeader(segment []byte) (header, error) {
	members, err := decodeSegment(segment)
	if err != nil {
		return header{}, err
	}
	var h header
	if err := stringMembers(members, map[string]*string{"alg": &h.alg, "typ": &h.typ}); err != nil {
		return header{}, err
	}
	raw, ok := members["jwk"]
	if !ok {
		return h, nil
	}
	fields, err := object(raw)
	if err != nil {
		return header{}, fmt.Errorf("jwk: %v", err)
	}
	var k JWK
	if err := stringMembers(fields, map[string]*string{
		"kty": &k.Kty, "alg": &k.Alg, "pub": &k.Pub, "crv": &k.Crv, "x": &k.X, "y": &k.Y,
	}); err != nil {
		return header{}, fmt.Errorf("jwk: %v", err)
	}
	for name := range fields {
		h.names = append(h.names, name)
	}
	h.jwk = &k
	return h, nil
}

func decodeClaims(segment []byte) (claims, error) {
	members, err := decodeSegment(segment)
	if err != nil {
		return claims{}, err
	}
	var cl claims
	if err := stringMembers(members, map[string]*string{"ath": &cl.ath, "jti": &cl.jti, "rel": &cl.rel}); err != nil {
		return claims{}, err
	}
	if raw, ok := members["iat"]; ok {
		var iat int64
		if isNull(raw) || json.Unmarshal(raw, &iat) != nil {
			return claims{}, fmt.Errorf("iat is not an integer")
		}
		cl.iat = &iat
	}
	return cl, nil
}

func decodeSegment(segment []byte) (map[string]json.RawMessage, error) {
	raw, err := b64.DecodeString(string(segment))
	if err != nil {
		return nil, fmt.Errorf("not base64url")
	}
	return object(raw)
}

// stringMembers decodes each named member that is present into its target.
// Names match exactly, where encoding/json would match a struct field
// regardless of case, and a null is refused rather than read as absent.
func stringMembers(members map[string]json.RawMessage, targets map[string]*string) error {
	for name, target := range targets {
		raw, ok := members[name]
		if !ok {
			continue
		}
		if isNull(raw) || json.Unmarshal(raw, target) != nil {
			return fmt.Errorf("%s is not a string", name)
		}
	}
	return nil
}

func isNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

func verify(key any, signed, signature []byte) error {
	switch key := key.(type) {
	case *mldsa.PublicKey:
		if mldsa.Verify(key, signed, signature, nil) != nil {
			return ErrBadSignature
		}
	case *ecdsa.PublicKey:
		if len(signature) != es256SignatureSize {
			return ErrBadSignature
		}
		digest := sha256.Sum256(signed)
		r := new(big.Int).SetBytes(signature[:es256SignatureSize/2])
		s := new(big.Int).SetBytes(signature[es256SignatureSize/2:])
		if !ecdsa.Verify(key, digest[:], r, s) {
			return ErrBadSignature
		}
	default:
		return ErrUnsupported
	}
	return nil
}
