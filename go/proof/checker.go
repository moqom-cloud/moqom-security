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
// either way.
const DefaultWindow = 5 * time.Minute

// Checker checks proofs and spends their nonces.
type Checker struct {
	// Store remembers spent nonces. Required: without it a proof is not
	// single-use.
	Store NonceStore
	// Algorithms accepted; nil means [Algorithms].
	Algorithms []Algorithm
	// Window is how far `iat` may be from now, either way; zero means
	// [DefaultWindow].
	Window time.Duration
}

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	JWK *JWK   `json:"jwk"`
}

// jwkMembers is the header again, for the names of the key's members, which
// [JWK] does not keep.
type jwkMembers struct {
	JWK map[string]json.RawMessage `json:"jwk"`
}

type claims struct {
	Ath string `json:"ath"`
	Iat *int64 `json:"iat"`
	Jti string `json:"jti"`
	Rel string `json:"rel"`
}

// Check verifies that proof was signed by the key whose thumbprint is
// thumbprint (the token's `cnf.jkt`), over token, for the certificate whose
// SHA-256 is certificateHash, at a time within the window of now, and spends
// its nonce until until (normally the token's expiry).
//
// The signature is verified before any claim is read, and the nonce is spent
// only once every other check has passed, so a corrupted proof cannot burn a
// genuine one's nonce.
func (c *Checker) Check(proof, token, certificateHash []byte, thumbprint string, now, until time.Time) error {
	if c.Store == nil {
		return fmt.Errorf("proof: a Checker needs a NonceStore")
	}
	if len(proof) == 0 || len(proof) > MaxProofBytes {
		return fmt.Errorf("%w: proof length is out of range", ErrMalformed)
	}
	headerSegment, claimsSegment, signed, signature, err := split(proof)
	if err != nil {
		return err
	}

	var h header
	if err := decodeSegment(headerSegment, &h); err != nil {
		return fmt.Errorf("%w: header: %v", ErrMalformed, err)
	}
	accepted := c.Algorithms
	if accepted == nil {
		accepted = Algorithms
	}
	if h.Typ != Type || !slices.Contains(accepted, Algorithm(h.Alg)) {
		return fmt.Errorf("%w: alg %q, typ %q", ErrUnsupported, h.Alg, h.Typ)
	}
	if h.JWK == nil {
		return fmt.Errorf("%w: header carries no key", ErrMalformed)
	}
	var members jwkMembers
	if err := decodeSegment(headerSegment, &members); err != nil {
		return fmt.Errorf("%w: header: %v", ErrMalformed, err)
	}
	for _, name := range privateMembers {
		if _, ok := members.JWK[name]; ok {
			return fmt.Errorf("%w: the key carries private member %q", ErrMalformed, name)
		}
	}
	if alg, err := h.JWK.Algorithm(); err != nil {
		return err
	} else if alg != Algorithm(h.Alg) {
		return fmt.Errorf("%w: alg %q with a %s key", ErrUnsupported, h.Alg, alg)
	}
	_, key, err := h.JWK.publicKey()
	if err != nil {
		return err
	}
	if err := verify(key, signed, signature); err != nil {
		return err
	}

	// Without this, anybody could sign with a key of their own beside a stolen
	// token.
	presented, err := h.JWK.Thumbprint()
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(presented), []byte(thumbprint)) != 1 {
		return ErrWrongKey
	}

	var cl claims
	if err := decodeSegment(claimsSegment, &cl); err != nil {
		return fmt.Errorf("%w: claims: %v", ErrMalformed, err)
	}
	ath := sha256.Sum256(token)
	if subtle.ConstantTimeCompare([]byte(cl.Ath), []byte(b64.EncodeToString(ath[:]))) != 1 {
		return ErrWrongToken
	}
	if subtle.ConstantTimeCompare([]byte(cl.Rel), []byte(b64.EncodeToString(certificateHash))) != 1 {
		return ErrWrongCertificate
	}
	if cl.Iat == nil {
		return fmt.Errorf("%w: no iat", ErrMalformed)
	}
	window := c.Window
	if window == 0 {
		window = DefaultWindow
	}
	issued := time.Unix(*cl.Iat, 0)
	if issued.Before(now.Add(-window)) {
		return ErrExpired
	}
	if issued.After(now.Add(window)) {
		return ErrNotYetValid
	}
	if cl.Jti == "" {
		return fmt.Errorf("%w: no jti to spend", ErrMalformed)
	}
	return c.Store.Spend(cl.Jti, until, now)
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

func decodeSegment(segment []byte, into any) error {
	raw, err := b64.DecodeString(string(segment))
	if err != nil {
		return fmt.Errorf("not base64url")
	}
	if err := json.Unmarshal(raw, into); err != nil {
		return fmt.Errorf("not JSON of the right shape")
	}
	return nil
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
