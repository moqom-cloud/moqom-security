// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

package proof

import (
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// Algorithm is a proof's JOSE `alg`.
type Algorithm string

const (
	// MLDSA87 is ML-DSA-87 (FIPS 204), signing the message directly with an
	// empty context, as draft-ietf-cose-dilithium specifies for JOSE.
	MLDSA87 Algorithm = "ML-DSA-87"
)

// Algorithms is every algorithm this package implements: ML-DSA-87 only, so
// that every proof is post-quantum. ES256, ML-DSA-65 and every other algorithm
// are refused as [ErrUnsupported].
var Algorithms = []Algorithm{MLDSA87}

// privateMembers carry a private key: `d` (EC, OKP, RSA), RSA's other primes,
// oct's `k`, and AKP's `priv` and `seed`. A proof carrying one has leaked its
// device key and is refused.
var privateMembers = []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k", "priv", "seed"}

// b64 is base64url without padding, strict about the unused bits of the last
// character, so that one value has exactly one spelling.
var b64 = base64.RawURLEncoding.Strict()

// JWK is a device's public key as a JSON Web Key: kty "AKP" with `alg`
// "ML-DSA-87" and `pub`.
//
// Only the members a thumbprint is computed over are modelled. Anything else a
// device sends is ignored by the hash, so it is not accepted into a type that
// exists to be hashed.
type JWK struct {
	Kty string `json:"kty"`
	Alg string `json:"alg,omitempty"`
	Pub string `json:"pub,omitempty"`
}

// Algorithm is the proof algorithm this key signs with.
func (k JWK) Algorithm() (Algorithm, error) {
	if k.Kty == "AKP" && k.Alg == string(MLDSA87) {
		return MLDSA87, nil
	}
	return "", fmt.Errorf("%w: kty %q, alg %q", ErrUnsupported, k.Kty, k.Alg)
}

// Thumbprint is the JWK thumbprint, base64url SHA-256 of the canonical form
// draft-ietf-cose-dilithium gives AKP keys, as RFC 7638 computes it.
//
// The canonical form is rebuilt from the decoded key rather than copied from
// the members, so a key has one thumbprint however it was spelled.
func (k JWK) Thumbprint() (string, error) {
	canonical, err := k.canonical()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(canonical))
	return b64.EncodeToString(sum[:]), nil
}

// canonical is the required members in lexicographic order with no
// whitespace. Every value is base64url or a fixed name, none of which JSON
// escapes, so it is assembled rather than encoded.
func (k JWK) canonical() (string, error) {
	if _, err := k.Algorithm(); err != nil {
		return "", err
	}
	raw, err := decodeExact(k.Pub, mldsa.MLDSA87PublicKeySize, "pub")
	if err != nil {
		return "", err
	}
	return `{"alg":"ML-DSA-87","kty":"AKP","pub":"` + b64.EncodeToString(raw) + `"}`, nil
}

// publicKey parses the key for verification.
func (k JWK) publicKey() (*mldsa.PublicKey, error) {
	if _, err := k.Algorithm(); err != nil {
		return nil, err
	}
	raw, err := decodeExact(k.Pub, mldsa.MLDSA87PublicKeySize, "pub")
	if err != nil {
		return nil, err
	}
	key, err := mldsa.NewPublicKey(mldsa.MLDSA87(), raw)
	if err != nil {
		return nil, fmt.Errorf("%w: pub is not an ML-DSA-87 key", ErrMalformed)
	}
	return key, nil
}

// jwkOf renders a public key as the JWK a proof carries.
func jwkOf(public any) (JWK, error) {
	switch key := public.(type) {
	case *mldsa.PublicKey:
		if len(key.Bytes()) != mldsa.MLDSA87PublicKeySize {
			return JWK{}, fmt.Errorf("%w: only ML-DSA-87 keys are supported", ErrUnsupported)
		}
		return JWK{Kty: "AKP", Alg: string(MLDSA87), Pub: b64.EncodeToString(key.Bytes())}, nil
	default:
		return JWK{}, fmt.Errorf("%w: %T", ErrUnsupported, public)
	}
}

// decodeExact decodes a base64url member that must be exactly size bytes. A
// shorter or longer value is a different key, not a differently padded one.
func decodeExact(value string, size int, member string) ([]byte, error) {
	raw, err := b64.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%w: %s is not base64url", ErrMalformed, member)
	}
	if len(raw) != size {
		return nil, fmt.Errorf("%w: %s is %d bytes, want %d", ErrMalformed, member, len(raw), size)
	}
	return raw, nil
}
