// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

package proof

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// Algorithm is a proof's JOSE `alg`.
type Algorithm string

const (
	// MLDSA65 is ML-DSA-65 (FIPS 204), signing the message directly with an
	// empty context, as draft-ietf-cose-dilithium specifies for JOSE.
	MLDSA65 Algorithm = "ML-DSA-65"
	// ES256 is ECDSA on P-256 with SHA-256, the signature as fixed-width r||s.
	ES256 Algorithm = "ES256"
)

// Algorithms is every algorithm a [Checker] accepts by default, preferred first.
var Algorithms = []Algorithm{MLDSA65, ES256}

// privateMembers carry a private key: `d` (EC, OKP, RSA), RSA's other primes,
// oct's `k`, and AKP's `priv` and `seed`. A proof carrying one has leaked its
// device key and is refused.
var privateMembers = []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k", "priv", "seed"}

const (
	p256CoordinateSize = 32
	es256SignatureSize = 64
)

// b64 is base64url without padding, strict about the unused bits of the last
// character, so that one value has exactly one spelling.
var b64 = base64.RawURLEncoding.Strict()

// JWK is a device's public key as a JSON Web Key: kty "AKP" with `alg` and
// `pub` for ML-DSA-65, kty "EC" with `crv`, `x` and `y` for P-256.
//
// Only the members a thumbprint is computed over are modelled. Anything else a
// device sends is ignored by the hash, so it is not accepted into a type that
// exists to be hashed.
type JWK struct {
	Kty string `json:"kty"`
	Alg string `json:"alg,omitempty"`
	Pub string `json:"pub,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

// Algorithm is the proof algorithm this key signs with.
func (k JWK) Algorithm() (Algorithm, error) {
	switch {
	case k.Kty == "AKP" && k.Alg == string(MLDSA65):
		return MLDSA65, nil
	case k.Kty == "EC" && k.Crv == "P-256":
		return ES256, nil
	default:
		return "", fmt.Errorf("%w: kty %q, alg %q, crv %q", ErrUnsupported, k.Kty, k.Alg, k.Crv)
	}
}

// Thumbprint is the JWK thumbprint, base64url SHA-256 of the canonical form:
// RFC 7638 for EC, draft-ietf-cose-dilithium for AKP.
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
	alg, err := k.Algorithm()
	if err != nil {
		return "", err
	}
	switch alg {
	case MLDSA65:
		raw, err := decodeExact(k.Pub, mldsa.MLDSA65PublicKeySize, "pub")
		if err != nil {
			return "", err
		}
		return `{"alg":"ML-DSA-65","kty":"AKP","pub":"` + b64.EncodeToString(raw) + `"}`, nil
	default:
		x, err := decodeExact(k.X, p256CoordinateSize, "x")
		if err != nil {
			return "", err
		}
		y, err := decodeExact(k.Y, p256CoordinateSize, "y")
		if err != nil {
			return "", err
		}
		return `{"crv":"P-256","kty":"EC","x":"` + b64.EncodeToString(x) +
			`","y":"` + b64.EncodeToString(y) + `"}`, nil
	}
}

// publicKey parses the key for verification.
func (k JWK) publicKey() (Algorithm, any, error) {
	alg, err := k.Algorithm()
	if err != nil {
		return "", nil, err
	}
	switch alg {
	case MLDSA65:
		raw, err := decodeExact(k.Pub, mldsa.MLDSA65PublicKeySize, "pub")
		if err != nil {
			return "", nil, err
		}
		key, err := mldsa.NewPublicKey(mldsa.MLDSA65(), raw)
		if err != nil {
			return "", nil, fmt.Errorf("%w: pub is not an ML-DSA-65 key", ErrMalformed)
		}
		return alg, key, nil
	default:
		x, err := decodeExact(k.X, p256CoordinateSize, "x")
		if err != nil {
			return "", nil, err
		}
		y, err := decodeExact(k.Y, p256CoordinateSize, "y")
		if err != nil {
			return "", nil, err
		}
		point := append(append([]byte{0x04}, x...), y...)
		key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
		if err != nil {
			return "", nil, fmt.Errorf("%w: x and y are not a P-256 point", ErrMalformed)
		}
		return alg, key, nil
	}
}

// jwkOf renders a public key as the JWK a proof carries.
func jwkOf(public any) (JWK, error) {
	switch key := public.(type) {
	case *mldsa.PublicKey:
		if len(key.Bytes()) != mldsa.MLDSA65PublicKeySize {
			return JWK{}, fmt.Errorf("%w: only ML-DSA-65 keys are supported", ErrUnsupported)
		}
		return JWK{Kty: "AKP", Alg: string(MLDSA65), Pub: b64.EncodeToString(key.Bytes())}, nil
	case *ecdsa.PublicKey:
		if key.Curve != elliptic.P256() {
			return JWK{}, fmt.Errorf("%w: only P-256 keys are supported", ErrUnsupported)
		}
		point, err := key.Bytes()
		if err != nil {
			return JWK{}, fmt.Errorf("%w: %v", ErrMalformed, err)
		}
		return JWK{
			Kty: "EC",
			Crv: "P-256",
			X:   b64.EncodeToString(point[1 : 1+p256CoordinateSize]),
			Y:   b64.EncodeToString(point[1+p256CoordinateSize:]),
		}, nil
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
