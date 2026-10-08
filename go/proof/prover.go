// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

package proof

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"time"
)

// Type is the JWS `typ` of a proof, so that a JWS made for anything else,
// including a token from the same deployment, is not one.
const Type = "MOQT-POP"

// Prover holds a device key and signs proofs with it.
type Prover struct {
	signer        crypto.Signer
	algorithm     Algorithm
	jwk           JWK
	header        string
	thumbprint    string
	deterministic bool
}

// NewProver wraps a device key: an *mldsa.PrivateKey for ML-DSA-65 or an
// *ecdsa.PrivateKey on P-256 for ES256.
func NewProver(key crypto.Signer) (*Prover, error) {
	jwk, err := jwkOf(key.Public())
	if err != nil {
		return nil, err
	}
	alg, err := jwk.Algorithm()
	if err != nil {
		return nil, err
	}
	canonical, err := jwk.canonical()
	if err != nil {
		return nil, err
	}
	thumbprint, err := jwk.Thumbprint()
	if err != nil {
		return nil, err
	}
	return &Prover{
		signer:     key,
		algorithm:  alg,
		jwk:        jwk,
		header:     `{"alg":"` + string(alg) + `","typ":"` + Type + `","jwk":` + canonical + `}`,
		thumbprint: thumbprint,
	}, nil
}

// GenerateProver makes a new software key for alg.
func GenerateProver(alg Algorithm) (*Prover, error) {
	switch alg {
	case MLDSA65:
		key, err := mldsa.GenerateKey(mldsa.MLDSA65())
		if err != nil {
			return nil, err
		}
		return NewProver(key)
	case ES256:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		return NewProver(key)
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupported, alg)
	}
}

// Deterministic makes this prover sign deterministically (ML-DSA's
// deterministic variant, RFC 6979 for ECDSA), for reproducible test vectors.
// Either form verifies the same way.
func (p *Prover) Deterministic() *Prover {
	copied := *p
	copied.deterministic = true
	return &copied
}

// Algorithm is the algorithm this prover signs with.
func (p *Prover) Algorithm() Algorithm { return p.algorithm }

// JWK is the public key, as a proof carries it and `/join` receives it.
func (p *Prover) JWK() JWK { return p.jwk }

// Thumbprint is the JWK thumbprint, what a token's `cnf.jkt` must equal.
func (p *Prover) Thumbprint() string { return p.thumbprint }

// Prove signs a proof that this key holds token, for the peer whose leaf
// certificate has SHA-256 certificateHash, using nonce as its single-use `jti`
// and issuedAt as its `iat`.
//
// nonce must be fresh for every proof; [NewNonce] makes one. An empty
// certificateHash binds the proof to no certificate, which a checker that
// knows its own refuses.
func (p *Prover) Prove(token, certificateHash []byte, nonce string, issuedAt time.Time) ([]byte, error) {
	if nonce == "" {
		return nil, fmt.Errorf("%w: a proof needs a nonce", ErrMalformed)
	}
	quotedNonce, err := json.Marshal(nonce)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	ath := sha256.Sum256(token)
	claims := `{"ath":"` + b64.EncodeToString(ath[:]) +
		`","iat":` + strconv.FormatInt(issuedAt.Unix(), 10) +
		`,"jti":` + string(quotedNonce) +
		`,"rel":"` + b64.EncodeToString(certificateHash) + `"}`

	signed := b64.EncodeToString([]byte(p.header)) + "." + b64.EncodeToString([]byte(claims))
	signature, err := p.sign([]byte(signed))
	if err != nil {
		return nil, err
	}
	return []byte(signed + "." + b64.EncodeToString(signature)), nil
}

func (p *Prover) sign(message []byte) ([]byte, error) {
	switch key := p.signer.(type) {
	case *mldsa.PrivateKey:
		if p.deterministic {
			return key.SignDeterministic(message, nil)
		}
		return key.Sign(nil, message, nil)
	case *ecdsa.PrivateKey:
		digest := sha256.Sum256(message)
		random := rand.Reader
		if p.deterministic {
			random = nil
		}
		der, err := key.Sign(random, digest[:], crypto.SHA256)
		if err != nil {
			return nil, err
		}
		return fixedWidth(der)
	default:
		// Anything else that holds one of these keys, a hardware signer for
		// instance, is asked as a crypto.Signer is.
		if p.algorithm == MLDSA65 {
			return p.signer.Sign(rand.Reader, message, &mldsa.Options{})
		}
		digest := sha256.Sum256(message)
		der, err := p.signer.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			return nil, err
		}
		return fixedWidth(der)
	}
}

// fixedWidth converts an ASN.1 ECDSA signature to the r||s form JWS uses.
func fixedWidth(der []byte) ([]byte, error) {
	var parsed struct{ R, S *big.Int }
	if rest, err := asn1.Unmarshal(der, &parsed); err != nil || len(rest) != 0 {
		return nil, fmt.Errorf("proof: ECDSA signature is not ASN.1")
	}
	out := make([]byte, es256SignatureSize)
	parsed.R.FillBytes(out[:es256SignatureSize/2])
	parsed.S.FillBytes(out[es256SignatureSize/2:])
	return out, nil
}

// NewNonce is a fresh 128-bit nonce, base64url.
func NewNonce() string {
	var bytes [16]byte
	_, _ = rand.Read(bytes[:])
	return b64.EncodeToString(bytes[:])
}
