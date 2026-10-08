// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

package proof

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

var (
	testNow   = time.Unix(1_700_000_000, 0)
	testUntil = testNow.Add(10 * time.Minute)
)

func TestARoundTripInEachAlgorithm(t *testing.T) {
	for _, alg := range Algorithms {
		t.Run(string(alg), func(t *testing.T) {
			prover, err := GenerateProver(alg)
			if err != nil {
				t.Fatal(err)
			}
			token := []byte("a.token")
			proof, err := prover.Prove(token, certificate[:], NewNonce(), testNow)
			if err != nil {
				t.Fatal(err)
			}
			checker := Checker{Store: NewMemoryNonceStore(0)}
			if err := checker.Check(proof, token, certificate[:], prover.Thumbprint(), testNow, testUntil); err != nil {
				t.Fatalf("Check() = %v", err)
			}
			if err := checker.Check(proof, token, certificate[:], prover.Thumbprint(), testNow, testUntil); !errors.Is(err, ErrReplayed) {
				t.Errorf("second Check() = %v, want ErrReplayed", err)
			}
		})
	}
}

// An ML-DSA-65 proof carries a 1,952-byte key and a 3,309-byte signature,
// both base64url, and must stay inside the limit with room to spare.
func TestAnMLDSAProofFitsTheLimit(t *testing.T) {
	prover, err := GenerateProver(MLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := prover.Prove([]byte(strings.Repeat("t", 5000)), certificate[:], NewNonce(), testNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(proof) > MaxProofBytes*3/4 {
		t.Errorf("an ML-DSA-65 proof is %d bytes, too close to the %d limit", len(proof), MaxProofBytes)
	}
}

func TestAJWKSurvivesJSON(t *testing.T) {
	prover, err := GenerateProver(MLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(prover.JWK())
	if err != nil {
		t.Fatal(err)
	}
	var decoded JWK
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if thumbprint, err := decoded.Thumbprint(); err != nil || thumbprint != prover.Thumbprint() {
		t.Errorf("Thumbprint() = %q, %v; want %q", thumbprint, err, prover.Thumbprint())
	}
	if strings.Contains(string(encoded), `"x"`) || strings.Contains(string(encoded), `"crv"`) {
		t.Errorf("an AKP key carries EC members: %s", encoded)
	}
}

func TestACheckerCanBeLimitedToOneAlgorithm(t *testing.T) {
	prover, err := GenerateProver(ES256)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := prover.Prove([]byte("t"), certificate[:], NewNonce(), testNow)
	if err != nil {
		t.Fatal(err)
	}
	checker := Checker{Store: NewMemoryNonceStore(0), Algorithms: []Algorithm{MLDSA65}}
	if err := checker.Check(proof, []byte("t"), certificate[:], prover.Thumbprint(), testNow, testUntil); !errors.Is(err, ErrUnsupported) {
		t.Errorf("Check() = %v, want ErrUnsupported", err)
	}
}

func TestAProofNeedsANonce(t *testing.T) {
	prover, err := GenerateProver(MLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prover.Prove([]byte("t"), certificate[:], "", testNow); !errors.Is(err, ErrMalformed) {
		t.Errorf("Prove() = %v, want ErrMalformed", err)
	}
	if NewNonce() == NewNonce() {
		t.Error("two nonces are the same")
	}
}

var errRefused = errors.New("the key refused")

// refusingSigner holds a public key and refuses every signature, as a locked
// hardware key does.
type refusingSigner struct{ public crypto.PublicKey }

func (s refusingSigner) Public() crypto.PublicKey { return s.public }

func (refusingSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errRefused
}

func TestASignerThatRefusesIsClassedSigning(t *testing.T) {
	ml, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	es, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, public := range []crypto.PublicKey{ml.Public(), es.Public()} {
		prover, err := NewProver(refusingSigner{public})
		if err != nil {
			t.Fatal(err)
		}
		_, err = prover.Prove([]byte("t"), certificate[:], NewNonce(), testNow)
		if !errors.Is(err, ErrSigning) || !errors.Is(err, errRefused) || Class(err) != "signing" {
			t.Errorf("%s: Prove() = %v (%q), want ErrSigning wrapping the signer's error", prover.Algorithm(), err, Class(err))
		}
	}
}

func TestTheStoreSweepsExpiredNoncesAndFailsClosed(t *testing.T) {
	store := NewMemoryNonceStore(2)
	for _, nonce := range []string{"a", "b"} {
		if err := store.Spend(nonce, testNow, testNow); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Spend("c", testUntil, testNow.Add(time.Second)); err != nil {
		t.Fatalf("expired nonces were not swept: %v", err)
	}
	if err := store.Spend("d", testUntil, testNow.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := store.Spend("e", testUntil, testNow.Add(time.Second)); !errors.Is(err, ErrOverloaded) {
		t.Errorf("Spend() = %v, want ErrOverloaded", err)
	}
}
