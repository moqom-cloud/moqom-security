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
	"slices"
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
			checker, err := NewChecker(NewDefaultMemoryNonceStore())
			if err != nil {
				t.Fatal(err)
			}
			if err := checker.Check(proof, token, certificate[:], prover.Thumbprint(), testNow, testUntil); err != nil {
				t.Fatalf("Check() = %v", err)
			}
			if err := checker.Check(proof, token, certificate[:], prover.Thumbprint(), testNow, testUntil); !errors.Is(err, ErrReplayed) {
				t.Errorf("second Check() = %v, want ErrReplayed", err)
			}
		})
	}
}

// An ML-DSA-87 proof carries a 2,592-byte key and a 4,627-byte signature,
// both base64url, and must stay inside the limit with room to spare.
func TestAnMLDSAProofFitsTheLimit(t *testing.T) {
	prover, err := GenerateProver(MLDSA87)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := prover.Prove([]byte(strings.Repeat("t", 5000)), certificate[:], NewNonce(), testNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(proof) > MaxProofBytes*3/4 {
		t.Errorf("an ML-DSA-87 proof is %d bytes, too close to the %d limit", len(proof), MaxProofBytes)
	}
}

func TestAJWKSurvivesJSON(t *testing.T) {
	prover, err := GenerateProver(MLDSA87)
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

// Only ML-DSA-87: a P-256 key makes no prover, and ES256 is no algorithm.
func TestClassicalKeysAreRefused(t *testing.T) {
	es, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewProver(es); !errors.Is(err, ErrUnsupported) {
		t.Errorf("NewProver(P-256) = %v, want ErrUnsupported", err)
	}
	if _, err := GenerateProver("ES256"); !errors.Is(err, ErrUnsupported) {
		t.Errorf("GenerateProver(ES256) = %v, want ErrUnsupported", err)
	}
	if _, err := NewChecker(NewDefaultMemoryNonceStore(), WithAlgorithms("ES256")); !errors.Is(err, ErrConfiguration) {
		t.Errorf("WithAlgorithms(ES256) = %v, want ErrConfiguration", err)
	}
	if !slices.Equal(Algorithms, []Algorithm{MLDSA87}) {
		t.Errorf("Algorithms = %v", Algorithms)
	}
}

func TestAProofNeedsANonce(t *testing.T) {
	prover, err := GenerateProver(MLDSA87)
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
	ml, err := mldsa.GenerateKey(mldsa.MLDSA87())
	if err != nil {
		t.Fatal(err)
	}
	prover, err := NewProver(refusingSigner{ml.Public()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = prover.Prove([]byte("t"), certificate[:], NewNonce(), testNow)
	if !errors.Is(err, ErrSigning) || !errors.Is(err, errRefused) || Class(err) != "signing" {
		t.Errorf("Prove() = %v (%q), want ErrSigning wrapping the signer's error", err, Class(err))
	}
}

func TestTheStoreSweepsExpiredNoncesAndFailsClosed(t *testing.T) {
	store, err := NewMemoryNonceStore(2)
	if err != nil {
		t.Fatal(err)
	}
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

func TestSettingsThatCannotWorkAreRefusedAtConstruction(t *testing.T) {
	store := NewDefaultMemoryNonceStore()
	_, zero := NewMemoryNonceStore(0)
	_, negative := NewMemoryNonceStore(-1)
	_, noStore := NewChecker(nil)
	_, zeroWindow := NewChecker(store, WithWindow(0))
	_, negativeWindow := NewChecker(store, WithWindow(-time.Second))
	_, noAlgorithms := NewChecker(store, WithAlgorithms())
	_, unknownAlgorithm := NewChecker(store, WithAlgorithms("EdDSA"))
	var unbuilt Checker
	var unbuiltStore MemoryNonceStore
	for name, err := range map[string]error{
		"capacity 0":        zero,
		"capacity -1":       negative,
		"no store":          noStore,
		"window 0":          zeroWindow,
		"window -1s":        negativeWindow,
		"no algorithms":     noAlgorithms,
		"unknown algorithm": unknownAlgorithm,
		"a zero Checker":    unbuilt.Check([]byte("p"), []byte("t"), nil, "jkt", testNow, testUntil),
		"a zero store":      unbuiltStore.Spend("n", testUntil, testNow),
		"a nil *Checker":    (*Checker)(nil).Check([]byte("p"), []byte("t"), nil, "jkt", testNow, testUntil),
	} {
		if !errors.Is(err, ErrConfiguration) || Class(err) != "configuration" {
			t.Errorf("%s: %v (%q), want ErrConfiguration", name, err, Class(err))
		}
	}

	checker, err := NewChecker(store)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(checker.Algorithms(), Algorithms) || checker.Window() != DefaultWindow ||
		checker.CertificateRequired() || store.Capacity() != DefaultCapacity {
		t.Errorf("defaults: %v %v %v %d", checker.Algorithms(), checker.Window(), checker.CertificateRequired(), store.Capacity())
	}
}

// A caller that passes an until earlier than the end of the proof's window
// must not get the proof accepted twice once the store sweeps.
func TestAShortUntilCannotReopenReplay(t *testing.T) {
	prover, err := GenerateProver(MLDSA87)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewMemoryNonceStore(2)
	if err != nil {
		t.Fatal(err)
	}
	checker, err := NewChecker(store)
	if err != nil {
		t.Fatal(err)
	}
	token := []byte("a.token")
	proof, err := prover.Prove(token, certificate[:], NewNonce(), testNow)
	if err != nil {
		t.Fatal(err)
	}
	if err := checker.Check(proof, token, certificate[:], prover.Thumbprint(), testNow, testNow); err != nil {
		t.Fatal(err)
	}
	// Fill the store so that the next spend sweeps whatever has expired.
	if err := store.Spend("filler", testNow, testNow); err != nil {
		t.Fatal(err)
	}
	edge := testNow.Add(DefaultWindow)
	if err := checker.Check(proof, token, certificate[:], prover.Thumbprint(), edge, edge); !errors.Is(err, ErrReplayed) {
		t.Errorf("at the edge of the window: %v, want ErrReplayed", err)
	}
	if store.Remembered() != 1 {
		t.Errorf("remembered %d, want only the proof's nonce", store.Remembered())
	}
}
