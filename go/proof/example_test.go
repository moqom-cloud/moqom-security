// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

package proof_test

import (
	"crypto/mldsa"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/moqom-cloud/moqom-security/go/proof"
)

// A device proves it holds the key its token names, and a relay checks the
// proof against its own certificate and spends the nonce.
func Example() {
	// On the device.
	device, err := proof.GenerateProver(proof.MLDSA87)
	if err != nil {
		panic(err)
	}
	jkt := device.Thumbprint() // the control plane puts this in the token's cnf.jkt
	token := []byte("eyJhbGciOiJNTC1EU0EtNjUi...")
	relayCertificate := sha256.Sum256([]byte("the relay's leaf certificate, DER"))
	now := time.Now()
	p, err := device.Prove(token, relayCertificate[:], proof.NewNonce(), now)
	if err != nil {
		panic(err)
	}

	// On the relay.
	checker, err := proof.NewChecker(proof.NewDefaultMemoryNonceStore())
	if err != nil {
		panic(err)
	}
	expiry := now.Add(15 * time.Minute)
	fmt.Println(checker.Check(p, token, relayCertificate[:], jkt, now, expiry))
	fmt.Println(proof.Class(checker.Check(p, token, relayCertificate[:], jkt, now, expiry)))
	// Output:
	// <nil>
	// replayed
}

// A device key is stored as its 32-byte ML-DSA-87 seed and loaded again.
func ExampleNewProver() {
	key, err := mldsa.GenerateKey(mldsa.MLDSA87())
	if err != nil {
		panic(err)
	}
	seed := key.Bytes()

	loaded, err := mldsa.NewPrivateKey(mldsa.MLDSA87(), seed)
	if err != nil {
		panic(err)
	}
	device, err := proof.NewProver(loaded)
	if err != nil {
		panic(err)
	}
	original, _ := proof.NewProver(key)
	fmt.Println(len(seed), device.Algorithm(), device.Thumbprint() == original.Thumbprint())
	// Output: 32 ML-DSA-87 true
}

// Each refusal names the check that failed.
func ExampleChecker_Check_refusals() {
	device, _ := proof.GenerateProver(proof.MLDSA87)
	stranger, _ := proof.GenerateProver(proof.MLDSA87)
	token := []byte("eyJhbGciOiJNTC1EU0EtNjUi...")
	relay := sha256.Sum256([]byte("relay A's leaf certificate"))
	other := sha256.Sum256([]byte("relay B's leaf certificate"))
	now := time.Now()
	expiry := now.Add(15 * time.Minute)
	checker, _ := proof.NewChecker(proof.NewDefaultMemoryNonceStore())

	check := func(p []byte, at time.Time) {
		fmt.Println(proof.Class(checker.Check(p, token, relay[:], device.Thumbprint(), at, expiry)))
	}
	p, _ := device.Prove([]byte("another token"), relay[:], proof.NewNonce(), now)
	check(p, now)
	p, _ = device.Prove(token, other[:], proof.NewNonce(), now)
	check(p, now)
	p, _ = stranger.Prove(token, relay[:], proof.NewNonce(), now)
	check(p, now)
	p, _ = device.Prove(token, relay[:], proof.NewNonce(), now.Add(-10*time.Minute))
	check(p, now)
	// Output:
	// wrong_token
	// wrong_certificate
	// wrong_key
	// expired
}

// Checkers that share a store share what has been spent, so a proof accepted
// on one connection is refused on every other.
func ExampleMemoryNonceStore() {
	store := proof.NewDefaultMemoryNonceStore()
	first, _ := proof.NewChecker(store)
	second, _ := proof.NewChecker(store, proof.WithAlgorithms(proof.MLDSA87))

	device, _ := proof.GenerateProver(proof.MLDSA87)
	token := []byte("eyJhbGciOiJNTC1EU0EtNjUi...")
	relay := sha256.Sum256([]byte("the relay's leaf certificate, DER"))
	now := time.Now()
	expiry := now.Add(15 * time.Minute)
	p, _ := device.Prove(token, relay[:], proof.NewNonce(), now)

	fmt.Println(first.Check(p, token, relay[:], device.Thumbprint(), now, expiry))
	fmt.Println(proof.Class(second.Check(p, token, relay[:], device.Thumbprint(), now, expiry)))
	fmt.Println(store.Remembered())
	// Output:
	// <nil>
	// replayed
	// 1
}
