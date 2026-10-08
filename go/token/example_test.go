// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

package token_test

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/moqom-cloud/moqom-security/go/token"
)

// Mint a token for a device, publish the key as a JWK set, and verify the
// token the way a relay does.
func Example() {
	// Generate a key once and keep its 32-byte seed in your secret store.
	generated, err := token.GenerateSigner()
	if err != nil {
		log.Fatal(err)
	}
	seed := generated.Seed()

	// Load it under the key ID your JWK set publishes.
	signer, err := token.NewSigner(seed)
	if err != nil {
		log.Fatal(err)
	}
	signer = signer.WithID("2026-10")

	now := time.Now()
	jws, err := signer.Sign(token.Claims{
		Issuer:   "https://api.example.com",
		Subject:  "ada",
		Tenant:   "acme",
		ID:       "c6c1f2d0",
		IssuedAt: now.Unix(),
		Expires:  now.Add(10 * time.Minute).Unix(),
		// The RFC 7638 thumbprint of the device's key, from moqom-proof.
		Confirmation: token.Confirmation{Thumbprint: "MpXqvQAmv7Y3Kk9dHnJpLwRtUvXyZaBcDeFgHiJkLmM"},
		Grant:        token.Grant{Room: "room-42", Publish: 3, Owner: true},
	})
	if err != nil {
		log.Fatal(err)
	}

	// A relay reads the published JWK set and verifies.
	jwk, err := signer.PublicKey().JWK()
	if err != nil {
		log.Fatal(err)
	}
	keys, err := token.ParseJWKSet([]byte(`{"keys":[` + string(jwk) + `]}`))
	if err != nil {
		log.Fatal(err)
	}
	verifier := token.NewVerifier("https://api.example.com", keys...).ForTenant("acme")
	claims, err := verifier.Verify(jws, time.Now())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(claims.Subject, claims.Tenant, claims.Grant.Room, claims.Grant.Publish, claims.Grant.Owner)
	// Output: ada acme room-42 3 true
}

// An expired token, a key ID the verifier does not hold, and another key
// published under the token's key ID.
func ExampleVerifier_Verify_errors() {
	signer, err := token.GenerateSigner()
	if err != nil {
		log.Fatal(err)
	}
	now := time.Now()
	jws, err := signer.Sign(token.Claims{
		Subject:      "ada",
		Tenant:       "acme",
		IssuedAt:     now.Unix(),
		Expires:      now.Add(10 * time.Minute).Unix(),
		Confirmation: token.Confirmation{Thumbprint: "MpXqvQAmv7Y3Kk9dHnJpLwRtUvXyZaBcDeFgHiJkLmM"},
	})
	if err != nil {
		log.Fatal(err)
	}
	verifier := token.NewVerifier("", signer.PublicKey())

	// Eleven minutes on, the ten-minute token is past its expiry and the 30-second skew.
	_, err = verifier.Verify(jws, now.Add(11*time.Minute))
	fmt.Println(errors.Is(err, token.ErrExpired), token.Class(err))

	other, err := token.GenerateSigner()
	if err != nil {
		log.Fatal(err)
	}
	_, err = token.NewVerifier("", other.PublicKey()).Verify(jws, now)
	fmt.Println(errors.Is(err, token.ErrUnknownKey), token.Class(err))

	impostor := other.WithID(signer.ID()).PublicKey()
	_, err = token.NewVerifier("", impostor).Verify(jws, now)
	fmt.Println(errors.Is(err, token.ErrBadSignature), token.Class(err))
	// Output:
	// true expired
	// true unknown_key
	// true bad_signature
}
