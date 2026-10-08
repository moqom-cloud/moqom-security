// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

package token

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestSignedTokensVerifyAndKeysRotate(t *testing.T) {
	retiring, err := GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	incoming, err := GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	verifier := NewVerifier("https://api.moqom.cloud", retiring.PublicKey(), incoming.PublicKey())
	now := time.Unix(vectorNow, 0)
	for _, signer := range []*Signer{retiring, incoming} {
		signed, err := signer.Sign(baseClaims())
		if err != nil {
			t.Fatal(err)
		}
		if claims, err := verifier.Verify(signed, now); err != nil || claims != baseClaims() {
			t.Errorf("a token from %s: %v", signer.ID(), err)
		}
	}
}

func TestASeedAlwaysNamesTheSameKey(t *testing.T) {
	one, _ := NewSigner(seed(9))
	two, _ := NewSigner(one.Seed())
	if one.ID() != two.ID() || one.ID() != KeyID(one.PublicKey().Bytes()) {
		t.Errorf("a seed gave %s then %s", one.ID(), two.ID())
	}
	if one.WithID("named").ID() != "named" || one.ID() == "named" {
		t.Error("WithID changed the original")
	}
}

func TestAJWKSetRoundTripsInEitherShape(t *testing.T) {
	signer, _ := NewSigner(seed(1))
	legacy, _ := NewPublicKey(EdDSA, "old", ed25519.NewKeyFromSeed(seed(4)).Public().(ed25519.PublicKey))
	var jwks []json.RawMessage
	for _, key := range []PublicKey{signer.PublicKey(), legacy} {
		encoded, err := key.JWK()
		if err != nil {
			t.Fatal(err)
		}
		jwks = append(jwks, encoded)
	}
	bare, _ := json.Marshal(jwks)
	wrapped, _ := json.Marshal(map[string]any{"keys": jwks})
	for _, document := range [][]byte{bare, wrapped} {
		keys, err := ParseJWKSet(document)
		if err != nil || len(keys) != 2 || keys[0].ID() != signer.ID() || keys[1].Algorithm() != EdDSA {
			t.Fatalf("%s: %v %v", document, keys, err)
		}
	}
	for _, document := range []string{
		`[{"kty":"AKP","alg":"ML-DSA-44","kid":"k","pub":"AAAA"}]`,
		`[{"kty":"AKP","alg":"ML-DSA-65","kid":"k","pub":"AAAA"}]`,
		`[{"kty":"OKP","crv":"P-256","kid":"k","x":"AAAA"}]`,
		`["not an object"]`,
	} {
		if _, err := ParseJWKSet([]byte(document)); err == nil {
			t.Errorf("%s was accepted", document)
		}
	}
}

func TestErrorsCarryTheirClass(t *testing.T) {
	signer, _ := NewSigner(seed(1))
	claims := baseClaims()
	claims.Expires = claims.IssuedAt + int64(MaxLifetime/time.Second) + 1
	if _, err := signer.Sign(claims); !errors.Is(err, ErrLifetime) || Class(err) != "lifetime" {
		t.Errorf("an over-long token gave %v", err)
	}
	if Class(errors.New("other")) != "" {
		t.Error("an unrelated error has a class")
	}
}
