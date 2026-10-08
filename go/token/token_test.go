// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

package token

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"slices"
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
	if _, err := NewSigner(seed(1)[:31]); !errors.Is(err, ErrKeyInvalid) || Class(err) != "key_invalid" {
		t.Errorf("a short seed gave %v", err)
	}
	if _, err := NewPublicKey("ES256", "k", nil); Class(err) != "key_unsupported" {
		t.Errorf("an ES256 key gave %v", err)
	}
}

func TestARawKeyOfTheWrongLengthIsRefused(t *testing.T) {
	signer, _ := NewSigner(seed(1))
	mldsa := signer.PublicKey().Bytes()
	ed := bytes.Repeat([]byte{7}, ed25519.PublicKeySize)
	if _, err := NewPublicKey(MLDSA65, "k", mldsa); err != nil {
		t.Errorf("an ML-DSA-65 key gave %v", err)
	}
	if _, err := NewPublicKey(EdDSA, "k", ed); err != nil {
		t.Errorf("an Ed25519 key gave %v", err)
	}
	for _, c := range []struct {
		algorithm Algorithm
		raw       []byte
	}{
		{MLDSA65, mldsa[:len(mldsa)-1]}, {MLDSA65, append(slices.Clone(mldsa), 0)}, {MLDSA65, ed}, {MLDSA65, nil},
		{EdDSA, ed[:31]}, {EdDSA, append(slices.Clone(ed), 0)}, {EdDSA, mldsa}, {EdDSA, nil},
	} {
		if _, err := NewPublicKey(c.algorithm, "k", c.raw); !errors.Is(err, ErrKeyInvalid) || Class(err) != "key_invalid" {
			t.Errorf("%s key of %d bytes gave %v", c.algorithm, len(c.raw), err)
		}
	}
}

func TestAVerifierLooksUpItsKeys(t *testing.T) {
	signer, _ := NewSigner(seed(1))
	if !NewVerifier("").IsEmpty() || NewVerifier("", signer.PublicKey()).IsEmpty() {
		t.Error("IsEmpty is wrong")
	}
	verifier := NewVerifier("", signer.PublicKey())
	if key, ok := verifier.Key(signer.ID()); !ok || key.ID() != signer.ID() {
		t.Error("the signer's key is not in the set")
	}
	if _, ok := verifier.Key("other"); ok {
		t.Error("a key that is not in the set was found")
	}
}
