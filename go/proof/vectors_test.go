// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

package proof

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func readVectors[T any](t *testing.T, name string) (vectorFile, []T) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorDir, name))
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		vectorFile
		Cases []T `json:"cases"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if len(file.Cases) == 0 {
		t.Fatalf("%s: no cases", name)
	}
	return file.vectorFile, file.Cases
}

func decodeHex(t *testing.T, value string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestKeyVectors(t *testing.T) {
	_, cases := readVectors[keyCase](t, "keys.json")
	for _, v := range cases {
		t.Run(v.Name, func(t *testing.T) {
			var prover *Prover
			var err error
			switch Algorithm(v.Alg) {
			case MLDSA65:
				var key *mldsa.PrivateKey
				key, err = mldsa.NewPrivateKey(mldsa.MLDSA65(), decodeHex(t, v.SeedHex))
				if err == nil {
					prover, err = NewProver(key)
				}
			case ES256:
				var key *ecdsa.PrivateKey
				key, err = ecdsa.ParseRawPrivateKey(elliptic.P256(), decodeHex(t, v.PrivateHex))
				if err == nil {
					prover, err = NewProver(key)
				}
				parsed, perr := x509.ParsePKCS8PrivateKey(decodeHex(t, v.PKCS8Hex))
				if perr != nil || !parsed.(*ecdsa.PrivateKey).Equal(key) {
					t.Errorf("pkcs8_hex is not the same key: %v", perr)
				}
			default:
				t.Fatalf("unknown alg %q", v.Alg)
			}
			if err != nil {
				t.Fatal(err)
			}
			if prover.JWK() != v.JWK {
				t.Errorf("JWK = %+v, want %+v", prover.JWK(), v.JWK)
			}
			if prover.Thumbprint() != v.Thumbprint {
				t.Errorf("Thumbprint = %s, want %s", prover.Thumbprint(), v.Thumbprint)
			}
		})
	}
}

func TestThumbprintVectors(t *testing.T) {
	_, cases := readVectors[thumbprintCase](t, "thumbprints.json")
	for _, v := range cases {
		t.Run(v.Name, func(t *testing.T) {
			got, err := v.JWK.Thumbprint()
			if v.Error != "" {
				if Class(err) != v.Error {
					t.Errorf("error = %v (%q), want %q", err, Class(err), v.Error)
				}
				return
			}
			if err != nil || got != v.Thumbprint {
				t.Errorf("Thumbprint() = %q, %v; want %q", got, err, v.Thumbprint)
			}
		})
	}
}

func TestProofVectors(t *testing.T) {
	file, cases := readVectors[proofCase](t, "proofs.json")
	for _, v := range cases {
		t.Run(v.Name, func(t *testing.T) {
			store := NewMemoryNonceStore(0)
			now, until := time.Unix(v.Now, 0), time.Unix(v.Until, 0)
			for _, nonce := range v.Spent {
				if err := store.Spend(nonce, until, now); err != nil {
					t.Fatal(err)
				}
			}
			checker := Checker{Store: store, Window: time.Duration(file.Window) * time.Second}
			err := checker.Check([]byte(v.Proof), []byte(v.Token), decodeHex(t, v.CertificateHashHex), v.Thumbprint, now, until)
			if Class(err) != v.Error {
				t.Fatalf("Check() = %v (%q), want %q", err, Class(err), v.Error)
			}
			if v.Error == "" {
				if store.Remembered() != len(v.Spent)+1 {
					t.Error("an accepted proof did not spend its nonce")
				}
				if Class(checker.Check([]byte(v.Proof), []byte(v.Token), decodeHex(t, v.CertificateHashHex), v.Thumbprint, now, until)) != "replayed" {
					t.Error("an accepted proof was accepted twice")
				}
			} else if store.Remembered() != len(v.Spent) {
				t.Error("a refused proof spent its nonce")
			}
		})
	}
}
