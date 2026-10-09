// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

package token

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type vectorSealKey struct {
	Kid       string `json:"kid"`
	IDHex     string `json:"id_hex"`
	SecretHex string `json:"secret_hex"`
}

// sealCase is one sealed token. If kid is set, sealing token with that key
// and nonce must give sealed exactly. Then the token presented (sealed, or
// token when there is none) is opened with keys and must give token, or, when
// now is set, verified by a verifier holding the signing keys and keys, and
// must give claims; either way, or be refused with error.
type sealCase struct {
	Name           string          `json:"name"`
	Kid            string          `json:"kid,omitempty"`
	NonceHex       string          `json:"nonce_hex,omitempty"`
	Token          string          `json:"token,omitempty"`
	Sealed         string          `json:"sealed,omitempty"`
	Keys           []string        `json:"keys"`
	AcceptUnsealed bool            `json:"accept_unsealed,omitempty"`
	Now            int64           `json:"now,omitempty"`
	Claims         json.RawMessage `json:"claims,omitempty"`
	Error          string          `json:"error,omitempty"`
}

type sealVectorFile struct {
	Library     string          `json:"library"`
	Description string          `json:"description"`
	Source      string          `json:"source"`
	Keys        []vectorKey     `json:"keys"`
	SealKeys    []vectorSealKey `json:"seal_keys"`
	Cases       []sealCase      `json:"cases"`
}

func vectorSealKeys(t *testing.T) ([]vectorSealKey, map[string]SealKey) {
	t.Helper()
	specs := []vectorSealKey{}
	keys := map[string]SealKey{}
	for _, spec := range []struct {
		name       string
		id, secret byte
	}{{"current", 0x11, 0x21}, {"next", 0x12, 0x22}, {"outsider", 0x13, 0x23}} {
		key, err := NewSealKey(bytes.Repeat([]byte{spec.id}, SealKeyIDSize), bytes.Repeat([]byte{spec.secret}, sealKeySize))
		if err != nil {
			t.Fatal(err)
		}
		keys[spec.name] = key
		specs = append(specs, vectorSealKey{Kid: spec.name, IDHex: hex.EncodeToString(key.ID()), SecretHex: hex.EncodeToString(key.Secret())})
	}
	return specs, keys
}

func nonce(fill byte) []byte { return bytes.Repeat([]byte{fill}, sealNonceSize) }

// sealRaw seals any plaintext under any prefix, for the cases Seal would not
// produce.
func sealRaw(key SealKey, prefix, nonce, plaintext []byte) string {
	sealed := append(append(bytes.Clone(prefix), nonce...), key.aead.Seal(nil, nonce, plaintext, prefix)...)
	return base64.RawURLEncoding.EncodeToString(sealed)
}

func buildSeal(t *testing.T, keys vectorKeys, seals map[string]SealKey) []sealCase {
	t.Helper()
	claims := baseClaims()
	signed, err := keys.signers[keys.current()].signDeterministic(claims)
	if err != nil {
		t.Fatal(err)
	}
	canonical := canonicalClaims(t, claims)
	sealed := func(name string, fill byte) string {
		out, err := seals[name].seal(signed, nonce(fill))
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	mutate := func(token string, edit func([]byte) []byte) string {
		raw, _ := base64.RawURLEncoding.DecodeString(token)
		return base64.RawURLEncoding.EncodeToString(edit(raw))
	}
	current := seals["current"]
	prefix := append([]byte{SealVersion}, current.ID()...)
	held := []string{"current", "next"}

	flipped := mutate(sealed("current", 0x01), func(raw []byte) []byte { raw[len(raw)-40] ^= 0x01; return raw })
	tagFlipped := mutate(sealed("current", 0x01), func(raw []byte) []byte { raw[len(raw)-1] ^= 0x80; return raw })
	relabelled := mutate(sealed("current", 0x01), func(raw []byte) []byte { copy(raw[1:sealPrefix], seals["next"].ID()); return raw })
	version2 := mutate(sealed("current", 0x01), func(raw []byte) []byte { raw[0] = 0x02; return raw })
	short := mutate(sealed("current", 0x01), func(raw []byte) []byte { return raw[:sealPrefix+sealNonceSize+sealTagSize-1] })
	overrun := sealRaw(current, prefix, nonce(0x05), binary.BigEndian.AppendUint16(nil, 0xFFFF))
	empty := sealRaw(current, prefix, nonce(0x06), nil)

	parts := bytes.Split([]byte(signed), []byte("."))
	badSignature := string(parts[0]) + "." + string(parts[1]) + "." + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x5A}, 4627))
	sealedBadSignature, err := current.seal(badSignature, nonce(0x07))
	if err != nil {
		t.Fatal(err)
	}

	return []sealCase{
		{Name: "sealed with the current key opens to the signed token", Kid: "current", NonceHex: hex.EncodeToString(nonce(0x01)), Token: signed, Sealed: sealed("current", 0x01), Keys: held},
		{Name: "sealed with the incoming key opens during a rotation", Kid: "next", NonceHex: hex.EncodeToString(nonce(0x02)), Token: signed, Sealed: sealed("next", 0x02), Keys: held},
		{Name: "the same token under another nonce shares nothing visible but the key id", Kid: "current", NonceHex: hex.EncodeToString(nonce(0x03)), Token: signed, Sealed: sealed("current", 0x03), Keys: held},
		{Name: "sealed with a key the verifier does not hold", Kid: "outsider", NonceHex: hex.EncodeToString(nonce(0x04)), Token: signed, Sealed: sealed("outsider", 0x04), Keys: held, Error: "unknown_key"},
		{Name: "one bit flipped in the ciphertext", Sealed: flipped, Keys: held, Error: "bad_signature"},
		{Name: "one bit flipped in the tag", Sealed: tagFlipped, Keys: held, Error: "bad_signature"},
		{Name: "the key id swapped for another held key", Sealed: relabelled, Keys: held, Error: "bad_signature"},
		{Name: "version 2", Sealed: version2, Keys: held, Error: "unsupported"},
		{Name: "one byte too short to hold a tag", Sealed: short, Keys: held, Error: "malformed"},
		{Name: "not base64url", Sealed: "AQ$$", Keys: held, Error: "malformed"},
		{Name: "padded base64url", Sealed: sealed("current", 0x01) + "=", Keys: held, Error: "malformed"},
		{Name: "authentic, with a segment length past the end", Sealed: overrun, Keys: held, Error: "malformed"},
		{Name: "authentic, and empty", Sealed: empty, Keys: held, Error: "malformed"},
		{Name: "verified: a sealed token gives its claims", Sealed: sealed("current", 0x01), Keys: held, Now: vectorNow, Claims: canonical},
		{Name: "verified: a signed token that is not sealed is refused", Token: signed, Keys: held, Now: vectorNow, Error: "unsupported"},
		{Name: "verified: a signed token is accepted during the move to sealing", Token: signed, Keys: held, AcceptUnsealed: true, Now: vectorNow, Claims: canonical},
		{Name: "verified: a sealed token whose signature does not verify", Sealed: sealedBadSignature, Keys: held, Now: vectorNow, Error: "bad_signature"},
		{Name: "verified: a sealed token past its expiry", Sealed: sealed("current", 0x01), Keys: held, Now: vectorNow + 600 + 31, Error: "expired"},
	}
}

func runSealVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(vectorDirectory, "seal.json"))
	if err != nil {
		t.Fatal(err)
	}
	var file sealVectorFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	seals := map[string]SealKey{}
	for _, spec := range file.SealKeys {
		id, _ := hex.DecodeString(spec.IDHex)
		secret, _ := hex.DecodeString(spec.SecretHex)
		key, err := NewSealKey(id, secret)
		if err != nil {
			t.Fatal(err)
		}
		seals[spec.Kid] = key
	}
	_, public, _ := readVectors[sealCase](t, "seal.json")
	var signing []PublicKey
	for _, key := range public {
		signing = append(signing, key)
	}
	for _, c := range file.Cases {
		t.Run("seal/"+c.Name, func(t *testing.T) {
			if c.Kid != "" {
				n, _ := hex.DecodeString(c.NonceHex)
				got, err := seals[c.Kid].seal(c.Token, n)
				if err != nil || got != c.Sealed {
					t.Fatalf("sealing gives %s (%v), want %s", got, err, c.Sealed)
				}
			}
			var held []SealKey
			for _, kid := range c.Keys {
				held = append(held, seals[kid])
			}
			presented := c.Sealed
			if presented == "" {
				presented = c.Token
			}
			if c.Now == 0 {
				opened, err := Open(presented, held...)
				if c.Error != "" {
					if Class(err) != c.Error || opened != "" {
						t.Fatalf("got %q, %v (%q), want %s", opened, err, Class(err), c.Error)
					}
					return
				}
				if err != nil || opened != c.Token {
					t.Fatalf("opened to %q (%v)", opened, err)
				}
				return
			}
			verifier := NewVerifier("", signing...).WithSealKeys(held...)
			if c.AcceptUnsealed {
				verifier = verifier.AcceptingUnsealed()
			}
			claims, err := verifier.Verify(presented, time.Unix(c.Now, 0))
			if c.Error != "" {
				if Class(err) != c.Error {
					t.Fatalf("got %v (%q), want %s", err, Class(err), c.Error)
				}
				return
			}
			want, err2 := decodeClaims(c.Claims)
			if err != nil || err2 != nil || claims != want {
				t.Fatalf("claims %+v (%v), want %+v", claims, err, want)
			}
		})
	}
}

func TestSealRoundTrip(t *testing.T) {
	key, err := GenerateSealKey()
	if err != nil {
		t.Fatal(err)
	}
	keys := buildKeys(t)
	signed, err := keys.signers[keys.current()].Sign(baseClaims())
	if err != nil {
		t.Fatal(err)
	}
	first, err := key.Seal(signed)
	if err != nil {
		t.Fatal(err)
	}
	second, _ := key.Seal(signed)
	if first == second {
		t.Fatal("two seals of one token are the same")
	}
	if !IsSealed(first) || IsSealed(signed) {
		t.Fatal("IsSealed is wrong")
	}
	if len(first) > len(signed)+80 {
		t.Fatalf("sealing grew the token from %d to %d bytes", len(signed), len(first))
	}
	for _, sealed := range []string{first, second} {
		opened, err := Open(sealed, key)
		if err != nil || opened != signed {
			t.Fatalf("does not open: %v", err)
		}
	}
	document, err := key.JWK()
	if err != nil {
		t.Fatal(err)
	}
	set, err := ParseSealKeySet([]byte(`{"keys":[` + string(document) + `]}`))
	if err != nil || len(set) != 1 || !bytes.Equal(set[0].Secret(), key.Secret()) || set[0].KeyID() != key.KeyID() {
		t.Fatalf("the JWK does not read back: %v", err)
	}
	for _, bad := range []string{
		`[{"kty":"oct","alg":"A128GCM","kid":"AAAAAAAAAAA","k":"` + base64.RawURLEncoding.EncodeToString(make([]byte, 32)) + `"}]`,
		`[{"kty":"oct","alg":"A256GCM","kid":"AAAA","k":"` + base64.RawURLEncoding.EncodeToString(make([]byte, 32)) + `"}]`,
		`[{"kty":"oct","alg":"A256GCM","kid":"AAAAAAAAAAA","k":"` + base64.RawURLEncoding.EncodeToString(make([]byte, 16)) + `"}]`,
		`[` + string(document) + `,` + string(document) + `]`,
	} {
		if _, err := ParseSealKeySet([]byte(bad)); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
}
