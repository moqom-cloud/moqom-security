// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

package token

// The shared vectors in vectors/token are generated here: run
//
//	MOQOM_WRITE_VECTORS=1 go test ./token -run TestVectors
//
// and regenerating is a no-op unless the format changes, because every key is
// a seed and every signature is deterministic (FIPS 204 deterministic ML-DSA,
// and Ed25519). Without the variable the test checks that the committed files
// are exactly what this build would write, then runs every case.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const vectorDirectory = "../../vectors/token"

// vectorNow is the `now` of every case, so expiry is a property of the file.
const vectorNow = 1_800_000_000

const vectorThumbprint = "MpXqvQAmv7Y3Kk9dHnJpLwRtUvXyZaBcDeFgHiJkLmM"

type vectorKey struct {
	Kid       string `json:"kid"`
	Alg       string `json:"alg"`
	SeedHex   string `json:"seed_hex"`
	PublicHex string `json:"public_hex"`
	// KidDerived says the kid is KeyID of the public key, which every language
	// then checks it derives the same way.
	KidDerived bool `json:"kid_derived"`
}

type verifyCase struct {
	Name   string          `json:"name"`
	Token  string          `json:"token"`
	Now    int64           `json:"now"`
	Issuer string          `json:"issuer"`
	Tenant string          `json:"tenant,omitempty"`
	Keys   []string        `json:"keys"`
	Claims json.RawMessage `json:"claims,omitempty"`
	Error  string          `json:"error,omitempty"`
}

type signCase struct {
	Name         string          `json:"name"`
	Kid          string          `json:"kid"`
	Claims       json.RawMessage `json:"claims"`
	SigningInput string          `json:"signing_input,omitempty"`
	Token        string          `json:"token,omitempty"`
	Error        string          `json:"error,omitempty"`
}

type vectorFile[C any] struct {
	Library     string      `json:"library"`
	Description string      `json:"description"`
	Source      string      `json:"source"`
	Keys        []vectorKey `json:"keys"`
	Cases       []C         `json:"cases"`
}

type vectorKeys struct {
	specs   []vectorKey
	signers map[string]*Signer
	legacy  ed25519.PrivateKey
	public  map[string]PublicKey
}

func seed(fill byte) []byte { return bytes.Repeat([]byte{fill}, 32) }

func buildKeys(t *testing.T) vectorKeys {
	t.Helper()
	keys := vectorKeys{signers: map[string]*Signer{}, public: map[string]PublicKey{}}
	for _, spec := range []struct {
		kid  string
		fill byte
	}{
		{"", 0x01},         // the current key, named by derivation
		{"pq-next", 0x02},  // the incoming key in a rotation
		{"outsider", 0x03}, // in no verifier's set
	} {
		signer, err := NewSigner(seed(spec.fill))
		if err != nil {
			t.Fatal(err)
		}
		if spec.kid != "" {
			signer = signer.WithID(spec.kid)
		}
		keys.signers[signer.ID()] = signer
		keys.public[signer.ID()] = signer.PublicKey()
		keys.specs = append(keys.specs, vectorKey{
			Kid: signer.ID(), Alg: string(MLDSA65), SeedHex: hex.EncodeToString(seed(spec.fill)),
			PublicHex: hex.EncodeToString(signer.PublicKey().Bytes()), KidDerived: spec.kid == "",
		})
	}
	keys.legacy = ed25519.NewKeyFromSeed(seed(0x04))
	legacy, err := NewPublicKey(EdDSA, "", keys.legacy.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	keys.public[legacy.ID()] = legacy
	keys.specs = append(keys.specs, vectorKey{
		Kid: legacy.ID(), Alg: string(EdDSA), SeedHex: hex.EncodeToString(seed(0x04)),
		PublicHex: hex.EncodeToString(legacy.Bytes()), KidDerived: true,
	})
	return keys
}

func (k vectorKeys) current() string  { return k.specs[0].Kid }
func (k vectorKeys) legacyID() string { return k.specs[3].Kid }

func baseClaims() Claims {
	return Claims{
		Issuer:       "https://api.moqom.cloud",
		Subject:      "ada",
		Tenant:       "acme",
		ID:           "vector-1",
		IssuedAt:     vectorNow,
		Expires:      vectorNow + 600,
		Confirmation: Confirmation{Thumbprint: vectorThumbprint},
		Grant:        Grant{Room: "room-42", Publish: 3},
	}
}

func rawSegment(text string) string { return base64.RawURLEncoding.EncodeToString([]byte(text)) }

// signRaw signs arbitrary segments, for the cases no Signer would produce.
func (k vectorKeys) signRaw(kid string, headerSegment, claimsSegment string) string {
	input := headerSegment + "." + claimsSegment
	var signature []byte
	if kid == k.legacyID() {
		signature = ed25519.Sign(k.legacy, []byte(input))
	} else {
		signed, err := k.signers[kid].private.SignDeterministic([]byte(input), nil)
		if err != nil {
			panic(err)
		}
		signature = signed
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func headerFor(alg, typ, kid string) string {
	encoded, _ := segment(map[string]string{"alg": alg, "typ": typ, "kid": kid})
	return encoded
}

// claimsJSON re-encodes claims canonically with members added or removed, for
// cases whose claims a Signer would refuse.
func claimsJSON(claims Claims, edit func(map[string]any)) string {
	encoded, _ := json.Marshal(claims)
	var members map[string]any
	_ = json.Unmarshal(encoded, &members)
	if edit != nil {
		edit(members)
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(members)
	return strings.TrimSuffix(buffer.String(), "\n")
}

func canonicalClaims(t *testing.T, claims Claims) json.RawMessage {
	t.Helper()
	encoded, err := segment(claims)
	if err != nil {
		t.Fatal(err)
	}
	decoded, _ := base64.RawURLEncoding.DecodeString(encoded)
	return decoded
}

func buildVerify(t *testing.T, keys vectorKeys) []verifyCase {
	t.Helper()
	current, legacy := keys.current(), keys.legacyID()
	set := []string{current, "pq-next", legacy}
	mldsaHeader := headerFor(string(MLDSA65), Type, current)

	mint := func(kid string, claims Claims) string {
		signed, err := keys.signers[kid].signDeterministic(claims)
		if err != nil {
			t.Fatalf("minting a vector: %v", err)
		}
		return signed
	}
	edit := func(claims Claims, change func(map[string]any)) string {
		return keys.signRaw(current, mldsaHeader, rawSegment(claimsJSON(claims, change)))
	}
	valid := func(name, token string, claims Claims) verifyCase {
		return verifyCase{Name: name, Token: token, Now: vectorNow, Issuer: "https://api.moqom.cloud",
			Keys: set, Claims: canonicalClaims(t, claims)}
	}
	refused := func(name, token, class string) verifyCase {
		return verifyCase{Name: name, Token: token, Now: vectorNow, Issuer: "https://api.moqom.cloud",
			Keys: set, Error: class}
	}

	plain := mint(current, baseClaims())
	parts := strings.Split(plain, ".")

	full := baseClaims()
	full.ID, full.Via, full.E2EE = "vector-full", "bea", "required"
	full.Grant = Grant{Room: "room-42", Publish: 15, Capabilities: 0x101, Owner: true, Backstage: true, AgeVerified: true}

	link := baseClaims()
	link.Subject, link.Grant = "relay", Grant{Room: "room-42", Relay: true}

	awkward := baseClaims()
	awkward.Subject, awkward.Via, awkward.Grant.Room = "ada\u0301/laptop", "be\u0301a \"the\" <host> & co\u2028", "tab\there\\"

	rotated := baseClaims()
	rotated.ID = "vector-rotated"

	legacyClaims := baseClaims()
	legacyClaims.ID = "vector-legacy"
	legacyToken := keys.signRaw(legacy, headerFor(string(EdDSA), Type, legacy), rawSegment(claimsJSON(legacyClaims, nil)))

	noIssued := baseClaims()
	noIssued.IssuedAt = 0
	ahead := baseClaims()
	ahead.IssuedAt, ahead.Expires = vectorNow+20, vectorNow+620
	maximum := baseClaims()
	maximum.Expires = vectorNow + 900

	cases := []verifyCase{
		valid("ml-dsa-65", plain, baseClaims()),
		valid("ml-dsa-65 every claim", mint(current, full), full),
		valid("relay link grant", mint(current, link), link),
		valid("unicode and escapes", mint(current, awkward), awkward),
		valid("the incoming key during a rotation", mint("pq-next", rotated), rotated),
		valid("ed25519 legacy key", legacyToken, legacyClaims),
		valid("unknown top-level claim is ignored", edit(baseClaims(), func(m map[string]any) {
			m["something_added_later"] = map[string]any{"nested": true}
		}), baseClaims()),
		valid("no iat", edit(noIssued, func(m map[string]any) { delete(m, "iat") }), noIssued),
		valid("issued inside the skew", mint(current, ahead), ahead),
		valid("lifetime of exactly fifteen minutes", mint(current, maximum), maximum),
		valid("no jti", edit(baseClaims(), func(m map[string]any) { delete(m, "jti") }), func() Claims {
			c := baseClaims()
			c.ID = ""
			return c
		}()),
	}

	inSkew := valid("expired inside the skew", plain, baseClaims())
	inSkew.Now = vectorNow + 600 + 30
	anyIssuer := valid("any issuer when none is pinned", plain, baseClaims())
	anyIssuer.Issuer = ""
	pinned := valid("pinned to its own tenant", plain, baseClaims())
	pinned.Tenant = "acme"
	cases = append(cases, inSkew, anyIssuer, pinned)

	expired := refused("expired", plain, "expired")
	expired.Now = vectorNow + 600 + 31
	early := refused("not yet valid", plain, "not_yet_valid")
	early.Now = vectorNow - 31
	foreign := refused("another issuer", plain, "wrong_issuer")
	foreign.Issuer = "https://api.example.test"
	tenant := refused("another tenant", plain, "wrong_tenant")
	tenant.Tenant = "globex"
	rotatedAway := refused("kid rotated out of the set", mint("pq-next", rotated), "unknown_key")
	rotatedAway.Keys = []string{current, legacy}
	cases = append(cases, expired, early, foreign, tenant, rotatedAway)

	tamperedClaims := baseClaims()
	tamperedClaims.Grant.Owner = true
	signature, _ := base64.RawURLEncoding.DecodeString(parts[2])
	flipped := append([]byte(nil), signature...)
	flipped[100] ^= 0x01
	// The same header bytes spelled with non-zero trailing bits: a second
	// encoding of one token, which only a lax decoder would accept.
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	nonCanonical := parts[0][:len(parts[0])-1] + string(alphabet[strings.IndexByte(alphabet, parts[0][len(parts[0])-1])|1])

	cases = append(cases,
		refused("unknown kid", mint("outsider", baseClaims()), "unknown_key"),
		refused("tampered payload", parts[0]+"."+rawSegment(claimsJSON(tamperedClaims, nil))+"."+parts[2], "bad_signature"),
		refused("tampered signature", parts[0]+"."+parts[1]+"."+base64.RawURLEncoding.EncodeToString(flipped), "bad_signature"),
		refused("signature from another key under this kid", func() string {
			other := strings.Split(mint("outsider", baseClaims()), ".")
			return parts[0] + "." + parts[1] + "." + other[2]
		}(), "bad_signature"),
		refused("alg none", headerFor("none", Type, current)+"."+parts[1]+".", "unsupported"),
		refused("alg HS256", headerFor("HS256", Type, current)+"."+parts[1]+"."+parts[2], "unsupported"),
		refused("alg empty", headerFor("", Type, current)+"."+parts[1]+"."+parts[2], "unsupported"),
		refused("alg EdDSA for an ML-DSA-65 key", keys.signRaw(current, headerFor(string(EdDSA), Type, current), parts[1]), "unsupported"),
		refused("alg ML-DSA-65 for an Ed25519 key", keys.signRaw(legacy, headerFor(string(MLDSA65), Type, legacy), rawSegment(claimsJSON(legacyClaims, nil))), "unsupported"),
		refused("typ JWT", keys.signRaw(current, headerFor(string(MLDSA65), "JWT", current), parts[1]), "unsupported"),
		refused("over-long lifetime", edit(baseClaims(), func(m map[string]any) { m["exp"] = vectorNow + 901 }), "lifetime"),
		refused("over-long lifetime without iat", edit(baseClaims(), func(m map[string]any) {
			delete(m, "iat")
			m["exp"] = vectorNow + 931
		}), "lifetime"),
		refused("no subject", edit(baseClaims(), func(m map[string]any) { delete(m, "sub") }), "incomplete"),
		refused("no tenant", edit(baseClaims(), func(m map[string]any) { m["aud"] = "" }), "incomplete"),
		refused("no device", edit(baseClaims(), func(m map[string]any) { m["cnf"] = map[string]any{} }), "incomplete"),
		refused("member names are case-sensitive", edit(baseClaims(), func(m map[string]any) {
			m["SUB"] = m["sub"]
			delete(m, "sub")
		}), "incomplete"),
		refused("no expiry", edit(baseClaims(), func(m map[string]any) { delete(m, "exp") }), "malformed"),
		refused("unknown grant field", edit(baseClaims(), func(m map[string]any) {
			m["moqt"].(map[string]any)["new"] = 1
		}), "malformed"),
		refused("grant field of the wrong type", edit(baseClaims(), func(m map[string]any) {
			m["moqt"].(map[string]any)["pub"] = 256
		}), "malformed"),
		refused("null claim", edit(baseClaims(), func(m map[string]any) { m["sub"] = nil }), "malformed"),
		refused("claims are an array", keys.signRaw(current, mldsaHeader, rawSegment(`["ada"]`)), "malformed"),
		refused("claims are not JSON", keys.signRaw(current, mldsaHeader, rawSegment(`{"sub":`)), "malformed"),
		refused("claims are not base64url", keys.signRaw(current, mldsaHeader, "e30!"), "malformed"),
		refused("unknown header parameter", keys.signRaw(current, rawSegment(
			`{"alg":"ML-DSA-65","typ":"MOQT","kid":"`+current+`","crit":["exp"]}`), parts[1]), "malformed"),
		refused("header is not JSON", rawSegment("alg")+"."+parts[1]+"."+parts[2], "malformed"),
		refused("header is not base64url", "e30="+"."+parts[1]+"."+parts[2], "malformed"),
		refused("signature is not base64url", parts[0]+"."+parts[1]+"."+parts[2][:40]+"+", "malformed"),
		refused("header with non-canonical trailing bits", nonCanonical+"."+parts[1]+"."+parts[2], "malformed"),
		refused("empty", "", "malformed"),
		refused("two segments", parts[0]+"."+parts[1], "malformed"),
		refused("four segments", plain+".", "malformed"),
		refused("too long", strings.Repeat("A", MaxTokenBytes+1), "malformed"),
	)
	if nonCanonical == parts[0] {
		t.Fatal("the non-canonical header encoding is canonical")
	}
	return cases
}

func buildSign(t *testing.T, keys vectorKeys) []signCase {
	t.Helper()
	current := keys.current()
	encode := func(claims Claims, change func(map[string]any)) json.RawMessage {
		return json.RawMessage(claimsJSON(claims, change))
	}
	full := baseClaims()
	full.ID, full.Via, full.E2EE = "vector-full", "bea", "required"
	full.Grant = Grant{Room: "room-42", Publish: 15, Capabilities: 0x101, Owner: true, Backstage: true, AgeVerified: true, Relay: true}
	escapes := baseClaims()
	escapes.Subject = "\"quoted\" back\\slash <tag> & \u00e9\u0301 \U0001F600"
	escapes.Grant.Room = "ctl\b\f\n\r\t\u0001\u001f\u007f end"
	escapes.Via = "line\u2028para\u2029"
	minimal := baseClaims()
	minimal.Issuer, minimal.ID, minimal.Grant = "", "", Grant{}
	maximum := baseClaims()
	maximum.Expires = vectorNow + 900

	cases := []signCase{
		{Name: "typical", Claims: encode(baseClaims(), nil)},
		{Name: "every claim", Claims: encode(full, nil)},
		{Name: "string escapes", Claims: encode(escapes, nil)},
		{Name: "minimal", Claims: encode(minimal, nil)},
		{Name: "fifteen minutes", Claims: encode(maximum, nil)},
		{Name: "over fifteen minutes", Claims: encode(baseClaims(), func(m map[string]any) { m["exp"] = vectorNow + 901 }), Error: "lifetime"},
		{Name: "expiry before issue", Claims: encode(baseClaims(), func(m map[string]any) { m["exp"] = vectorNow - 1 }), Error: "lifetime"},
		{Name: "no iat", Claims: encode(baseClaims(), func(m map[string]any) { delete(m, "iat") }), Error: "lifetime"},
		{Name: "no subject", Claims: encode(baseClaims(), func(m map[string]any) { m["sub"] = "" }), Error: "incomplete"},
		{Name: "no tenant", Claims: encode(baseClaims(), func(m map[string]any) { m["aud"] = "" }), Error: "incomplete"},
		{Name: "no device", Claims: encode(baseClaims(), func(m map[string]any) { m["cnf"] = map[string]any{"jkt": ""} }), Error: "incomplete"},
		{Name: "thumbprint too short", Claims: encode(baseClaims(), func(m map[string]any) {
			m["cnf"] = map[string]any{"jkt": "OuXpLpEHW7dCPqjKWm8Zq1TfBb2nQ4Zt"}
		}), Error: "thumbprint"},
		{Name: "thumbprint not base64url", Claims: encode(baseClaims(), func(m map[string]any) {
			m["cnf"] = map[string]any{"jkt": "MpXqvQAmv7Y3Kk9dHnJpLwRtUvXyZaBcDeFgHiJkLm+"}
		}), Error: "thumbprint"},
	}
	for i := range cases {
		cases[i].Kid = current
		if cases[i].Error != "" {
			continue
		}
		claims, err := decodeClaims(cases[i].Claims)
		if err != nil {
			t.Fatalf("%s: %v", cases[i].Name, err)
		}
		signed, err := keys.signers[current].signDeterministic(claims)
		if err != nil {
			t.Fatalf("%s: %v", cases[i].Name, err)
		}
		cases[i].Token = signed
		cases[i].SigningInput = signed[:strings.LastIndexByte(signed, '.')]
	}
	return cases
}

func encodeVectors(t *testing.T, value any) []byte {
	t.Helper()
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func TestVectors(t *testing.T) {
	keys := buildKeys(t)
	files := map[string][]byte{
		"verify.json": encodeVectors(t, vectorFile[verifyCase]{
			Library:     "moqom-token",
			Description: "Verifying tokens: each case names the verifier's issuer, tenant pin and key set, and gives the claims a verified token yields or the error class it is refused with.",
			Source:      "Generated by go/token/vectors_test.go (MOQOM_WRITE_VECTORS=1) with deterministic ML-DSA-65 and Ed25519.",
			Keys:        keys.specs,
			Cases:       buildVerify(t, keys),
		}),
		"sign.json": encodeVectors(t, vectorFile[signCase]{
			Library:     "moqom-token",
			Description: "Signing tokens: the canonical header.claims bytes every implementation must produce for the claims given, and the token Go's deterministic ML-DSA-65 makes of them, or the error class signing is refused with.",
			Source:      "Generated by go/token/vectors_test.go (MOQOM_WRITE_VECTORS=1) with deterministic ML-DSA-65.",
			Keys:        keys.specs,
			Cases:       buildSign(t, keys),
		}),
	}
	for name, encoded := range files {
		path := filepath.Join(vectorDirectory, name)
		if os.Getenv("MOQOM_WRITE_VECTORS") == "1" {
			if err := os.WriteFile(path, encoded, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		committed, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s (regenerate with MOQOM_WRITE_VECTORS=1): %v", path, err)
		}
		if !bytes.Equal(committed, encoded) {
			t.Errorf("%s differs from what this build generates; regenerate with MOQOM_WRITE_VECTORS=1", name)
		}
	}
	runVerifyVectors(t)
	runSignVectors(t)
}

func readVectors[C any](t *testing.T, name string) (vectorFile[C], map[string]PublicKey, map[string]*Signer) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorDirectory, name))
	if err != nil {
		t.Fatal(err)
	}
	var file vectorFile[C]
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	public := map[string]PublicKey{}
	signers := map[string]*Signer{}
	for _, spec := range file.Keys {
		seedBytes, _ := hex.DecodeString(spec.SeedHex)
		raw, _ := hex.DecodeString(spec.PublicHex)
		id := spec.Kid
		if spec.KidDerived {
			id = ""
		}
		key, err := NewPublicKey(Algorithm(spec.Alg), id, raw)
		if err != nil {
			t.Fatalf("key %s: %v", spec.Kid, err)
		}
		if key.ID() != spec.Kid {
			t.Fatalf("key %s derives kid %s", spec.Kid, key.ID())
		}
		public[spec.Kid] = key
		if Algorithm(spec.Alg) == MLDSA65 {
			signer, err := NewSigner(seedBytes)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(signer.PublicKey().Bytes(), raw) {
				t.Fatalf("key %s: the seed does not give the public key", spec.Kid)
			}
			signers[spec.Kid] = signer.WithID(spec.Kid)
		} else if !bytes.Equal(ed25519.NewKeyFromSeed(seedBytes).Public().(ed25519.PublicKey), raw) {
			t.Fatalf("key %s: the seed does not give the public key", spec.Kid)
		}
	}
	return file, public, signers
}

func runVerifyVectors(t *testing.T) {
	file, public, _ := readVectors[verifyCase](t, "verify.json")
	for _, c := range file.Cases {
		t.Run("verify/"+c.Name, func(t *testing.T) {
			var set []PublicKey
			for _, kid := range c.Keys {
				set = append(set, public[kid])
			}
			verifier := NewVerifier(c.Issuer, set...).ForTenant(c.Tenant)
			claims, err := verifier.Verify(c.Token, time.Unix(c.Now, 0))
			if c.Error != "" {
				if Class(err) != c.Error {
					t.Fatalf("got %v (%q), want %s", err, Class(err), c.Error)
				}
				if claims != (Claims{}) {
					t.Fatal("claims came back from a refused token")
				}
				return
			}
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			want, err := decodeClaims(c.Claims)
			if err != nil {
				t.Fatal(err)
			}
			if claims != want {
				t.Fatalf("claims %+v, want %+v", claims, want)
			}
		})
	}
}

func runSignVectors(t *testing.T) {
	file, public, signers := readVectors[signCase](t, "sign.json")
	for _, c := range file.Cases {
		t.Run("sign/"+c.Name, func(t *testing.T) {
			claims, err := decodeClaims(c.Claims)
			if err != nil {
				t.Fatal(err)
			}
			signer := signers[c.Kid]
			hedged, err := signer.Sign(claims)
			if c.Error != "" {
				if Class(err) != c.Error {
					t.Fatalf("got %v, want %s", err, c.Error)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := hedged[:strings.LastIndexByte(hedged, '.')]; got != c.SigningInput {
				t.Fatalf("signing input\n %s\nwant\n %s", got, c.SigningInput)
			}
			deterministic, err := signer.signDeterministic(claims)
			if err != nil || deterministic != c.Token {
				t.Fatalf("deterministic token differs: %v", err)
			}
			verifier := NewVerifier("", public[c.Kid])
			for _, token := range []string{c.Token, hedged} {
				verified, err := verifier.Verify(token, time.Unix(claims.IssuedAt, 0))
				if err != nil || verified != claims {
					t.Fatalf("the signed token does not verify to its claims: %v", err)
				}
			}
		})
	}
}
