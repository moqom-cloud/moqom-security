// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

package token

// The shared vectors in vectors/token are generated here: run
//
//	MOQOM_WRITE_VECTORS=1 go test ./token -run TestVectors
//
// and regenerating is a no-op unless the format changes, because every key is
// a seed and every signature is deterministic (FIPS 204 deterministic
// ML-DSA-87). Without the variable the test checks that the committed files
// are exactly what this build would write, then runs every case.

import (
	"bytes"
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
	Name   string `json:"name"`
	Token  string `json:"token"`
	Now    int64  `json:"now"`
	Issuer string `json:"issuer"`
	Tenant string `json:"tenant,omitempty"`
	// Pool, when present, pins the verifier to that relay pool, "" being the
	// shared fleet. Absent does not check the pool.
	Pool   *string         `json:"pool,omitempty"`
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
			Kid: signer.ID(), Alg: string(MLDSA87), SeedHex: hex.EncodeToString(seed(spec.fill)),
			PublicHex: hex.EncodeToString(signer.PublicKey().Bytes()), KidDerived: spec.kid == "",
		})
	}
	return keys
}

func (k vectorKeys) current() string { return k.specs[0].Kid }

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
	signature, err := k.signers[kid].private.SignDeterministic([]byte(input), nil)
	if err != nil {
		panic(err)
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
	current := keys.current()
	set := []string{current, "pq-next"}
	mldsaHeader := headerFor(string(MLDSA87), Type, current)

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
	full.ID, full.Via = "vector-full", "bea"
	full.Grant = Grant{Room: "room-42", Publish: 15, Capabilities: 0x101, Owner: true, Backstage: true, AgeVerified: true}

	link := baseClaims()
	link.Subject, link.Grant = "relay", Grant{Room: "room-42", Relay: true}

	awkward := baseClaims()
	awkward.Subject, awkward.Via, awkward.Grant.Room = "ada\u0301/laptop", "be\u0301a \"the\" <host> & co\u2028", "tab\there\\"

	rotated := baseClaims()
	rotated.ID = "vector-rotated"

	noIssued := baseClaims()
	noIssued.IssuedAt = 0
	ahead := baseClaims()
	ahead.IssuedAt, ahead.Expires = vectorNow+20, vectorNow+620
	maximum := baseClaims()
	maximum.Expires = vectorNow + 900

	cases := []verifyCase{
		valid("ml-dsa-87", plain, baseClaims()),
		valid("ml-dsa-87 every claim", mint(current, full), full),
		valid("relay link grant", mint(current, link), link),
		valid("unicode and escapes", mint(current, awkward), awkward),
		valid("the incoming key during a rotation", mint("pq-next", rotated), rotated),
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
	rotatedAway.Keys = []string{current}
	cases = append(cases, expired, early, foreign, tenant, rotatedAway)

	// Compared byte for byte: canonically equivalent is not equal.
	composed := baseClaims()
	composed.Issuer, composed.Tenant = "https://café.example", "café"
	composedToken := mint(current, composed)
	decomposedTenant := refused("tenant that differs only in Unicode normalization", composedToken, "wrong_tenant")
	decomposedTenant.Issuer, decomposedTenant.Tenant = composed.Issuer, "café"
	decomposedIssuer := refused("issuer that differs only in Unicode normalization", composedToken, "wrong_issuer")
	decomposedIssuer.Issuer = "https://café.example"
	sameTenant := valid("tenant and issuer with the same bytes", composedToken, composed)
	sameTenant.Issuer, sameTenant.Tenant = composed.Issuer, composed.Tenant
	cases = append(cases, decomposedTenant, decomposedIssuer, sameTenant)

	pin := func(pool string) *string { return &pool }
	pooledClaims := baseClaims()
	pooledClaims.Pool = "acme-prod"
	pooledToken := mint(current, pooledClaims)
	ownPool := valid("a pool relay admits its own pool's token", pooledToken, pooledClaims)
	ownPool.Pool = pin("acme-prod")
	unpinned := valid("a verifier with no pool reads the pool and admits it", pooledToken, pooledClaims)
	shared := refused("a shared relay refuses a pooled token", pooledToken, "wrong_pool")
	shared.Pool = pin("")
	otherPool := refused("a pool relay refuses another pool's token", pooledToken, "wrong_pool")
	otherPool.Pool = pin("globex-prod")
	unpooled := refused("a pool relay refuses a token naming no pool", plain, "wrong_pool")
	unpooled.Pool = pin("acme-prod")
	sharedPlain := valid("a shared relay admits a token naming no pool", plain, baseClaims())
	sharedPlain.Pool = pin("")
	cases = append(cases, ownPool, unpinned, shared, otherPool, unpooled, sharedPlain)

	tamperedClaims := baseClaims()
	tamperedClaims.Grant.Owner = true
	signature, _ := base64.RawURLEncoding.DecodeString(parts[2])
	flipped := append([]byte(nil), signature...)
	flipped[100] ^= 0x01
	// The same header bytes spelled with non-zero trailing bits: a second
	// encoding of one token, which only a lax decoder would accept.
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	nonCanonical := parts[0][:len(parts[0])-1] + string(alphabet[strings.IndexByte(alphabet, parts[0][len(parts[0])-1])|1])

	base := claimsJSON(baseClaims(), nil)
	withClaims := func(name, old, replacement string) string {
		if !strings.Contains(base, old) {
			t.Fatalf("%s: %q is not in the claims", name, old)
		}
		return keys.signRaw(current, mldsaHeader, rawSegment(strings.Replace(base, old, replacement, 1)))
	}
	duplicate := func(name, old, replacement string) verifyCase {
		return refused(name, withClaims(name, old, replacement), "malformed")
	}
	duplicateHeader := func(name, header string) verifyCase {
		return refused(name, keys.signRaw(current, rawSegment(header), parts[1]), "malformed")
	}
	cases = append(cases,
		duplicate("duplicate claim with another value", `{"aud":`, `{"sub":"eve","aud":`),
		duplicate("duplicate claim with the same value", `{"aud":`, `{"sub":"ada","aud":`),
		duplicate("duplicate claim spelled with an escape", `{"aud":`, `{"s\u0075b":"eve","aud":`),
		duplicate("duplicate member in cnf", `"cnf":{"jkt":`, `"cnf":{"jkt":"AAAA","jkt":`),
		duplicate("duplicate member in the grant", `"moqt":{`, `"moqt":{"room":"room-1",`),
		duplicate("duplicate member in an unknown claim", `{"aud":`, `{"later":{"a":1,"a":2},"aud":`),
		duplicate("duplicate member in an object inside an array", `{"aud":`, `{"later":[{"a":1},{"b":[{"c":1,"c":1}]}],"aud":`),
		duplicateHeader("duplicate header parameter", `{"alg":"ML-DSA-87","kid":"`+current+`","kid":"`+current+`","typ":"MOQT"}`),
		duplicateHeader("duplicate header alg with another value", `{"alg":"ML-DSA-87","alg":"ML-DSA-87","kid":"`+current+`","typ":"MOQT"}`),
		duplicateHeader("duplicate header parameter spelled with an escape", `{"alg":"ML-DSA-87","k\u0069d":"`+current+`","kid":"`+current+`","typ":"MOQT"}`),
		valid("member names that differ only in case or sit in sibling objects",
			withClaims("siblings", `{"aud":`, `{"later":[{"a":1},{"a":1}],"Later":{"a":{"a":1}},"aud":`), baseClaims()),
	)

	// Strict JSON: correctly signed claims and headers that some parser would
	// read differently, and the edge cases every parser must accept.
	malformed := func(name, old, replacement string) verifyCase {
		return refused(name, withClaims(name, old, replacement), "malformed")
	}
	header := func(text string) string {
		return rawSegment(strings.ReplaceAll(text, "KID", current))
	}
	nested := func(depth int) string {
		return `{"later":` + strings.Repeat("[", depth-1) + strings.Repeat("]", depth-1) + `,"aud":`
	}
	surrogate := baseClaims()
	surrogate.Subject = "ada\U0001F600"
	limits := baseClaims()
	limits.Grant.Publish, limits.Grant.Capabilities = 255, 4294967295
	cases = append(cases,
		malformed("iat in exponent form", `"iat":1800000000`, `"iat":1.8e9`),
		malformed("iat with a zero fraction", `"iat":1800000000`, `"iat":1800000000.0`),
		malformed("exp in exponent form", `"exp":1800000600`, `"exp":18000006e2`),
		malformed("iat of -0", `"iat":1800000000`, `"iat":-0`),
		malformed("exp too large for 64 bits", `"exp":1800000600`, `"exp":9223372036854775808`),
		malformed("pub with a zero fraction", `"pub":3`, `"pub":3.0`),
		malformed("pub in exponent form", `"pub":3`, `"pub":3e0`),
		malformed("negative pub", `"pub":3`, `"pub":-1`),
		malformed("cap too large for 32 bits", `"cap":0`, `"cap":4294967296`),
		malformed("boolean grant field as a number", `"moqt":{`, `"moqt":{"own":1,`),
		malformed("boolean grant field as a string", `"moqt":{`, `"moqt":{"own":"true",`),
		malformed("string claim as a number", `"jti":"vector-1"`, `"jti":1`),
		malformed("cnf is an array", `"cnf":{"jkt":"`+vectorThumbprint+`"}`, `"cnf":["`+vectorThumbprint+`"]`),
		malformed("moqt is null", `"moqt":{"cap":0,"pub":3,"room":"room-42"}`, `"moqt":null`),
		malformed("jkt is null", `"jkt":"`+vectorThumbprint+`"`, `"jkt":null`),
		refused("claims are null", keys.signRaw(current, mldsaHeader, rawSegment(`null`)), "malformed"),
		refused("claims are a string", keys.signRaw(current, mldsaHeader, rawSegment(`"ada"`)), "malformed"),
		malformed("claim with an unpaired high surrogate escape", `"sub":"ada"`, `"sub":"ada\ud83d"`),
		malformed("claim with an unpaired low surrogate escape", `"sub":"ada"`, `"sub":"ada\ude00"`),
		malformed("claim with a high surrogate escape before a non-surrogate", `"sub":"ada"`, `"sub":"ada\ud83d\u0041"`),
		malformed("unknown claim with an unpaired surrogate escape", `{"aud":`, `{"later":["\udc00"],"aud":`),
		malformed("claims that are not utf-8", `"sub":"ada"`, "\"sub\":\"ada\xff\""),
		malformed("claims with a utf-8 encoded surrogate", `"sub":"ada"`, "\"sub\":\"ada\xed\xa0\x80\""),
		malformed("claims with an overlong utf-8 encoding", `"sub":"ada"`, "\"sub\":\"ada\xc0\xaf\""),
		malformed("claims with a raw control character in a string", `"sub":"ada"`, "\"sub\":\"ad\x01a\""),
		malformed("claims with a number too large for a double", `{"aud":`, `{"later":1e400,"aud":`),
		malformed("claims with a leading-zero number", `{"aud":`, `{"later":01,"aud":`),
		malformed("claims nested one deeper than allowed", `{"aud":`, nested(128)),
		malformed("claims with a byte order mark", `{"aud":`, "\uFEFF{\"aud\":"),
		malformed("claims with data after the object", `"sub":"ada"}`, `"sub":"ada"} {}`),
		refused("header is null", keys.signRaw(current, rawSegment(`null`), parts[1]), "malformed"),
		refused("header is an array", keys.signRaw(current, header(`["ML-DSA-87","MOQT","KID"]`), parts[1]), "malformed"),
		refused("header kid is null", keys.signRaw(current, header(`{"alg":"ML-DSA-87","typ":"MOQT","kid":null}`), parts[1]), "malformed"),
		refused("header alg is a number", keys.signRaw(current, header(`{"alg":87,"typ":"MOQT","kid":"KID"}`), parts[1]), "malformed"),
		refused("header with an unpaired surrogate escape", keys.signRaw(current, header(`{"alg":"ML-DSA-87","typ":"MOQT\udc00","kid":"KID"}`), parts[1]), "malformed"),
		refused("header that is not utf-8", keys.signRaw(current, header("{\"alg\":\"ML-DSA-87\",\"typ\":\"MOQT\xff\",\"kid\":\"KID\"}"), parts[1]), "malformed"),

		valid("claims nested as deep as allowed", withClaims("deep", `{"aud":`, nested(127)), baseClaims()),
		valid("unknown claim that is null is ignored", withClaims("null", `{"aud":`, `{"later":null,"aud":`), baseClaims()),
		valid("unknown claim numbers need not be integers", withClaims("numbers", `{"aud":`, `{"later":[1.5,1e3,-0,1E+2],"aud":`), baseClaims()),
		valid("claims with a number too small for a double", withClaims("tiny", `{"aud":`, `{"later":1e-400,"aud":`), baseClaims()),
		valid("claim with a surrogate pair escape", withClaims("pair", `"sub":"ada"`, `"sub":"ada\ud83d\ude00"`), surrogate),
		valid("escaped member names and values", withClaims("escaped", `"sub":"ada"`, `"s\u0075b":"\u0061d\u0061"`), baseClaims()),
		valid("whitespace around and inside the claims", keys.signRaw(current, mldsaHeader, rawSegment(
			" \n"+strings.ReplaceAll(base, `":`, `" : `)+"\t\r\n")), baseClaims()),
		valid("grant integers at their limits", mint(current, limits), limits),
		valid("header with whitespace and escapes", keys.signRaw(current, header(` {"alg" : "ML-DSA-87", "typ":"MO\u0051T", "kid":"KID"} `), parts[1]), baseClaims()),
	)

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
		refused("alg EdDSA for an ML-DSA-87 key", keys.signRaw(current, headerFor("EdDSA", Type, current), parts[1]), "unsupported"),
		refused("alg ML-DSA-65 for an ML-DSA-87 key", keys.signRaw(current, headerFor("ML-DSA-65", Type, current), parts[1]), "unsupported"),
		refused("alg ES256 for an ML-DSA-87 key", keys.signRaw(current, headerFor("ES256", Type, current), parts[1]), "unsupported"),
		refused("typ JWT", keys.signRaw(current, headerFor(string(MLDSA87), "JWT", current), parts[1]), "unsupported"),
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
			`{"alg":"ML-DSA-87","typ":"MOQT","kid":"`+current+`","crit":["exp"]}`), parts[1]), "malformed"),
		refused("header is not JSON", rawSegment("alg")+"."+parts[1]+"."+parts[2], "malformed"),
		refused("header is not base64url", "e30="+"."+parts[1]+"."+parts[2], "malformed"),
		refused("signature is not base64url", parts[0]+"."+parts[1]+"."+parts[2][:40]+"+", "malformed"),
		refused("header with non-canonical trailing bits", nonCanonical+"."+parts[1]+"."+parts[2], "malformed"),
		refused("empty", "", "malformed"),
		refused("two segments", parts[0]+"."+parts[1], "malformed"),
		refused("four segments", plain+".", "malformed"),
		refused("too long", strings.Repeat("A", MaxTokenBytes+1), "malformed"),
		// A decoder that skips line breaks reads these as the token without
		// them; the signature segment is not signed, so that would be a second
		// spelling of one token.
		refused("signature segment with a line break", parts[0]+"."+parts[1]+"."+parts[2][:100]+"\n"+parts[2][100:], "malformed"),
		refused("claims segment with a line break", keys.signRaw(current, mldsaHeader, parts[1][:20]+"\n"+parts[1][20:]), "malformed"),
		refused("header segment with a line break", keys.signRaw(current, parts[0][:10]+"\r\n"+parts[0][10:], parts[1]), "malformed"),
	)
	if nonCanonical == parts[0] {
		t.Fatal("the non-canonical header encoding is canonical")
	}

	boundTo := func(name, jkt string) verifyCase {
		return refused(name, edit(baseClaims(), func(m map[string]any) {
			m["cnf"] = map[string]any{"jkt": jkt}
		}), "thumbprint")
	}
	for _, jkt := range badThumbprints() {
		cases = append(cases, boundTo(jkt.name, jkt.value))
	}
	return cases
}

// badThumbprints are `cnf.jkt` values that are not an RFC 7638 SHA-256
// thumbprint, which a signer refuses to mint and a verifier to accept.
func badThumbprints() []struct{ name, value string } {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := vectorThumbprint[len(vectorThumbprint)-1]
	return []struct{ name, value string }{
		{"thumbprint of 32 characters", "OuXpLpEHW7dCPqjKWm8Zq1TfBb2nQ4Zt"},
		{"thumbprint of 44 characters", vectorThumbprint + "A"},
		{"thumbprint with padding", vectorThumbprint + "="},
		{"thumbprint with a character outside base64url", vectorThumbprint[:42] + "+"},
		{"thumbprint with non-canonical trailing bits", vectorThumbprint[:42] + string(alphabet[strings.IndexByte(alphabet, last)|1])},
		{"thumbprint with a line break", vectorThumbprint[:21] + "\n" + vectorThumbprint[21:]},
		{"thumbprint that is a device ID", vectorThumbprint[:16]},
	}
}

func buildSign(t *testing.T, keys vectorKeys) []signCase {
	t.Helper()
	current := keys.current()
	encode := func(claims Claims, change func(map[string]any)) json.RawMessage {
		return json.RawMessage(claimsJSON(claims, change))
	}
	full := baseClaims()
	full.ID, full.Via = "vector-full", "bea"
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
	for _, jkt := range badThumbprints()[1:] {
		if strings.Contains(jkt.name, "outside base64url") {
			continue
		}
		cases = append(cases, signCase{Name: jkt.name, Claims: encode(baseClaims(), func(m map[string]any) {
			m["cnf"] = map[string]any{"jkt": jkt.value}
		}), Error: "thumbprint"})
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

type keySetCase struct {
	Name     string   `json:"name"`
	Document string   `json:"document"`
	Kids     []string `json:"kids"`
	Error    string   `json:"error,omitempty"`
}

func buildKeySets(t *testing.T, keys vectorKeys) []keySetCase {
	t.Helper()
	jwk := func(kid string) string {
		encoded, err := keys.public[kid].JWK()
		if err != nil {
			t.Fatal(err)
		}
		return string(encoded)
	}
	current, next := jwk(keys.current()), jwk("pq-next")
	pub := base64.RawURLEncoding.EncodeToString(keys.public[keys.current()].Bytes())
	nextPub := base64.RawURLEncoding.EncodeToString(keys.public["pq-next"].Bytes())
	ed25519X := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x04}, 32))
	akp := func(kid, pub string) string {
		return `{"kty":"AKP","alg":"ML-DSA-87","kid":"` + kid + `","pub":"` + pub + `"}`
	}
	accepted := func(name, document string, kids ...string) keySetCase {
		if kids == nil {
			kids = []string{}
		}
		return keySetCase{Name: name, Document: document, Kids: kids}
	}
	refused := func(name, document, class string) keySetCase {
		return keySetCase{Name: name, Document: document, Error: class}
	}
	both := []string{keys.current(), "pq-next"}
	return []keySetCase{
		accepted("wrapped", `{"keys":[`+current+`,`+next+`]}`, both...),
		accepted("bare array", `[`+current+`,`+next+`]`, both...),
		accepted("empty", `{"keys":[]}`),
		accepted("members a key does not need are ignored",
			`{"keys":[{"kty":"AKP","alg":"ML-DSA-87","use":"sig","key_ops":["verify"],"kid":"old","pub":"`+pub+`"}],"cache":"max-age=60"}`, "old"),
		accepted("member names that differ only in case are not duplicates",
			`[{"kty":"AKP","alg":"ML-DSA-87","kid":"old","KID":"other","pub":"`+pub+`"}]`, "old"),

		refused("the same kid twice", `{"keys":[`+akp("k", pub)+`,`+akp("k", nextPub)+`]}`, "duplicate_kid"),
		refused("the same key twice", `{"keys":[`+current+`,`+current+`]}`, "duplicate_kid"),

		refused("not JSON", `{"keys":[`, "set_malformed"),
		refused("a single JWK rather than a set", current, "set_malformed"),
		refused("no keys member", `{}`, "set_malformed"),
		refused("keys is null", `{"keys":null}`, "set_malformed"),
		refused("null", `null`, "set_malformed"),
		refused("a key that is not an object", `["`+pub[:8]+`"]`, "set_malformed"),
		refused("a key with no kid", `[{"kty":"AKP","alg":"ML-DSA-87","pub":"`+pub+`"}]`, "set_malformed"),
		refused("a key with an empty kid", `[`+akp("", pub)+`]`, "set_malformed"),
		refused("a key with no kty", `[{"alg":"ML-DSA-87","kid":"old","pub":"`+pub+`"}]`, "set_malformed"),
		refused("member names are case-sensitive", `[{"kty":"AKP","alg":"ML-DSA-87","KID":"old","pub":"`+pub+`"}]`, "set_malformed"),
		refused("a null member", `[{"kty":"AKP","alg":null,"kid":"old","pub":"`+pub+`"}]`, "set_malformed"),
		refused("a member of the wrong type", `[{"kty":"AKP","alg":"ML-DSA-87","kid":7,"pub":"`+pub+`"}]`, "set_malformed"),
		refused("a member named twice", `[{"kty":"AKP","alg":"ML-DSA-87","kid":"old","pub":"AAAA","pub":"`+pub+`"}]`, "set_malformed"),
		refused("keys named twice", `{"keys":[],"keys":[`+current+`]}`, "set_malformed"),
		refused("a malformed key after a good one", `[`+current+`,{"kty":"AKP"}]`, "set_malformed"),
		refused("a kid with an unpaired surrogate escape", `[`+akp(`old\ud83d`, pub)+`]`, "set_malformed"),
		refused("an ignored member with an unpaired surrogate escape",
			`{"keys":[`+current+`],"note":"\udc00"}`, "set_malformed"),
		refused("a number too large for a double", `{"keys":[`+current+`],"version":1e400}`, "set_malformed"),
		refused("a leading-zero number", `{"keys":[`+current+`],"version":01}`, "set_malformed"),
		refused("nested one deeper than allowed",
			`[{"kty":"AKP","alg":"ML-DSA-87","kid":"old","pub":"`+pub+`","ext":`+strings.Repeat("[", 126)+strings.Repeat("]", 126)+`}]`, "set_malformed"),
		refused("a byte order mark", "\uFEFF["+current+"]", "set_malformed"),
		refused("data after the set", `[`+current+`] []`, "set_malformed"),
		refused("a raw control character in a string", "[{\"kty\":\"AKP\",\"alg\":\"ML-DSA-87\",\"kid\":\"o\x01ld\",\"pub\":\""+pub+"\"}]", "set_malformed"),
		refused("a top-level string", `"keys"`, "set_malformed"),
		refused("a key that is an array", `[["AKP","ML-DSA-87","old","`+pub+`"]]`, "set_malformed"),
		refused("a wrapped set that is an array", `[[[`+current+`]]]`, "set_malformed"),
		accepted("kids that differ only in Unicode normalization are distinct",
			`[`+akp("café", pub)+`,`+akp("café", pub)+`]`, "café", "café"),
		accepted("nested as deep as allowed",
			`[{"kty":"AKP","alg":"ML-DSA-87","kid":"old","pub":"`+pub+`","ext":`+strings.Repeat("[", 125)+strings.Repeat("]", 125)+`}]`, "old"),
		accepted("ignored members may be null or any number", `{"keys":[{"kty":"AKP","alg":"ML-DSA-87","use":null,"kid":"old","pub":"`+pub+`","n":[1.5,-0,1e-400]}],"next":null}`, "old"),
		accepted("a kid with a surrogate pair escape and whitespace", " [ "+akp(`old\ud83d\ude00`, pub)+" ]\n", "old\U0001F600"),

		refused("ML-DSA-65", `[{"kty":"AKP","alg":"ML-DSA-65","kid":"k","pub":"`+pub[:2603]+`"}]`, "key_unsupported"),
		refused("ML-DSA-44", `[{"kty":"AKP","alg":"ML-DSA-44","kid":"k","pub":"`+pub+`"}]`, "key_unsupported"),
		refused("AKP with no alg", `[{"kty":"AKP","kid":"k","pub":"`+pub+`"}]`, "key_unsupported"),
		refused("OKP Ed25519", `[{"kty":"OKP","crv":"Ed25519","kid":"k","x":"`+ed25519X+`"}]`, "key_unsupported"),
		refused("EC P-256", `[{"kty":"EC","crv":"P-256","kid":"k","x":"`+ed25519X+`","y":"`+ed25519X+`"}]`, "key_unsupported"),
		refused("OKP X25519", `[{"kty":"OKP","crv":"X25519","kid":"k","x":"`+ed25519X+`"}]`, "key_unsupported"),
		refused("an Ed25519 key after a good one", `[`+current+`,{"kty":"OKP","crv":"Ed25519","kid":"old","x":"`+ed25519X+`"}]`, "key_unsupported"),
		refused("an unsupported key after a good one", `[`+current+`,{"kty":"oct","kid":"k","k":"AAAA"}]`, "key_unsupported"),

		refused("ML-DSA-87 key of the wrong length", `[`+akp("k", pub[:len(pub)-4])+`]`, "key_invalid"),
		refused("ML-DSA-87 alg on an ML-DSA-65-sized key", `[`+akp("k", pub[:2603])+`]`, "key_invalid"),
		refused("public key with padding", `[`+akp("k", pub+"=")+`]`, "key_invalid"),
		refused("public key in standard base64", `[`+akp("k", "+"+pub[1:])+`]`, "key_invalid"),
		refused("public key with a line break", `[`+akp("k", pub[:20]+`\n`+pub[20:])+`]`, "key_invalid"),
		refused("no public key", `[{"kty":"AKP","alg":"ML-DSA-87","kid":"k"}]`, "key_invalid"),
	}
}

func runKeySetVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(vectorDirectory, "keysets.json"))
	if err != nil {
		t.Fatal(err)
	}
	var file vectorFile[keySetCase]
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	for _, c := range file.Cases {
		t.Run("keysets/"+c.Name, func(t *testing.T) {
			keys, err := ParseJWKSet([]byte(c.Document))
			if c.Error != "" {
				if Class(err) != c.Error || keys != nil {
					t.Fatalf("got %v (%q), want %s", err, Class(err), c.Error)
				}
				return
			}
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			kids := []string{}
			for _, key := range keys {
				kids = append(kids, key.ID())
			}
			if strings.Join(kids, ",") != strings.Join(c.Kids, ",") {
				t.Fatalf("kids %v, want %v", kids, c.Kids)
			}
		})
	}
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
	sealSpecs, seals := vectorSealKeys(t)
	files := map[string][]byte{
		"verify.json": encodeVectors(t, vectorFile[verifyCase]{
			Library:     "moqom-token",
			Description: "Verifying tokens: each case names the verifier's issuer, tenant pin, pool pin (absent: not checked) and key set, and gives the claims a verified token yields or the error class it is refused with.",
			Source:      "Generated by go/token/vectors_test.go (MOQOM_WRITE_VECTORS=1) with deterministic ML-DSA-87.",
			Keys:        keys.specs,
			Cases:       buildVerify(t, keys),
		}),
		"sign.json": encodeVectors(t, vectorFile[signCase]{
			Library:     "moqom-token",
			Description: "Signing tokens: the canonical header.claims bytes every implementation must produce for the claims given, and the token Go's deterministic ML-DSA-87 makes of them, or the error class signing is refused with.",
			Source:      "Generated by go/token/vectors_test.go (MOQOM_WRITE_VECTORS=1) with deterministic ML-DSA-87.",
			Keys:        keys.specs,
			Cases:       buildSign(t, keys),
		}),
		"seal.json": encodeVectors(t, sealVectorFile{
			Library:     "moqom-token",
			Description: "Sealing tokens: base64url(version 0x01 | 8-byte key id | 12-byte nonce | AES-256-GCM(segments)), with version and key id as additional data and segments the JWS header and claims, each after a two-byte big-endian length, then the signature, as raw bytes. Each case either seals a signed token under the key and nonce given and must match exactly, then opens it with the keys listed; or, with now set, verifies it with the signing keys and those seal keys, giving claims or an error class.",
			Source:      "Generated by go/token/vectors_test.go (MOQOM_WRITE_VECTORS=1) with deterministic ML-DSA-87 and fixed nonces.",
			Keys:        keys.specs,
			SealKeys:    sealSpecs,
			Cases:       buildSeal(t, keys, seals),
		}),
		"keysets.json": encodeVectors(t, vectorFile[keySetCase]{
			Library:     "moqom-token",
			Description: "Loading JWK sets: each case gives a document and either the key IDs it yields, in order, or the error class it is refused with.",
			Source:      "Generated by go/token/vectors_test.go (MOQOM_WRITE_VECTORS=1) from the keys listed.",
			Keys:        keys.specs,
			Cases:       buildKeySets(t, keys),
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
	runKeySetVectors(t)
	runSealVectors(t)
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
		signer, err := NewSigner(seedBytes)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(signer.PublicKey().Bytes(), raw) {
			t.Fatalf("key %s: the seed does not give the public key", spec.Kid)
		}
		signers[spec.Kid] = signer.WithID(spec.Kid)
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
			if c.Pool != nil {
				verifier = verifier.ForPool(*c.Pool)
			}
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
