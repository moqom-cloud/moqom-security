// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

package proof

// The generator for vectors/proof. It runs as a test so that it can reach the
// unexported signing path, and so that every `go test` checks that
// regenerating is a no-op: MOQOM_WRITE_VECTORS=1 writes the files, otherwise
// they are compared.
//
// Every signature is deterministic (ML-DSA's deterministic variant, RFC 6979
// for the ES256 proofs that must be refused, ML-DSA-65's for the ML-DSA-65
// ones). Implementations verifying them
// need not sign that way.

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const vectorDir = "../../vectors/proof"

const (
	vectorNow    = 1_700_000_000
	vectorUntil  = vectorNow + 600
	vectorWindow = 300
)

var (
	shortToken = "a.token"
	// Shaped like the compact JWS a token is, dots and all, so an
	// implementation that hashed only up to the first separator fails.
	jwsToken = "eyJhbGciOiJNTC1EU0EtNjUiLCJ0eXAiOiJNT1FUIiwia2lkIjoidmVjdG9yIn0" +
		".eyJpc3MiOiJodHRwczovL2FwaS5tb3FvbS5jbG91ZCIsImNuZiI6eyJqa3QiOiJ2ZWN0b3IifX0" +
		".c2lnbmF0dXJlLWJ5dGVzLXdoaWNoLW5vdGhpbmctaGVyZS12ZXJpZmllcw"
	certificate = sha256.Sum256([]byte("moqom-proof vector relay certificate"))
	elsewhere   = sha256.Sum256([]byte("moqom-proof vector other certificate"))
)

type vectorFile struct {
	Library     string `json:"library"`
	Description string `json:"description"`
	Source      string `json:"source"`
	Window      int64  `json:"window_seconds,omitempty"`
	Cases       any    `json:"cases"`
}

type keyCase struct {
	Name       string `json:"name"`
	Alg        string `json:"alg"`
	SeedHex    string `json:"seed_hex"`
	JWK        JWK    `json:"jwk"`
	Thumbprint string `json:"thumbprint"`
}

// vectorJWK is a JWK as a vector spells it, EC members included, so that the
// keys this package refuses can be written down.
type vectorJWK struct {
	Kty string `json:"kty"`
	Alg string `json:"alg,omitempty"`
	Pub string `json:"pub,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

func (v vectorJWK) jwk() JWK { return JWK{Kty: v.Kty, Alg: v.Alg, Pub: v.Pub} }

type thumbprintCase struct {
	Name       string    `json:"name"`
	JWK        vectorJWK `json:"jwk"`
	Thumbprint string    `json:"thumbprint,omitempty"`
	Error      string    `json:"error,omitempty"`
}

type proofCase struct {
	Name               string   `json:"name"`
	Token              string   `json:"token"`
	CertificateHashHex string   `json:"certificate_hash_hex"`
	Thumbprint         string   `json:"thumbprint"`
	Now                int64    `json:"now"`
	Until              int64    `json:"until"`
	Spent              []string `json:"spent,omitempty"`
	RequireCertificate bool     `json:"require_certificate,omitempty"`
	Proof              string   `json:"proof"`
	Error              string   `json:"error,omitempty"`
}

type vectorKey struct {
	name   string
	prover *Prover
	seed   []byte
}

func mldsaVectorKey(t *testing.T, name string, fill byte) vectorKey {
	seed := bytes.Repeat([]byte{fill}, mldsa.PrivateKeySize)
	key, err := mldsa.NewPrivateKey(mldsa.MLDSA87(), seed)
	if err != nil {
		t.Fatal(err)
	}
	prover, err := NewProver(key)
	if err != nil {
		t.Fatal(err)
	}
	return vectorKey{name: name, prover: prover.Deterministic(), seed: seed}
}

// classicalKey is a P-256 key, for ES256 proofs a checker must refuse: what an
// older device would send, correctly signed, and not post-quantum.
type classicalKey struct {
	key  *ecdsa.PrivateKey
	x, y string
}

func newClassicalKey(t *testing.T) classicalKey {
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), bytes.Repeat([]byte{0x07}, 32))
	if err != nil {
		t.Fatal(err)
	}
	point, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return classicalKey{key: key, x: b64.EncodeToString(point[1:33]), y: b64.EncodeToString(point[33:])}
}

func (k classicalKey) canonical() string {
	return `{"crv":"P-256","kty":"EC","x":"` + k.x + `","y":"` + k.y + `"}`
}

func (k classicalKey) thumbprint() string {
	sum := sha256.Sum256([]byte(k.canonical()))
	return b64.EncodeToString(sum[:])
}

// forge signs header and claims with ES256, the signature as JWS's r||s.
func (k classicalKey) forge(t *testing.T, header, claims string) string {
	signed := b64.EncodeToString([]byte(header)) + "." + b64.EncodeToString([]byte(claims))
	digest := sha256.Sum256([]byte(signed))
	der, err := k.key.Sign(nil, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &parsed); err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	parsed.R.FillBytes(signature[:32])
	parsed.S.FillBytes(signature[32:])
	return signed + "." + b64.EncodeToString(signature)
}

// mlDSA65Key is an ML-DSA-65 key, for proofs a checker must refuse: correctly
// signed, post-quantum, and not the parameter set MOQOM accepts.
type mlDSA65Key struct {
	key *mldsa.PrivateKey
	pub string
}

func newMLDSA65Key(t *testing.T) mlDSA65Key {
	key, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), bytes.Repeat([]byte{0x07}, mldsa.PrivateKeySize))
	if err != nil {
		t.Fatal(err)
	}
	return mlDSA65Key{key: key, pub: b64.EncodeToString(key.PublicKey().Bytes())}
}

func (k mlDSA65Key) canonical() string {
	return `{"alg":"ML-DSA-65","kty":"AKP","pub":"` + k.pub + `"}`
}

func (k mlDSA65Key) thumbprint() string {
	sum := sha256.Sum256([]byte(k.canonical()))
	return b64.EncodeToString(sum[:])
}

func (k mlDSA65Key) forge(t *testing.T, header, claims string) string {
	signed := b64.EncodeToString([]byte(header)) + "." + b64.EncodeToString([]byte(claims))
	signature, err := k.key.SignDeterministic([]byte(signed), nil)
	if err != nil {
		t.Fatal(err)
	}
	return signed + "." + b64.EncodeToString(signature)
}

// forge signs arbitrary header and claims JSON with key, for the cases a
// [Prover] will not make.
func forge(t *testing.T, key *Prover, header, claims string) string {
	signed := b64.EncodeToString([]byte(header)) + "." + b64.EncodeToString([]byte(claims))
	signature, err := key.sign([]byte(signed))
	if err != nil {
		t.Fatal(err)
	}
	return signed + "." + b64.EncodeToString(signature)
}

func claimsJSON(token string, iat int64, jti string, certificateHash []byte) string {
	ath := sha256.Sum256([]byte(token))
	return `{"ath":"` + b64.EncodeToString(ath[:]) + `","iat":` + strconv.FormatInt(iat, 10) +
		`,"jti":"` + jti + `","rel":"` + b64.EncodeToString(certificateHash) + `"}`
}

func prove(t *testing.T, key *Prover, token string, certificateHash []byte, jti string, iat int64) string {
	proof, err := key.Prove([]byte(token), certificateHash, jti, time.Unix(iat, 0))
	if err != nil {
		t.Fatal(err)
	}
	return string(proof)
}

// truncate drops the last n bytes of the signature, keeping the canonical
// spelling.
func truncate(t *testing.T, jws string, n int) string {
	at := strings.LastIndexByte(jws, '.') + 1
	signature := mustDecode(t, jws[at:])
	return jws[:at] + b64.EncodeToString(signature[:len(signature)-n])
}

// flip changes one base64url character of segment index (0, 1 or 2) to
// another, keeping the alphabet and the canonical spelling.
func flip(jws string, index int) string {
	parts := strings.Split(jws, ".")
	segment := []byte(parts[index])
	at := len(segment) / 2
	if segment[at] == 'A' {
		segment[at] = 'B'
	} else {
		segment[at] = 'A'
	}
	parts[index] = string(segment)
	return strings.Join(parts, ".")
}

func generate(t *testing.T) map[string]vectorFile {
	device := mldsaVectorKey(t, "ml-dsa-87 device", 0x07)
	other := mldsaVectorKey(t, "ml-dsa-87 other device", 0x08)
	classical := newClassicalKey(t)
	previous := newMLDSA65Key(t)

	var keys []keyCase
	for _, k := range []vectorKey{device, other} {
		keys = append(keys, keyCase{
			Name:       k.name,
			Alg:        string(k.prover.Algorithm()),
			SeedHex:    hex.EncodeToString(k.seed),
			JWK:        k.prover.JWK(),
			Thumbprint: k.prover.Thumbprint(),
		})
	}

	thumbprints := thumbprintCases(t, device.prover.JWK(), previous.pub)

	cert := certificate[:]
	ml := device.prover
	mlHeader := ml.header
	akp := ml.JWK()
	mlCanonical, _ := akp.canonical()
	esHeader := `{"alg":"ES256","typ":"MOQT-POP","jwk":` + classical.canonical() + `}`

	valid := prove(t, ml, shortToken, cert, "ml-dsa-valid", vectorNow)
	validES := classical.forge(t, esHeader, claimsJSON(shortToken, vectorNow, "es256-valid", cert))
	valid65 := previous.forge(t, `{"alg":"ML-DSA-65","typ":"MOQT-POP","jwk":`+previous.canonical()+`}`,
		claimsJSON(shortToken, vectorNow, "ml-dsa-65-valid", cert))

	c := func(name, token, proof string, thumbprint string, err string) proofCase {
		return proofCase{
			Name: name, Token: token, CertificateHashHex: hex.EncodeToString(cert),
			Thumbprint: thumbprint, Now: vectorNow, Until: vectorUntil, Proof: proof, Error: err,
		}
	}
	mlT, esT, ml65T := ml.Thumbprint(), classical.thumbprint(), previous.thumbprint()

	proofs := []proofCase{
		c("ml-dsa-87 valid", shortToken, valid, mlT, ""),
		c("ml-dsa-87 valid over a jws-shaped token", jwsToken,
			prove(t, ml, jwsToken, cert, "ml-dsa-jws", vectorNow), mlT, ""),
		c("es256 correctly signed, refused as not post-quantum", shortToken, validES, esT, "unsupported"),
		c("ml-dsa-65 correctly signed, refused as not ml-dsa-87", shortToken, valid65, ml65T, "unsupported"),
		c("ml-dsa-87 iat at the past edge of the window", shortToken,
			prove(t, ml, shortToken, cert, "ml-dsa-past-edge", vectorNow-vectorWindow), mlT, ""),
		c("ml-dsa-87 iat at the future edge of the window", shortToken,
			prove(t, ml, shortToken, cert, "ml-dsa-future-edge", vectorNow+vectorWindow), mlT, ""),

		c("ml-dsa-87 wrong certificate hash", shortToken,
			prove(t, ml, shortToken, elsewhere[:], "ml-dsa-elsewhere", vectorNow), mlT, "wrong_certificate"),
		c("ml-dsa-87 bound to no certificate", shortToken,
			prove(t, ml, shortToken, nil, "ml-dsa-unbound", vectorNow), mlT, "wrong_certificate"),

		c("ml-dsa-87 wrong token", jwsToken, valid, mlT, "wrong_token"),
		c("ml-dsa-87 token is a prefix of the one proven", "a", valid, mlT, "wrong_token"),

		c("ml-dsa-87 iat too old", shortToken,
			prove(t, ml, shortToken, cert, "ml-dsa-old", vectorNow-vectorWindow-1), mlT, "expired"),
		c("ml-dsa-87 iat in the future", shortToken,
			prove(t, ml, shortToken, cert, "ml-dsa-future", vectorNow+vectorWindow+1), mlT, "not_yet_valid"),

		c("ml-dsa-87 signed by a key the token does not name", shortToken, valid, other.prover.Thumbprint(), "wrong_key"),
		c("ml-dsa-87 proof for a token naming an es256 key", shortToken, valid, esT, "wrong_key"),
		c("es256 proof for a token naming an ml-dsa-87 key", shortToken, validES, mlT, "unsupported"),
		c("ml-dsa-65 proof for a token naming an ml-dsa-87 key", shortToken, valid65, mlT, "unsupported"),

		c("alg es256 over an akp key", shortToken,
			forge(t, ml, `{"alg":"ES256","typ":"MOQT-POP","jwk":`+mlCanonical+`}`,
				claimsJSON(shortToken, vectorNow, "confused-1", cert)), mlT, "unsupported"),
		c("alg ml-dsa-87 over an ec key", shortToken,
			forge(t, ml, `{"alg":"ML-DSA-87","typ":"MOQT-POP","jwk":`+classical.canonical()+`}`,
				claimsJSON(shortToken, vectorNow, "confused-2", cert)), esT, "unsupported"),
		c("alg ml-dsa-65 over an ml-dsa-87 key", shortToken,
			forge(t, ml, `{"alg":"ML-DSA-65","typ":"MOQT-POP","jwk":`+mlCanonical+`}`,
				claimsJSON(shortToken, vectorNow, "confused-65", cert)), mlT, "unsupported"),
		c("akp key naming ml-dsa-65", shortToken,
			forge(t, ml, `{"alg":"ML-DSA-87","typ":"MOQT-POP","jwk":`+previous.canonical()+`}`,
				claimsJSON(shortToken, vectorNow, "confused-65-key", cert)), ml65T, "unsupported"),
		c("akp key naming ml-dsa-44", shortToken,
			forge(t, ml, `{"alg":"ML-DSA-87","typ":"MOQT-POP","jwk":{"alg":"ML-DSA-44","kty":"AKP","pub":"`+akp.Pub+`"}}`,
				claimsJSON(shortToken, vectorNow, "confused-3", cert)), mlT, "unsupported"),
		c("alg none", shortToken,
			b64.EncodeToString([]byte(`{"alg":"none","typ":"MOQT-POP","jwk":`+mlCanonical+`}`))+"."+
				b64.EncodeToString([]byte(claimsJSON(shortToken, vectorNow, "none", cert)))+".", mlT, "unsupported"),
		c("alg eddsa", shortToken,
			forge(t, ml, `{"alg":"EdDSA","typ":"MOQT-POP","jwk":`+mlCanonical+`}`,
				claimsJSON(shortToken, vectorNow, "eddsa", cert)), mlT, "unsupported"),
		c("typ of a token rather than a proof", shortToken,
			forge(t, ml, `{"alg":"ML-DSA-87","typ":"MOQT","jwk":`+mlCanonical+`}`,
				claimsJSON(shortToken, vectorNow, "typ-moqt", cert)), mlT, "unsupported"),
		c("typ of an rfc 9449 dpop proof", shortToken,
			forge(t, ml, `{"alg":"ML-DSA-87","typ":"dpop+jwt","jwk":`+mlCanonical+`}`,
				claimsJSON(shortToken, vectorNow, "typ-dpop", cert)), mlT, "unsupported"),

		c("ml-dsa-87 signature altered", shortToken, flip(valid, 2), mlT, "bad_signature"),
		c("ml-dsa-87 claims altered after signing", shortToken, flip(valid, 1), mlT, "bad_signature"),
		c("ml-dsa-87 signature truncated", shortToken, truncate(t, valid, 6), mlT, "bad_signature"),
		c("ml-dsa-87 signature by another key under this key's header", shortToken,
			forge(t, other.prover, mlHeader, claimsJSON(shortToken, vectorNow, "swapped", cert)), mlT, "bad_signature"),

		c("ml-dsa-87 replayed nonce", shortToken, valid, mlT, "replayed"),

		c("empty", shortToken, "", mlT, "malformed"),
		c("only separators", shortToken, "..", mlT, "malformed"),
		c("two segments", shortToken, strings.Join(strings.Split(valid, ".")[:2], "."), mlT, "malformed"),
		c("four segments", shortToken, valid+".AAAA", mlT, "malformed"),
		c("header is not base64url", shortToken, "!!!"+valid[strings.Index(valid, "."):], mlT, "malformed"),
		c("header is not json", shortToken,
			forge(t, ml, `not json`, claimsJSON(shortToken, vectorNow, "nojson", cert)), mlT, "malformed"),
		c("header carries no key", shortToken,
			forge(t, ml, `{"alg":"ML-DSA-87","typ":"MOQT-POP"}`, claimsJSON(shortToken, vectorNow, "nokey", cert)), mlT, "malformed"),
		c("akp key carrying priv", shortToken,
			forge(t, ml, `{"alg":"ML-DSA-87","typ":"MOQT-POP","jwk":{"alg":"ML-DSA-87","kty":"AKP","priv":"`+b64.EncodeToString(device.seed)+`","pub":"`+akp.Pub+`"}}`,
				claimsJSON(shortToken, vectorNow, "private-priv", cert)), mlT, "malformed"),
		c("akp key carrying seed", shortToken,
			forge(t, ml, `{"alg":"ML-DSA-87","typ":"MOQT-POP","jwk":{"alg":"ML-DSA-87","kty":"AKP","pub":"`+akp.Pub+`","seed":"`+b64.EncodeToString(device.seed)+`"}}`,
				claimsJSON(shortToken, vectorNow, "private-seed", cert)), mlT, "malformed"),
		c("akp key carrying d", shortToken,
			forge(t, ml, `{"alg":"ML-DSA-87","typ":"MOQT-POP","jwk":{"alg":"ML-DSA-87","d":"`+b64.EncodeToString(device.seed)+`","kty":"AKP","pub":"`+akp.Pub+`"}}`,
				claimsJSON(shortToken, vectorNow, "private-akp-d", cert)), mlT, "malformed"),
		c("signature is padded", shortToken, valid+"=", mlT, "malformed"),
		c("akp pub is the wrong length", shortToken,
			forge(t, ml, `{"alg":"ML-DSA-87","typ":"MOQT-POP","jwk":{"alg":"ML-DSA-87","kty":"AKP","pub":"`+akp.Pub[:len(akp.Pub)-4]+`"}}`,
				claimsJSON(shortToken, vectorNow, "short-pub", cert)), mlT, "malformed"),
		c("claims are not json", shortToken, forge(t, ml, mlHeader, `not json`), mlT, "malformed"),
		c("no iat", shortToken,
			forge(t, ml, mlHeader, `{"ath":"`+athOf(shortToken)+`","jti":"no-iat","rel":"`+b64.EncodeToString(cert)+`"}`), mlT, "malformed"),
		c("iat is a string", shortToken,
			forge(t, ml, mlHeader, `{"ath":"`+athOf(shortToken)+`","iat":"1700000000","jti":"iat-string","rel":"`+b64.EncodeToString(cert)+`"}`), mlT, "malformed"),
		c("iat is not an integer", shortToken,
			forge(t, ml, mlHeader, `{"ath":"`+athOf(shortToken)+`","iat":1700000000.5,"jti":"iat-float","rel":"`+b64.EncodeToString(cert)+`"}`), mlT, "malformed"),
		c("no jti", shortToken,
			forge(t, ml, mlHeader, `{"ath":"`+athOf(shortToken)+`","iat":1700000000,"rel":"`+b64.EncodeToString(cert)+`"}`), mlT, "malformed"),
		c("longer than the limit", shortToken, strings.Repeat("a", MaxProofBytes+1), mlT, "malformed"),
	}
	for i := range proofs {
		switch proofs[i].Name {
		case "ml-dsa-87 replayed nonce":
			proofs[i].Spent = []string{"ml-dsa-valid"}
		}
	}
	withoutCertificate := func(name, proof, thumbprint, err string, require bool) proofCase {
		return proofCase{
			Name: name, Token: shortToken, Thumbprint: thumbprint, Now: vectorNow, Until: vectorUntil,
			RequireCertificate: require, Proof: proof, Error: err,
		}
	}
	noRel := `{"ath":"` + athOf(shortToken) + `","iat":1700000000,"jti":"ml-dsa-no-rel"}`
	proofs = append(proofs,
		withoutCertificate("ml-dsa-87 bound to no certificate, checked by a checker with none",
			prove(t, ml, shortToken, nil, "ml-dsa-unbound-ok", vectorNow), mlT, "", false),
		withoutCertificate("ml-dsa-87 with no rel, checked by a checker with none",
			forge(t, ml, mlHeader, noRel), mlT, "", false),
		withoutCertificate("ml-dsa-87 bound to a certificate, checked by a checker with none",
			prove(t, ml, shortToken, cert, "ml-dsa-unverifiable", vectorNow), mlT, "wrong_certificate", false),
		withoutCertificate("ml-dsa-87 bound to no certificate, checked by a checker that requires one and has none",
			prove(t, ml, shortToken, nil, "ml-dsa-required", vectorNow), mlT, "wrong_certificate", true),
		withoutCertificate("ml-dsa-87 bound to a certificate, checked by a checker that requires one and has none",
			prove(t, ml, shortToken, cert, "ml-dsa-required-bound", vectorNow), mlT, "wrong_certificate", true),
	)
	noRelBound := c("ml-dsa-87 with no rel, checked by a checker with a certificate", shortToken,
		forge(t, ml, mlHeader, `{"ath":"`+athOf(shortToken)+`","iat":1700000000,"jti":"ml-dsa-no-rel-bound"}`), mlT, "wrong_certificate")
	proofs = append(proofs, noRelBound)
	requiredWithCertificate := c("ml-dsa-87 valid at a checker that requires a certificate and has one", shortToken,
		prove(t, ml, shortToken, cert, "ml-dsa-required-ok", vectorNow), mlT, "")
	requiredWithCertificate.RequireCertificate = true
	proofs = append(proofs, requiredWithCertificate)
	proofs = append(proofs, strictJSONCases(t, c, ml, mlT, other.prover.JWK().Pub)...)
	proofs = append(proofs, byteCases(t, c, ml, mlT)...)

	const source = "Generated by go/proof/generate_test.go (MOQOM_WRITE_VECTORS=1 go test ./proof); signatures are deterministic."
	return map[string]vectorFile{
		"keys.json": {
			Library:     "moqom-proof",
			Description: "ML-DSA-87 device keys from seeds, with the public JWK and thumbprint each must produce.",
			Source:      source, Cases: keys,
		},
		"thumbprints.json": {
			Library: "moqom-proof",
			Description: "JWK thumbprints: draft-ietf-cose-dilithium (alg, kty, pub) for AKP ML-DSA-87, and keys that have none, " +
				"including every classical key and every other ML-DSA parameter set: EC, OKP, RSA, ML-DSA-44 and ML-DSA-65 are refused as unsupported, since only ML-DSA-87 is accepted.",
			Source: source + " The first EC case is RFC 7517 appendix A.1.",
			Cases:  thumbprints,
		},
		"proofs.json": {
			Library: "moqom-proof",
			Description: "Proofs to check: each against token, certificate_hash_hex (SHA-256 of the peer's leaf certificate; empty for none), " +
				"thumbprint (the token's cnf.jkt), now, with nonces in spent already spent until until. A case with error must be refused with that class.",
			Source: source, Window: vectorWindow, Cases: proofs,
		},
	}
}

// strictJSONCases are signed proofs whose header or claims two JSON parsers
// could read differently: a member named twice, names that differ only in
// case, null for a known member, an array where an object belongs, a number
// that is integral but not an integer literal, an unpaired surrogate, and bytes
// that are not UTF-8. Each is signed, so an implementation that let its parser
// choose would accept it or refuse it for another reason.
func strictJSONCases(t *testing.T, c func(name, token, proof, thumbprint, err string) proofCase, ml *Prover, mlT, otherPub string) []proofCase {
	akp := ml.JWK()
	mlCanonical, _ := akp.canonical()
	cert := certificate[:]
	rel := b64.EncodeToString(cert)
	header := func(name, header, jti, err string) proofCase {
		return c(name, shortToken, forge(t, ml, header, claimsJSON(shortToken, vectorNow, jti, cert)), mlT, err)
	}
	claims := func(name, claims, err string) proofCase {
		return c(name, shortToken, forge(t, ml, ml.header, claims), mlT, err)
	}
	akpWith := func(members string) string {
		return `{"alg":"ML-DSA-87","typ":"MOQT-POP","jwk":{` + members + `}}`
	}
	tail := func(jti string) string {
		return `"iat":1700000000,"jti":"` + jti + `","rel":"` + rel + `"}`
	}
	ath := `"ath":"` + athOf(shortToken) + `",`
	return []proofCase{
		header("duplicate header alg with another value",
			`{"alg":"ES256","alg":"ML-DSA-87","typ":"MOQT-POP","jwk":`+mlCanonical+`}`, "dup-alg", "malformed"),
		header("duplicate header typ",
			`{"alg":"ML-DSA-87","typ":"MOQT-POP","typ":"MOQT-POP","jwk":`+mlCanonical+`}`, "dup-typ", "malformed"),
		header("duplicate header jwk",
			`{"alg":"ML-DSA-87","typ":"MOQT-POP","jwk":{"alg":"ML-DSA-87","kty":"AKP","pub":"`+otherPub+`"},"jwk":`+mlCanonical+`}`, "dup-jwk", "malformed"),
		header("duplicate jwk member pub",
			akpWith(`"alg":"ML-DSA-87","kty":"AKP","pub":"`+otherPub+`","pub":"`+akp.Pub+`"`), "dup-pub", "malformed"),
		header("duplicate jwk member spelled with an escape",
			akpWith(`"alg":"ML-DSA-87","kty":"AKP","p\u0075b":"`+otherPub+`","pub":"`+akp.Pub+`"`), "dup-pub-escaped", "malformed"),
		header("duplicate member in an unknown header parameter",
			`{"alg":"ML-DSA-87","typ":"MOQT-POP","jwk":`+mlCanonical+`,"later":[{"a":1,"a":2}]}`, "dup-later", "malformed"),
		header("header member names that differ only in case",
			`{"alg":"ML-DSA-87","typ":"MOQT-POP","jwk":{"alg":"ML-DSA-87","kty":"AKP","pub":"`+akp.Pub+`","PUB":"`+otherPub+`"},"ALG":"ES256","Typ":"MOQT"}`, "header-case", ""),
		header("header is a json array",
			`["ML-DSA-87","MOQT-POP",`+mlCanonical+`]`, "header-array", "malformed"),
		header("header is null", `null`, "header-null", "malformed"),
		header("header alg is null",
			`{"alg":null,"typ":"MOQT-POP","jwk":`+mlCanonical+`}`, "alg-null", "malformed"),
		header("jwk member is null",
			akpWith(`"alg":"ML-DSA-87","kty":"AKP","pub":null`), "pub-null", "malformed"),
		header("header with an unpaired surrogate escape",
			`{"alg":"ML-DSA-87","typ":"MOQT-POP","jwk":`+mlCanonical+`,"later":"\ud800"}`, "header-surrogate", "malformed"),
		header("header that is not utf-8",
			`{"alg":"ML-DSA-87","typ":"MOQT-POP","jwk":`+mlCanonical+`,"later":"`+"\xff"+`"}`, "header-utf8", "malformed"),

		claims("duplicate claim ath",
			`{"ath":"`+athOf(jwsToken)+`",`+ath+tail("dup-ath"), "malformed"),
		claims("duplicate claim iat",
			`{`+ath+`"iat":1,`+tail("dup-iat"), "malformed"),
		claims("duplicate claim jti",
			`{`+ath+`"jti":"dup-jti-first",`+tail("dup-jti-second"), "malformed"),
		claims("duplicate claim rel",
			`{`+ath+`"iat":1700000000,"jti":"dup-rel","rel":"`+b64.EncodeToString(elsewhere[:])+`","rel":"`+rel+`"}`, "malformed"),
		claims("duplicate claim spelled with an escape",
			`{"\u0061th":"`+athOf(jwsToken)+`",`+ath+tail("dup-escaped"), "malformed"),
		claims("duplicate member in an object inside an array in an unknown claim",
			`{`+ath+`"later":[{"a":1},{"b":[{"c":1,"c":1}]}],`+tail("dup-nested"), "malformed"),
		claims("claim names that differ only in case or sit in sibling objects",
			`{`+ath+`"ATH":"`+athOf(jwsToken)+`","Rel":"","later":[{"a":1},{"a":1}],"Later":{"a":{"a":1}},`+tail("claims-case"), ""),
		claims("claims are a json array",
			`["`+athOf(shortToken)+`",1700000000,"claims-array","`+rel+`"]`, "malformed"),
		claims("claims are null", `null`, "malformed"),
		claims("ath is null", `{"ath":null,`+tail("ath-null"), "malformed"),
		claims("rel is null", `{`+ath+`"iat":1700000000,"jti":"rel-null","rel":null}`, "malformed"),
		claims("jti is null", `{`+ath+`"iat":1700000000,"jti":null,"rel":"`+rel+`"}`, "malformed"),
		claims("iat is null", `{`+ath+`"iat":null,"jti":"iat-null","rel":"`+rel+`"}`, "malformed"),
		claims("iat in exponent form", `{`+ath+`"iat":1.7e9,"jti":"iat-exponent","rel":"`+rel+`"}`, "malformed"),
		claims("iat with a zero fraction", `{`+ath+`"iat":1700000000.0,"jti":"iat-fraction","rel":"`+rel+`"}`, "malformed"),
		claims("jti with an unpaired surrogate escape", `{`+ath+`"iat":1700000000,"jti":"\udc00x","rel":"`+rel+`"}`, "malformed"),
		claims("jti with a surrogate pair", `{`+ath+`"iat":1700000000,"jti":"\ud83d\ude00-pair","rel":"`+rel+`"}`, ""),
		header("header nested as deep as allowed",
			`{"alg":"ML-DSA-87","typ":"MOQT-POP","jwk":`+mlCanonical+`,"later":`+strings.Repeat("[", 126)+strings.Repeat("]", 126)+`}`, "depth-127", ""),
		header("header nested one deeper than allowed",
			`{"alg":"ML-DSA-87","typ":"MOQT-POP","jwk":`+mlCanonical+`,"later":`+strings.Repeat("[", 127)+strings.Repeat("]", 127)+`}`, "depth-128", "malformed"),
		claims("claims with a number too large for a double", `{`+ath+`"later":1e400,`+tail("number-overflow"), "malformed"),
		claims("claims with a number too small for a double", `{`+ath+`"later":1e-400,`+tail("number-underflow"), ""),
		claims("claims that are not utf-8", `{`+ath+`"later":"`+"\xc3"+`",`+tail("claims-utf8"), "malformed"),
	}
}

// byteCases are proofs that a reader comparing strings by canonical Unicode
// equivalence (Swift's ==) or reading -0 as an integer would judge otherwise.
func byteCases(t *testing.T, c func(name, token, proof, thumbprint, err string) proofCase, ml *Prover, mlT string) []proofCase {
	cert := certificate[:]
	rel := b64.EncodeToString(cert)
	ath := `"ath":"` + athOf(shortToken) + `",`
	signed := func(header, claims string) string { return forge(t, ml, header, claims) }

	equivalent := c("nonce canonically equivalent to a spent one",
		shortToken, signed(ml.header, claimsJSON(shortToken, vectorNow, "nonce-\u00e9", cert)), mlT, "")
	equivalent.Spent = []string{"nonce-e\u0301"}
	return []proofCase{
		c("iat is negative zero", shortToken,
			signed(ml.header, `{`+ath+`"iat":-0,"jti":"iat-negative-zero","rel":"`+rel+`"}`), mlT, "malformed"),
		c("jwk kty spelled with a kelvin sign", shortToken,
			signed(`{"alg":"ML-DSA-87","typ":"MOQT-POP","jwk":{"alg":"ML-DSA-87","kty":"A`+"\u212a"+`P","pub":"`+ml.JWK().Pub+`"}}`,
				claimsJSON(shortToken, vectorNow, "kty-kelvin", cert)), mlT, "unsupported"),
		equivalent,
	}
}

func athOf(token string) string {
	sum := sha256.Sum256([]byte(token))
	return b64.EncodeToString(sum[:])
}

func thumbprintCases(t *testing.T, akp JWK, mlDSA65Pub string) []thumbprintCase {
	var zero [32]byte
	ok := func(name string, jwk JWK) thumbprintCase {
		thumbprint, err := jwk.Thumbprint()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return thumbprintCase{Name: name, JWK: vectorJWK{Kty: jwk.Kty, Alg: jwk.Alg, Pub: jwk.Pub}, Thumbprint: thumbprint}
	}
	bad := func(name string, jwk vectorJWK) thumbprintCase {
		_, err := jwk.jwk().Thumbprint()
		if err == nil {
			t.Fatalf("%s: accepted", name)
		}
		return thumbprintCase{Name: name, JWK: jwk, Error: Class(err)}
	}
	return []thumbprintCase{
		ok("akp ml-dsa-87 key", akp),
		bad("rfc 7517 a.1 ec p-256 key, not post-quantum", vectorJWK{Kty: "EC", Crv: "P-256",
			X: "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4", Y: "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}),
		bad("ec p-384", vectorJWK{Kty: "EC", Crv: "P-384",
			X: b64.EncodeToString(zero[:]), Y: b64.EncodeToString(zero[:])}),
		bad("okp ed25519", vectorJWK{Kty: "OKP", Crv: "Ed25519", X: b64.EncodeToString(zero[:])}),
		bad("akp ml-dsa-65", vectorJWK{Kty: "AKP", Alg: "ML-DSA-65", Pub: mlDSA65Pub}),
		bad("akp ml-dsa-65 alg on an ml-dsa-87 key", vectorJWK{Kty: "AKP", Alg: "ML-DSA-65", Pub: akp.Pub}),
		bad("akp ml-dsa-87 alg on an ml-dsa-65 key", vectorJWK{Kty: "AKP", Alg: "ML-DSA-87", Pub: mlDSA65Pub}),
		bad("akp ml-dsa-44", vectorJWK{Kty: "AKP", Alg: "ML-DSA-44", Pub: akp.Pub}),
		bad("akp with no alg", vectorJWK{Kty: "AKP", Pub: akp.Pub}),
		bad("akp pub one byte short", vectorJWK{Kty: "AKP", Alg: "ML-DSA-87",
			Pub: b64.EncodeToString(mustDecode(t, akp.Pub)[1:])}),
		bad("empty", vectorJWK{}),
	}
}

func mustDecode(t *testing.T, value string) []byte {
	raw, err := b64.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestGenerateVectors(t *testing.T) {
	write := os.Getenv("MOQOM_WRITE_VECTORS") == "1"
	for name, file := range generate(t) {
		encoded, err := json.MarshalIndent(file, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		encoded = append(encoded, '\n')
		path := filepath.Join(vectorDir, name)
		if write {
			if err := os.WriteFile(path, encoded, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		committed, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v (regenerate with MOQOM_WRITE_VECTORS=1)", name, err)
		}
		if !bytes.Equal(committed, encoded) {
			t.Errorf("%s: regenerating is not a no-op; run with MOQOM_WRITE_VECTORS=1 if the format changed", name)
		}
	}
}
