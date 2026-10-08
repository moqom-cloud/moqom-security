// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

package token

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"
)

// Failures a caller can tell apart, because they mean different things: a
// malformed token is a client bug, an expired one is routine, and a bad
// signature is worth counting. Each is one of the error classes the shared
// vectors name, given by Class.
var (
	ErrMalformed    = errors.New("token is malformed")
	ErrUnsupported  = errors.New("token algorithm or type is not supported")
	ErrUnknownKey   = errors.New("token was signed by an unknown key")
	ErrBadSignature = errors.New("token signature does not verify")
	ErrExpired      = errors.New("token has expired")
	ErrNotYetValid  = errors.New("token is not valid yet")
	ErrLifetime     = errors.New("token lifetime is out of range")
	ErrWrongIssuer  = errors.New("token was issued by another deployment")
	ErrWrongTenant  = errors.New("token is for another tenant")
	ErrIncomplete   = errors.New("token does not name a complete identity")
	ErrThumbprint   = errors.New("token is not bound to an RFC 7638 SHA-256 thumbprint")
)

// Class is the vector error class of err, or "" if err is none of the above.
func Class(err error) string {
	for _, class := range []struct {
		err  error
		name string
	}{
		{ErrMalformed, "malformed"},
		{ErrUnsupported, "unsupported"},
		{ErrUnknownKey, "unknown_key"},
		{ErrBadSignature, "bad_signature"},
		{ErrExpired, "expired"},
		{ErrNotYetValid, "not_yet_valid"},
		{ErrLifetime, "lifetime"},
		{ErrWrongIssuer, "wrong_issuer"},
		{ErrWrongTenant, "wrong_tenant"},
		{ErrIncomplete, "incomplete"},
		{ErrThumbprint, "thumbprint"},
	} {
		if errors.Is(err, class.err) {
			return class.name
		}
	}
	return ""
}

// Type is the JWS `typ` every token carries, so a JWS minted for anything else
// in a deployment cannot be replayed at a relay.
const Type = "MOQT"

// MaxLifetime caps how long a token is good for, from `iat` to `exp`.
//
// Enforced on both sides. A token is a bearer credential until its holder
// proves the key `cnf.jkt` names, and the window in which a leaked one is
// useful is its remaining lifetime; a caller asking for longer is refused
// rather than clamped.
const MaxLifetime = 15 * time.Minute

// ClockSkew is how much disagreement between the minting and verifying clocks
// is tolerated. One-directional in effect: a token from slightly in the future
// is a clock, an expired one is a boundary and is not extended further.
const ClockSkew = 30 * time.Second

// MaxTokenBytes bounds a token before anything in it is decoded. A real one is
// about five kilobytes, nearly all of it the 3,309-byte ML-DSA-65 signature.
const MaxTokenBytes = 8192

// Claims is what a token asserts, in the order and spelling it has on the wire.
//
// Unknown top-level claims in a token are ignored, so an issuer can add one
// without upgrading every verifier first; the grant is the exception, see
// Grant.
type Claims struct {
	Issuer  string `json:"iss"`
	Subject string `json:"sub"`
	// Tenant is the customer the token is for, carried as the audience.
	Tenant   string `json:"aud"`
	ID       string `json:"jti"`
	IssuedAt int64  `json:"iat"`
	Expires  int64  `json:"exp"`

	Confirmation Confirmation `json:"cnf"`
	Grant        Grant        `json:"moqt"`

	// Via is the username whose following brought the holder in. Provenance,
	// not authorisation: it grants nothing.
	Via string `json:"via,omitempty"`
	// E2EE is the room's end-to-end encryption policy, for the client.
	E2EE string `json:"e2ee,omitempty"`
}

// Confirmation is what the token is bound to.
type Confirmation struct {
	// Thumbprint is the RFC 7638 SHA-256 thumbprint of the device key, base64url.
	Thumbprint string `json:"jkt"`
}

// Grant is what the holder may do, the `moqt` claim.
//
// Parsed strictly: a field this build does not know is refused, because a field
// added later is as likely to narrow a grant as to widen one, and a verifier
// that ignored a narrowing would enforce more than was issued.
type Grant struct {
	Room string `json:"room,omitempty"`
	// Publish and Capabilities are bitmasks whose bit positions belong to the
	// deployment's protocol, not to this package.
	Publish      uint8  `json:"pub"`
	Capabilities uint32 `json:"cap"`
	Owner        bool   `json:"own,omitempty"`
	Backstage    bool   `json:"bs,omitempty"`
	AgeVerified  bool   `json:"age,omitempty"`
	// Relay marks another relay's link to the one this is presented to.
	Relay bool `json:"rly,omitempty"`
}

// IssuedAtTime and ExpiresTime are the times as time.Time.
func (c Claims) IssuedAtTime() time.Time { return time.Unix(c.IssuedAt, 0) }
func (c Claims) ExpiresTime() time.Time  { return time.Unix(c.Expires, 0) }

// ValidThumbprint reports whether thumbprint is an RFC 7638 SHA-256
// thumbprint: 43 base64url characters decoding to 32 bytes. A token whose
// `cnf.jkt` is anything else is bound to no key at all, since no proof of
// possession can match it.
func ValidThumbprint(thumbprint string) bool {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(thumbprint)
	return err == nil && len(decoded) == sha256.Size
}

type header struct {
	Algorithm Algorithm `json:"alg"`
	Type      string    `json:"typ"`
	KeyID     string    `json:"kid"`
}

// segment is the canonical encoding of a header or claims: Go's struct order,
// no insignificant whitespace, and HTML characters left alone. The other two
// implementations write the same bytes, which the sign vectors pin.
func segment(value any) (string, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes.TrimSuffix(buffer.Bytes(), []byte("\n"))), nil
}

// signingInput checks claims as Sign does and returns `header.claims`.
func signingInput(algorithm Algorithm, keyID string, claims Claims) (string, error) {
	for _, text := range []string{
		claims.Issuer, claims.Subject, claims.Tenant, claims.ID, claims.Confirmation.Thumbprint,
		claims.Grant.Room, claims.Via, claims.E2EE, keyID,
	} {
		if !utf8.ValidString(text) {
			return "", fmt.Errorf("%w: a claim is not UTF-8", ErrMalformed)
		}
	}
	if claims.Subject == "" || claims.Tenant == "" || claims.Confirmation.Thumbprint == "" {
		return "", fmt.Errorf("%w: a token needs a subject, a tenant and a device thumbprint", ErrIncomplete)
	}
	if !ValidThumbprint(claims.Confirmation.Thumbprint) {
		return "", ErrThumbprint
	}
	if claims.IssuedAt == 0 || claims.Expires <= claims.IssuedAt ||
		claims.Expires-claims.IssuedAt > int64(MaxLifetime/time.Second) {
		return "", fmt.Errorf("%w: iat and exp must be set, in order, at most %s apart", ErrLifetime, MaxLifetime)
	}
	encodedHeader, err := segment(header{Algorithm: algorithm, Type: Type, KeyID: keyID})
	if err != nil {
		return "", err
	}
	encodedClaims, err := segment(claims)
	if err != nil {
		return "", err
	}
	return encodedHeader + "." + encodedClaims, nil
}
