// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

package token

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// Verifier checks tokens against a set of keys.
//
// A set rather than one key, because rotation needs an overlap: the new key is
// published, signing moves to it, and the old one stays verifiable until the
// last token it signed has expired.
type Verifier struct {
	keys map[string]PublicKey
	// Issuer, if set, is the only `iss` accepted, so a token from another
	// deployment that happens to share a key identifier is refused.
	issuer string
	tenant string
}

// NewVerifier accepts tokens signed by keys and issued by issuer; an empty
// issuer accepts any.
func NewVerifier(issuer string, keys ...PublicKey) *Verifier {
	byID := make(map[string]PublicKey, len(keys))
	for _, key := range keys {
		byID[key.id] = key
	}
	return &Verifier{keys: byID, issuer: issuer}
}

// ForTenant is the same verifier refusing every token not issued for tenant
// (ErrWrongTenant). Empty accepts any.
func (v *Verifier) ForTenant(tenant string) *Verifier {
	return &Verifier{keys: v.keys, issuer: v.issuer, tenant: tenant}
}

// Key is the key named id, if the set has one.
func (v *Verifier) Key(id string) (PublicKey, bool) {
	key, ok := v.keys[id]
	return key, ok
}

// Verify checks token at now and returns its claims.
//
// The signature is checked before any claim is read: acting on a claim from an
// unverified token, even to word an error, is how a parser becomes an attack
// surface. Then the claims, in this order: issuer, expiry, not-before,
// lifetime, completeness, tenant.
func (v *Verifier) Verify(token string, now time.Time) (Claims, error) {
	if len(token) == 0 || len(token) > MaxTokenBytes {
		return Claims{}, fmt.Errorf("%w: token length is out of range", ErrMalformed)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, fmt.Errorf("%w: expected three segments", ErrMalformed)
	}

	headerBytes, err := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if err != nil {
		return Claims{}, fmt.Errorf("%w: header is not base64url", ErrMalformed)
	}
	var parsed header
	if err := decodeHeader(headerBytes, &parsed); err != nil {
		return Claims{}, fmt.Errorf("%w: header is not JSON", ErrMalformed)
	}
	if parsed.Type != Type {
		return Claims{}, fmt.Errorf("%w: type %q is not a MOQT token", ErrUnsupported, parsed.Type)
	}
	key, ok := v.keys[parsed.KeyID]
	if !ok {
		return Claims{}, fmt.Errorf("%w: %q", ErrUnknownKey, parsed.KeyID)
	}
	if parsed.Algorithm != key.algorithm {
		return Claims{}, fmt.Errorf("%w: %q for a %s key", ErrUnsupported, parsed.Algorithm, key.algorithm)
	}

	signature, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil {
		return Claims{}, fmt.Errorf("%w: signature is not base64url", ErrMalformed)
	}
	if !key.Verify([]byte(parts[0]+"."+parts[1]), signature) {
		return Claims{}, ErrBadSignature
	}

	claimsBytes, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil {
		return Claims{}, fmt.Errorf("%w: claims are not base64url", ErrMalformed)
	}
	claims, err := decodeClaims(claimsBytes)
	if err != nil {
		return Claims{}, fmt.Errorf("%w: claims are not JSON", ErrMalformed)
	}
	if err := v.check(claims, now); err != nil {
		return Claims{}, err
	}
	return claims, nil
}

func (v *Verifier) check(claims Claims, now time.Time) error {
	if v.issuer != "" && claims.Issuer != v.issuer {
		return fmt.Errorf("%w: issued by %q", ErrWrongIssuer, claims.Issuer)
	}
	if claims.Expires == 0 {
		return fmt.Errorf("%w: no expiry", ErrMalformed)
	}
	// Whole seconds, as the claims are, so every implementation draws the
	// boundaries at the same instant.
	seconds, skew, limit := now.Unix(), int64(ClockSkew/time.Second), int64(MaxLifetime/time.Second)
	if seconds-skew > claims.Expires {
		return fmt.Errorf("%w: expired at %s", ErrExpired, claims.ExpiresTime().UTC())
	}
	if claims.IssuedAt != 0 && seconds+skew < claims.IssuedAt {
		return fmt.Errorf("%w: issued at %s", ErrNotYetValid, claims.IssuedAtTime().UTC())
	}
	// Without `iat` the lifetime is measured from now, with the skew allowed,
	// so leaving it out cannot buy a longer token.
	if claims.IssuedAt != 0 {
		if claims.Expires-claims.IssuedAt > limit {
			return fmt.Errorf("%w: valid for %ds", ErrLifetime, claims.Expires-claims.IssuedAt)
		}
	} else if claims.Expires-seconds > limit+skew {
		return fmt.Errorf("%w: valid for %ds", ErrLifetime, claims.Expires-seconds)
	}
	if claims.Subject == "" || claims.Tenant == "" || claims.Confirmation.Thumbprint == "" {
		return ErrIncomplete
	}
	if v.tenant != "" && claims.Tenant != v.tenant {
		return fmt.Errorf("%w: %q", ErrWrongTenant, claims.Tenant)
	}
	return nil
}

// decodeHeader reads exactly alg, typ and kid. Any other parameter is refused,
// since one this build does not know (`crit`, `jku`, `x5u`) may change what the
// signature means.
func decodeHeader(data []byte, into *header) error {
	if err := uniqueMembers(data); err != nil {
		return err
	}
	fields, err := object(data)
	if err != nil {
		return err
	}
	return fieldsInto(fields, map[string]any{
		"alg": &into.Algorithm, "typ": &into.Type, "kid": &into.KeyID,
	}, true)
}

// decodeClaims reads the claims with exact, case-sensitive member names, which
// encoding/json's struct decoding does not give: the other implementations
// would not see a "Sub" as `sub`, so neither may this one.
func decodeClaims(data []byte) (Claims, error) {
	var claims Claims
	if err := uniqueMembers(data); err != nil {
		return Claims{}, err
	}
	fields, err := object(data)
	if err != nil {
		return Claims{}, err
	}
	if err := fieldsInto(fields, map[string]any{
		"iss": &claims.Issuer, "sub": &claims.Subject, "aud": &claims.Tenant, "jti": &claims.ID,
		"iat": &claims.IssuedAt, "exp": &claims.Expires, "via": &claims.Via, "e2ee": &claims.E2EE,
	}, false); err != nil {
		return Claims{}, err
	}
	if raw, ok := fields["cnf"]; ok {
		confirmation, err := object(raw)
		if err != nil {
			return Claims{}, err
		}
		if err := fieldsInto(confirmation, map[string]any{"jkt": &claims.Confirmation.Thumbprint}, false); err != nil {
			return Claims{}, err
		}
	}
	if raw, ok := fields["moqt"]; ok {
		grant, err := object(raw)
		if err != nil {
			return Claims{}, err
		}
		g := &claims.Grant
		if err := fieldsInto(grant, map[string]any{
			"room": &g.Room, "pub": &g.Publish, "cap": &g.Capabilities, "own": &g.Owner,
			"bs": &g.Backstage, "age": &g.AgeVerified, "rly": &g.Relay,
		}, true); err != nil {
			return Claims{}, err
		}
	}
	return claims, nil
}

func object(data []byte) (map[string]json.RawMessage, error) {
	if !bytes.HasPrefix(bytes.TrimLeft(data, " \t\r\n"), []byte("{")) {
		return nil, fmt.Errorf("not a JSON object")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, err
	}
	return fields, nil
}

// uniqueMembers refuses JSON in which any object, at any depth, names a member
// twice. encoding/json keeps the last and other parsers the first, so a token
// with a duplicate would mean different things to different verifiers. Names
// are compared after unescaping, so "sub" and "s\u0075b" are the same.
func uniqueMembers(data []byte) error {
	type level struct {
		names   map[string]bool
		wantKey bool
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	var stack []*level
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if token == json.Delim('}') || token == json.Delim(']') {
			stack = stack[:len(stack)-1]
			continue
		}
		var top *level
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		if top != nil && top.names != nil {
			if top.wantKey {
				name, _ := token.(string)
				if top.names[name] {
					return fmt.Errorf("member %q appears twice", name)
				}
				top.names[name], top.wantKey = true, false
				continue
			}
			top.wantKey = true
		}
		switch token {
		case json.Delim('{'):
			stack = append(stack, &level{names: map[string]bool{}, wantKey: true})
		case json.Delim('['):
			stack = append(stack, &level{})
		}
	}
}

// fieldsInto decodes each known member into its target. A null is refused
// rather than read as absent, and with strict an unknown member is refused.
func fieldsInto(fields map[string]json.RawMessage, targets map[string]any, strict bool) error {
	for name, raw := range fields {
		target, known := targets[name]
		if !known {
			if strict {
				return fmt.Errorf("unknown member %q", name)
			}
			continue
		}
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return fmt.Errorf("member %q is null", name)
		}
		if err := json.Unmarshal(raw, target); err != nil {
			return fmt.Errorf("member %q: %w", name, err)
		}
	}
	return nil
}
