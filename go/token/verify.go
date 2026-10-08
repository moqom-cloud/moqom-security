// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

package token

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
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

// IsEmpty reports whether the verifier holds no key, and so verifies nothing.
func (v *Verifier) IsEmpty() bool { return len(v.keys) == 0 }

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
// lifetime, completeness, thumbprint, tenant.
func (v *Verifier) Verify(token string, now time.Time) (Claims, error) {
	if len(token) == 0 || len(token) > MaxTokenBytes {
		return Claims{}, fmt.Errorf("%w: token length is out of range", ErrMalformed)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, fmt.Errorf("%w: expected three segments", ErrMalformed)
	}

	headerBytes, err := decodeBase64URL(parts[0])
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

	signature, err := decodeBase64URL(parts[2])
	if err != nil {
		return Claims{}, fmt.Errorf("%w: signature is not base64url", ErrMalformed)
	}
	if !key.Verify([]byte(parts[0]+"."+parts[1]), signature) {
		return Claims{}, ErrBadSignature
	}

	claimsBytes, err := decodeBase64URL(parts[1])
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
	if !ValidThumbprint(claims.Confirmation.Thumbprint) {
		return ErrThumbprint
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

// object decodes one JSON object into its members, after [strict].
func object(data []byte) (map[string]json.RawMessage, error) {
	if err := strict(data); err != nil {
		return nil, err
	}
	if trimmed := bytes.TrimLeft(data, " \t\r\n"); trimmed[0] != '{' {
		return nil, errors.New("not a JSON object")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, err
	}
	return fields, nil
}

// maxNesting is how many arrays and objects may sit inside one another, the
// outermost included: serde_json's limit.
const maxNesting = 127

// strict refuses JSON that two parsers could read differently: invalid UTF-8,
// a `\u` escape of an unpaired surrogate, a number too large for a float64,
// nesting deeper than [maxNesting], or an object anywhere inside that names a
// member twice. encoding/json would replace the first two with U+FFFD and keep
// the last of a duplicate, where other parsers refuse or keep the first.
func strict(data []byte) error {
	if !utf8.Valid(data) {
		return errors.New("not UTF-8")
	}
	if !json.Valid(data) {
		return errors.New("not JSON")
	}
	if !pairedSurrogates(data) {
		return errors.New("an unpaired surrogate escape")
	}
	return uniqueMembers(data)
}

// uniqueMembers refuses JSON in which any object, at any depth, names a member
// twice. Names are compared after unescaping and byte for byte, so "sub" and
// "s\u0075b" are the same and "sub" and "Sub" are not. It also refuses nesting
// deeper than [maxNesting], and (as Token does) a number that overflows a
// float64.
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
		if (token == json.Delim('{') || token == json.Delim('[')) && len(stack) == maxNesting {
			return fmt.Errorf("nested deeper than %d", maxNesting)
		}
		switch token {
		case json.Delim('{'):
			stack = append(stack, &level{names: map[string]bool{}, wantKey: true})
		case json.Delim('['):
			stack = append(stack, &level{})
		}
	}
}

// pairedSurrogates reports whether every `\u` escape in valid JSON data that
// names a surrogate is a high one followed at once by a low one.
func pairedSurrogates(data []byte) bool {
	inString := false
	for i := 0; i < len(data); i++ {
		switch {
		case !inString:
			inString = data[i] == '"'
		case data[i] == '"':
			inString = false
		case data[i] == '\\':
			i++
			if data[i] != 'u' {
				continue
			}
			unit := hexUnit(data[i+1 : i+5])
			i += 4
			switch {
			case unit >= 0xDC00 && unit < 0xE000:
				return false
			case unit >= 0xD800 && unit < 0xDC00:
				if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
					return false
				}
				if low := hexUnit(data[i+3 : i+7]); low < 0xDC00 || low >= 0xE000 {
					return false
				}
				i += 6
			}
		}
	}
	return true
}

func hexUnit(digits []byte) uint64 {
	unit, _ := strconv.ParseUint(string(digits), 16, 16)
	return unit
}

// fieldsInto decodes each known member into its target. A null is refused
// rather than read as absent, and with strict an unknown member is refused.
// So is -0, which serde_json reads as a float and so not as an integer.
func fieldsInto(fields map[string]json.RawMessage, targets map[string]any, strict bool) error {
	for name, raw := range fields {
		target, known := targets[name]
		if !known {
			if strict {
				return fmt.Errorf("unknown member %q", name)
			}
			continue
		}
		switch string(bytes.TrimSpace(raw)) {
		case "null":
			return fmt.Errorf("member %q is null", name)
		case "-0":
			return fmt.Errorf("member %q is -0", name)
		}
		if err := json.Unmarshal(raw, target); err != nil {
			return fmt.Errorf("member %q: %w", name, err)
		}
	}
	return nil
}
