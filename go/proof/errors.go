// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

package proof

import "errors"

// Why a proof was refused. Each maps to the error class the shared vectors
// name; see [Class].
var (
	ErrMalformed        = errors.New("proof is malformed")
	ErrUnsupported      = errors.New("proof algorithm, type or key is not supported")
	ErrBadSignature     = errors.New("proof signature does not verify")
	ErrWrongKey         = errors.New("proof is signed by a key the token was not issued to")
	ErrWrongToken       = errors.New("proof was made for a different token")
	ErrWrongCertificate = errors.New("proof was made for another peer certificate")
	ErrExpired          = errors.New("proof was issued too long ago")
	ErrNotYetValid      = errors.New("proof is issued in the future")
	ErrReplayed         = errors.New("proof nonce has already been spent")
	ErrOverloaded       = errors.New("nonce store is full")
)

var classes = []struct {
	err   error
	class string
}{
	{ErrMalformed, "malformed"},
	{ErrUnsupported, "unsupported"},
	{ErrBadSignature, "bad_signature"},
	{ErrWrongKey, "wrong_key"},
	{ErrWrongToken, "wrong_token"},
	{ErrWrongCertificate, "wrong_certificate"},
	{ErrExpired, "expired"},
	{ErrNotYetValid, "not_yet_valid"},
	{ErrReplayed, "replayed"},
	{ErrOverloaded, "overloaded"},
}

// Class is the vector error class of err, or "" for nil or an error this
// package did not return.
func Class(err error) string {
	for _, c := range classes {
		if errors.Is(err, c.err) {
			return c.class
		}
	}
	return ""
}
