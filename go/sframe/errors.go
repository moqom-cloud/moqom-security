// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

package sframe

import (
	"errors"
	"fmt"
)

// Why an object was refused. Each maps to the error class the shared vectors
// name; see [Class].
var (
	ErrMalformedHeader = errors.New("sframe: header is malformed")
	// ErrUnknownKey is recoverable: key distribution and media race, so a
	// caller may hold the object and retry once the key arrives. Returned as an
	// *UnknownKeyError.
	ErrUnknownKey = errors.New("sframe: no key for KID")
	// ErrAuthentication must not be reported onward in any more detail: which
	// objects fail to authenticate is information an attacker can use.
	ErrAuthentication = errors.New("sframe: authentication failed")
	// ErrReplay is returned as a *ReplayError.
	ErrReplay = errors.New("sframe: counter already seen or too old")
	// ErrCounterExhausted is fatal for the key: the only safe response is to rekey.
	ErrCounterExhausted = errors.New("sframe: counter space exhausted")
	// ErrNoKey: the sender has no key yet, and refuses rather than send in the clear.
	ErrNoKey            = errors.New("sframe: no key to send under")
	ErrInvalidMetadata  = errors.New("sframe: metadata has no canonical encoding")
	ErrUnsupportedSuite = errors.New("sframe: cipher suite not supported")
	// ErrInvalidBaseKey: a base key that is not the suite's KeyLength bytes.
	ErrInvalidBaseKey = errors.New("sframe: base key is not the suite's key length")
)

// UnknownKeyError names the KID no key is held for.
type UnknownKeyError struct{ KeyID uint64 }

func (e *UnknownKeyError) Error() string { return fmt.Sprintf("sframe: no key for KID %d", e.KeyID) }

func (e *UnknownKeyError) Is(target error) bool { return target == ErrUnknownKey }

// ReplayError names the counter refused.
type ReplayError struct{ Counter uint64 }

func (e *ReplayError) Error() string {
	return fmt.Sprintf("sframe: counter %d already seen or too old", e.Counter)
}

func (e *ReplayError) Is(target error) bool { return target == ErrReplay }

var classes = []struct {
	err   error
	class string
}{
	{ErrMalformedHeader, "malformed_header"},
	{ErrUnknownKey, "unknown_key"},
	{ErrAuthentication, "authentication_failure"},
	{ErrReplay, "replay"},
	{ErrCounterExhausted, "counter_exhausted"},
	{ErrNoKey, "no_key"},
	{ErrInvalidMetadata, "invalid_metadata"},
	{ErrUnsupportedSuite, "unsupported_suite"},
	{ErrInvalidBaseKey, "invalid_base_key"},
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
