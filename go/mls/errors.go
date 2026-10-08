// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

package mls

import "errors"

// The failure classes, shared with the Swift and Rust implementations and
// named in the vectors. Errors returned by this package wrap one of them; test
// with errors.Is.
var (
	// ErrMalformed is bytes that do not parse.
	ErrMalformed = errors.New("mls: malformed")
	// ErrUnsupported is a version or cipher suite that is not implemented.
	ErrUnsupported = errors.New("mls: unsupported")
	// ErrInvalidKeyPackage is a key package whose keys are the wrong size or
	// shape for its suite.
	ErrInvalidKeyPackage = errors.New("mls: invalid key package")
	// ErrBadSignature is a signature that does not verify.
	ErrBadSignature = errors.New("mls: bad signature")
	// ErrConfirmationMismatch is a confirmation tag or member list that does
	// not match what the epoch derives.
	ErrConfirmationMismatch = errors.New("mls: confirmation mismatch")
	// ErrDecryptionFailed is HPKE or AEAD refusing to open something.
	ErrDecryptionFailed = errors.New("mls: decryption failed")
	// ErrWrongEpoch is a commit for an epoch other than the one held.
	ErrWrongEpoch = errors.New("mls: wrong epoch")
	// ErrWrongGroup is a commit for another group.
	ErrWrongGroup = errors.New("mls: wrong group")
	// ErrInvalidProposal is a proposal naming a member that is not there,
	// adding one twice, or a committer removing itself.
	ErrInvalidProposal = errors.New("mls: invalid proposal")
	// ErrUnknownSender is a commit or GroupInfo from a leaf that is not a
	// member.
	ErrUnknownSender = errors.New("mls: unknown sender")
	// ErrNotAddressed is a Welcome or commit with nothing for this member.
	ErrNotAddressed = errors.New("mls: not addressed")
	// ErrCipherSuiteMismatch is a key package or Welcome in a suite other
	// than the group's.
	ErrCipherSuiteMismatch = errors.New("mls: cipher suite mismatch")
	// ErrRemoved is committing from a group this member has left.
	ErrRemoved = errors.New("mls: removed")
	// ErrCryptoFailure is a primitive failing where it should not be able to.
	ErrCryptoFailure = errors.New("mls: crypto failure")
)
