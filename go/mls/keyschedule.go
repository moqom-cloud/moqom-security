// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

package mls

import "fmt"

// The RFC 9420 §8 key schedule, bit-exact with the RFC and held to the working
// group's key-schedule vectors. What feeds it -- where the commit secret comes
// from, what the tree hash covers -- is MOQOM's simplification; see group.go.

// GroupContext is RFC 9420 §8.1's. The cipher suite is part of it, so every
// signature over a commit or GroupInfo, and every secret derived, is bound to
// the suite the group was founded with.
type GroupContext struct {
	CipherSuite             CipherSuite
	GroupID                 []byte
	Epoch                   uint64
	TreeHash                []byte
	ConfirmedTranscriptHash []byte
}

// Encode is the serialised form. Extensions are always empty: none are
// implemented.
func (c GroupContext) Encode() []byte {
	var w writer
	w.uint16(protocolVersion)
	w.uint16(uint16(c.CipherSuite))
	w.vector(c.GroupID)
	w.uint64(c.Epoch)
	w.vector(c.TreeHash)
	w.vector(c.ConfirmedTranscriptHash)
	w.vector(nil)
	return w.bytes
}

func readGroupContext(r *reader) (GroupContext, error) {
	suite, err := r.cipherSuite()
	if err != nil {
		return GroupContext{}, err
	}
	c := GroupContext{CipherSuite: suite, GroupID: r.vector(), Epoch: r.uint64(), TreeHash: r.vector(), ConfirmedTranscriptHash: r.vector()}
	extensions := r.vector()
	if r.err != nil {
		return GroupContext{}, r.err
	}
	if len(extensions) != 0 {
		return GroupContext{}, fmt.Errorf("%w: GroupContext extensions", ErrUnsupported)
	}
	return c, nil
}

// EpochSecrets is everything one epoch of the key schedule produces.
type EpochSecrets struct {
	CipherSuite        CipherSuite
	JoinerSecret       []byte
	WelcomeSecret      []byte
	EpochSecret        []byte
	SenderDataSecret   []byte
	EncryptionSecret   []byte
	ExporterSecret     []byte
	ExternalSecret     []byte
	ConfirmationKey    []byte
	MembershipKey      []byte
	ResumptionPSK      []byte
	EpochAuthenticator []byte
	// InitSecret is the next epoch's init_secret.
	InitSecret []byte
}

// DeriveEpochSecrets is one epoch, from the previous epoch's init secret and
// this commit's secret. A nil pskSecret is the suite's all-zero secret.
func DeriveEpochSecrets(initSecret, commitSecret, pskSecret []byte, context GroupContext) *EpochSecrets {
	return deriveEpoch(context.CipherSuite, initSecret, commitSecret, pskSecret, context.Encode())
}

// deriveEpoch is the same over a GroupContext already serialised, which is how
// another suite's vectors run through the same hash and KDF.
func deriveEpoch(suite CipherSuite, initSecret, commitSecret, pskSecret, encodedContext []byte) *EpochSecrets {
	joiner := suite.ExpandWithLabel(suite.extract(initSecret, commitSecret), "joiner", encodedContext, suite.HashLength())
	return deriveFromJoiner(suite, joiner, pskSecret, encodedContext)
}

func deriveFromJoiner(suite CipherSuite, joiner, pskSecret, encodedContext []byte) *EpochSecrets {
	member := suite.extract(joiner, psk(suite, pskSecret))
	epoch := suite.ExpandWithLabel(member, "epoch", encodedContext, suite.HashLength())
	derived := func(label string) []byte { return suite.DeriveSecret(epoch, label) }
	return &EpochSecrets{
		CipherSuite:        suite,
		JoinerSecret:       joiner,
		WelcomeSecret:      suite.DeriveSecret(member, "welcome"),
		EpochSecret:        epoch,
		SenderDataSecret:   derived("sender data"),
		EncryptionSecret:   derived("encryption"),
		ExporterSecret:     derived("exporter"),
		ExternalSecret:     derived("external"),
		ConfirmationKey:    derived("confirm"),
		MembershipKey:      derived("membership"),
		ResumptionPSK:      derived("resumption"),
		EpochAuthenticator: derived("authentication"),
		InitSecret:         derived("init"),
	}
}

func psk(suite CipherSuite, secret []byte) []byte {
	if secret == nil {
		return make([]byte, suite.HashLength())
	}
	return secret
}

// welcomeSecret is the welcome secret for a joiner secret, without deriving
// the epoch.
func welcomeSecret(suite CipherSuite, joiner, pskSecret []byte) []byte {
	return suite.DeriveSecret(suite.extract(joiner, psk(suite, pskSecret)), "welcome")
}

// Exporter is MLS-Exporter, RFC 9420 §8.5. A length that is negative or past
// 255 times the suite's hash length is ErrInvalidLength.
func (e *EpochSecrets) Exporter(label string, context []byte, length int) ([]byte, error) {
	s := e.CipherSuite
	if limit := 255 * s.HashLength(); length < 0 || length > limit {
		return nil, fmt.Errorf("%w: %d bytes, at most %d", ErrInvalidLength, length, limit)
	}
	var info writer
	info.uint16(uint16(s.HashLength()))
	info.vector(append([]byte("MLS 1.0 "), label...))
	info.vector(nil)
	secret := s.expand(e.ExporterSecret, info.bytes, s.HashLength())
	return s.ExpandWithLabel(secret, "exported", s.hash(context), length), nil
}

// SFrameExporterLabel is the label RFC 9605 §5.2 exports an epoch's SFrame
// base_key under, with an empty context and the SFrame suite's AEAD.Nk bytes.
const SFrameExporterLabel = "SFrame 1.0 Base Key"
