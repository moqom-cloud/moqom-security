// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

package mls

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

func TestGroupRoundTrip(t *testing.T) {
	for _, suite := range []CipherSuite{SuiteMLDSA, SuiteXWing, SuiteX25519} {
		t.Run(suite.Name(), func(t *testing.T) {
			bundle := must[*KeyPackageBundle](t)
			group := must[*Group](t)
			commit := must[*PendingCommit](t)

			alice := group(CreateGroup([]byte("g"), bundle(GenerateKeyPackage("alice", suite))))
			bob := bundle(GenerateKeyPackage("bob", suite))
			carol := bundle(GenerateKeyPackage("carol", suite))

			add := commit(alice.Commit([]*KeyPackage{bob.KeyPackage, carol.KeyPackage}, nil))
			wire, err := DecodeWelcome(add.Welcome.Encode())
			if err != nil {
				t.Fatal(err)
			}
			bobGroup := group(Join(wire, bob))
			carolGroup := group(Join(wire, carol))
			alice = add.Next
			for _, g := range []*Group{bobGroup, carolGroup} {
				if !bytes.Equal(g.EpochAuthenticator(), alice.EpochAuthenticator()) ||
					!bytes.Equal(must[[]byte](t)(g.Exporter(SFrameExporterLabel, nil, 16)), must[[]byte](t)(alice.Exporter(SFrameExporterLabel, nil, 16))) {
					t.Fatal("joiners disagree with the founder")
				}
			}

			remove := commit(bobGroup.Commit(nil, []uint32{0}))
			message, err := DecodeCommitMessage(remove.Message.Encode())
			if err != nil {
				t.Fatal(err)
			}
			if _, removed, err := alice.Process(message); err != nil || !removed {
				t.Fatalf("alice was not removed: %v", err)
			}
			carolGroup = advance(t, carolGroup, message)
			if !bytes.Equal(carolGroup.EpochAuthenticator(), remove.Next.EpochAuthenticator()) || len(carolGroup.Members()) != 3 {
				t.Fatal("carol disagrees after the remove")
			}
			if _, _, err := carolGroup.Process(message); !errors.Is(err, ErrWrongEpoch) {
				t.Fatalf("replay: %v", err)
			}
		})
	}
}

func TestAudienceRoundTrip(t *testing.T) {
	private, public, err := GenerateAudienceKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	base := bytes.Repeat([]byte{7}, 32)
	envelope, err := SealAudience(base, public, []byte("g"), 3)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := OpenAudience(envelope, private, []byte("g"), 3); err != nil || !bytes.Equal(got, base) {
		t.Fatalf("open: %v", err)
	}
	if _, err := OpenAudience(envelope, private, []byte("g"), 4); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("other epoch: %v", err)
	}
	if _, err := SealAudience(base, public[:32], []byte("g"), 3); err == nil {
		t.Fatal("sealed to an X25519-sized key")
	}
}

func TestExporterLength(t *testing.T) {
	for _, suite := range []CipherSuite{SuiteMLDSA, SuiteXWing, SuiteX25519} {
		t.Run(suite.Name(), func(t *testing.T) {
			g := must[*Group](t)(CreateGroup([]byte("g"), must[*KeyPackageBundle](t)(GenerateKeyPackage("alice", suite))))
			limit := 255 * suite.HashLength()
			if out, err := g.Exporter("x", nil, limit); err != nil || len(out) != limit {
				t.Fatalf("at the limit: %d bytes, %v", len(out), err)
			}
			for _, length := range []int{limit + 1, 1 << 16, -1} {
				out, err := g.Exporter("x", nil, length)
				if !errors.Is(err, ErrInvalidLength) || Class(err) != "invalid-length" || out != nil {
					t.Errorf("length %d: %v", length, err)
				}
			}
		})
	}
}

func TestExpandWithLabelLength(t *testing.T) {
	for _, suite := range []CipherSuite{SuiteMLDSA, SuiteXWing, SuiteX25519} {
		t.Run(suite.Name(), func(t *testing.T) {
			secret := bytes.Repeat([]byte{1}, suite.HashLength())
			limit := 255 * suite.HashLength()
			for _, length := range []int{0, limit} {
				if out, err := suite.ExpandWithLabel(secret, "x", nil, length); err != nil || len(out) != length {
					t.Fatalf("length %d: %d bytes, %v", length, len(out), err)
				}
			}
			for _, length := range []int{limit + 1, 1 << 16, -1} {
				out, err := suite.ExpandWithLabel(secret, "x", nil, length)
				if !errors.Is(err, ErrInvalidLength) || Class(err) != "invalid-length" || out != nil {
					t.Errorf("length %d: %v", length, err)
				}
			}
		})
	}
}

func TestClass(t *testing.T) {
	for _, c := range classes {
		if got := Class(fmt.Errorf("%w: detail", c.err)); got != c.class {
			t.Errorf("%v: %q, want %q", c.err, got, c.class)
		}
	}
	if Class(nil) != "" || Class(errors.New("other")) != "" {
		t.Error("an error outside every class has one")
	}
}
