// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

package mls

import (
	"bytes"
	"crypto/mldsa"
	"crypto/mlkem"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

const vectorDir = "../../vectors/mls"

type vector map[string]any

func (v vector) name() string             { s, _ := v["name"].(string); return s }
func (v vector) str(key string) string    { return v[key].(string) }
func (v vector) has(key string) bool      { _, ok := v[key]; return ok }
func (v vector) int(key string) int       { return int(v[key].(float64)) }
func (v vector) object(key string) vector { return vector(v[key].(map[string]any)) }

func (v vector) objects(key string) []vector {
	list, _ := v[key].([]any)
	out := make([]vector, len(list))
	for i, item := range list {
		out[i] = vector(item.(map[string]any))
	}
	return out
}

func (v vector) hex(t *testing.T, key string) []byte {
	t.Helper()
	out, err := hex.DecodeString(v.str(key))
	if err != nil {
		t.Fatalf("%s: %v", key, err)
	}
	return out
}

// errorClass is the vector failure class an error belongs to.
func errorClass(err error) string {
	classes := []struct {
		err   error
		class string
	}{
		{ErrMalformed, "malformed"}, {ErrUnsupported, "unsupported"}, {ErrInvalidKeyPackage, "invalid-key-package"},
		{ErrBadSignature, "bad-signature"}, {ErrConfirmationMismatch, "confirmation-mismatch"},
		{ErrDecryptionFailed, "decryption-failed"}, {ErrWrongEpoch, "wrong-epoch"}, {ErrWrongGroup, "wrong-group"},
		{ErrInvalidProposal, "invalid-proposal"}, {ErrUnknownSender, "unknown-sender"}, {ErrNotAddressed, "not-addressed"},
		{ErrCipherSuiteMismatch, "cipher-suite-mismatch"}, {ErrRemoved, "removed"}, {ErrCryptoFailure, "crypto-failure"},
	}
	if err == nil {
		return ""
	}
	for _, c := range classes {
		if errors.Is(err, c.err) {
			return c.class
		}
	}
	return err.Error()
}

func expectedError(v vector) string {
	s, _ := v["error"].(string)
	return s
}

func loadCases(t *testing.T, file string) []vector {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(vectorDir, file))
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Cases []vector `json:"cases"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("%s: %v", file, err)
	}
	if len(document.Cases) == 0 {
		t.Fatalf("%s: no cases", file)
	}
	return document.Cases
}

func TestPublishedCryptoBasics(t *testing.T) {
	for _, v := range loadCases(t, "mlswg-crypto-basics.json") {
		t.Run(v.name(), func(t *testing.T) {
			suite := SuiteMLDSA
			if v.int("cipher_suite") == 1 {
				suite = SuiteX25519
			}
			e := v.object("ref_hash")
			if got := suite.RefHash(e.str("label"), e.hex(t, "value")); !bytes.Equal(got, e.hex(t, "out")) {
				t.Error("ref_hash")
			}
			e = v.object("expand_with_label")
			if got := suite.ExpandWithLabel(e.hex(t, "secret"), e.str("label"), e.hex(t, "context"), e.int("length")); !bytes.Equal(got, e.hex(t, "out")) {
				t.Error("expand_with_label")
			}
			e = v.object("derive_secret")
			if got := suite.DeriveSecret(e.hex(t, "secret"), e.str("label")); !bytes.Equal(got, e.hex(t, "out")) {
				t.Error("derive_secret")
			}
			e = v.object("derive_tree_secret")
			generation := binary.BigEndian.AppendUint32(nil, uint32(e.int("generation")))
			if got := suite.ExpandWithLabel(e.hex(t, "secret"), e.str("label"), generation, e.int("length")); !bytes.Equal(got, e.hex(t, "out")) {
				t.Error("derive_tree_secret")
			}
			if suite != SuiteX25519 {
				return
			}
			s := v.object("sign_with_label")
			if !suite.VerifyWithLabel(s.hex(t, "pub"), s.str("label"), s.hex(t, "content"), s.hex(t, "signature")) {
				t.Error("published signature")
			}
			// Ed25519 is deterministic, so our own signature is the published one.
			ours, err := suite.SignWithLabel(s.hex(t, "priv"), s.str("label"), s.hex(t, "content"))
			if err != nil || !bytes.Equal(ours, s.hex(t, "signature")) {
				t.Errorf("sign_with_label: %v", err)
			}
			c := v.object("encrypt_with_label")
			opened, err := suite.DecryptWithLabel(c.hex(t, "priv"), c.str("label"), c.hex(t, "context"),
				HPKECiphertext{KEMOutput: c.hex(t, "kem_output"), Ciphertext: c.hex(t, "ciphertext")})
			if err != nil || !bytes.Equal(opened, c.hex(t, "plaintext")) {
				t.Errorf("encrypt_with_label: %v", err)
			}
			sealed, err := suite.EncryptWithLabel(c.hex(t, "pub"), c.str("label"), c.hex(t, "context"), []byte("x"))
			if err != nil {
				t.Fatal(err)
			}
			if back, err := suite.DecryptWithLabel(c.hex(t, "priv"), c.str("label"), c.hex(t, "context"), sealed); err != nil || string(back) != "x" {
				t.Errorf("round trip: %v", err)
			}
		})
	}
}

func TestPublishedKeySchedule(t *testing.T) {
	for _, v := range loadCases(t, "mlswg-key-schedule.json") {
		t.Run(v.name(), func(t *testing.T) {
			suite := SuiteMLDSA
			if v.int("cipher_suite") == 1 {
				suite = SuiteX25519
			}
			initSecret := v.hex(t, "initial_init_secret")
			for index, e := range v.objects("epochs") {
				if suite == SuiteX25519 {
					context := GroupContext{CipherSuite: suite, GroupID: v.hex(t, "group_id"), Epoch: uint64(index),
						TreeHash: e.hex(t, "tree_hash"), ConfirmedTranscriptHash: e.hex(t, "confirmed_transcript_hash")}
					if !bytes.Equal(context.Encode(), e.hex(t, "group_context")) {
						t.Errorf("epoch %d: group context", index)
					}
				}
				s := deriveEpoch(suite, initSecret, e.hex(t, "commit_secret"), e.hex(t, "psk_secret"), e.hex(t, "group_context"))
				checkSecrets(t, index, s, e, "")
				if !bytes.Equal(welcomeSecret(suite, s.JoinerSecret, e.hex(t, "psk_secret")), e.hex(t, "welcome_secret")) {
					t.Errorf("epoch %d: welcome secret alone", index)
				}
				x := e.object("exporter")
				if got := s.Exporter(x.str("label"), x.hex(t, "context"), x.int("length")); !bytes.Equal(got, x.hex(t, "secret")) {
					t.Errorf("epoch %d: exporter", index)
				}
				initSecret = s.InitSecret
			}
		})
	}
}

func checkSecrets(t *testing.T, index int, s *EpochSecrets, e vector, suffix string) {
	t.Helper()
	for key, value := range map[string][]byte{
		"joiner_secret": s.JoinerSecret, "welcome_secret": s.WelcomeSecret, "sender_data_secret": s.SenderDataSecret,
		"encryption_secret": s.EncryptionSecret, "exporter_secret": s.ExporterSecret, "external_secret": s.ExternalSecret,
		"confirmation_key": s.ConfirmationKey, "membership_key": s.MembershipKey, "resumption_psk": s.ResumptionPSK,
		"epoch_authenticator": s.EpochAuthenticator, "init_secret": s.InitSecret,
	} {
		if !bytes.Equal(value, e.hex(t, key+suffix)) {
			t.Errorf("epoch %d: %s", index, key)
		}
	}
	if suffix != "" && !bytes.Equal(s.EpochSecret, e.hex(t, "epoch_secret"+suffix)) {
		t.Errorf("epoch %d: epoch_secret", index)
	}
}

func TestPublishedDeserialization(t *testing.T) {
	for _, v := range loadCases(t, "mlswg-deserialization.json") {
		var w writer
		w.length(v.int("length"))
		if !bytes.Equal(w.bytes, v.hex(t, "vlbytes_header")) {
			t.Errorf("%s: encode", v.name())
		}
		r := &reader{data: v.hex(t, "vlbytes_header")}
		if got := r.length(); got != v.int("length") || r.finish() != nil {
			t.Errorf("%s: decode %d", v.name(), got)
		}
	}
	r := &reader{data: []byte{0x40, 0x05, 1, 2, 3, 4, 5}}
	if r.vector(); !errors.Is(r.err, ErrMalformed) {
		t.Error("a two-byte encoding of five was accepted")
	}
}

func cryptoCases(t *testing.T) []vector {
	return slices.Concat(loadCases(t, "mls-crypto.json"), loadCases(t, "mls-crypto-go.json"), loadCases(t, "mls-crypto-rust.json"))
}

func TestCryptoVectors(t *testing.T) {
	suite := SuiteMLDSA
	for _, v := range cryptoCases(t) {
		t.Run(v.name(), func(t *testing.T) {
			want := expectedError(v)
			switch v.str("op") {
			case "expand_with_label":
				if got := suite.ExpandWithLabel(v.hex(t, "secret_hex"), v.str("label"), v.hex(t, "context_hex"), v.int("length")); !bytes.Equal(got, v.hex(t, "out_hex")) {
					t.Error("mismatch")
				}
			case "derive_secret":
				if got := suite.DeriveSecret(v.hex(t, "secret_hex"), v.str("label")); !bytes.Equal(got, v.hex(t, "out_hex")) {
					t.Error("mismatch")
				}
			case "ref_hash":
				if got := suite.RefHash(v.str("label"), v.hex(t, "value_hex")); !bytes.Equal(got, v.hex(t, "out_hex")) {
					t.Error("mismatch")
				}
			case "sign_with_label":
				key, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), v.hex(t, "seed_hex"))
				if err != nil || !bytes.Equal(key.PublicKey().Bytes(), v.hex(t, "public_key_hex")) {
					t.Fatalf("public key from seed: %v", err)
				}
				ok := suite.VerifyWithLabel(v.hex(t, "public_key_hex"), v.str("label"), v.hex(t, "content_hex"), v.hex(t, "signature_hex"))
				if ok != (want == "") {
					t.Errorf("verified %v, want error %q", ok, want)
				}
				if want == "" {
					ours, err := suite.SignWithLabel(v.hex(t, "seed_hex"), v.str("label"), v.hex(t, "content_hex"))
					if err != nil || !suite.VerifyWithLabel(v.hex(t, "public_key_hex"), v.str("label"), v.hex(t, "content_hex"), ours) {
						t.Errorf("own signature: %v", err)
					}
				}
			case "encrypt_with_label":
				key, err := mlkem.NewDecapsulationKey768(v.hex(t, "seed_hex"))
				if err != nil || !bytes.Equal(key.EncapsulationKey().Bytes(), v.hex(t, "public_key_hex")) {
					t.Fatalf("public key from seed: %v", err)
				}
				opened, err := suite.DecryptWithLabel(v.hex(t, "seed_hex"), v.str("label"), v.hex(t, "context_hex"),
					HPKECiphertext{KEMOutput: v.hex(t, "kem_output_hex"), Ciphertext: v.hex(t, "ciphertext_hex")})
				if got := errorClass(err); got != want {
					t.Fatalf("error %q, want %q", got, want)
				}
				if want == "" && !bytes.Equal(opened, v.hex(t, "plaintext_hex")) {
					t.Error("plaintext")
				}
			default:
				t.Fatalf("unknown op %q", v.str("op"))
			}
		})
	}
}

func TestKeyScheduleVectors(t *testing.T) {
	for _, v := range loadCases(t, "mls-key-schedule.json") {
		initSecret := v.hex(t, "initial_init_secret_hex")
		for index, e := range v.objects("epochs") {
			context := GroupContext{CipherSuite: CipherSuite(v.int("cipher_suite")), GroupID: v.hex(t, "group_id_hex"), Epoch: uint64(index),
				TreeHash: e.hex(t, "tree_hash_hex"), ConfirmedTranscriptHash: e.hex(t, "confirmed_transcript_hash_hex")}
			if !bytes.Equal(context.Encode(), e.hex(t, "group_context_hex")) {
				t.Errorf("epoch %d: group context", index)
			}
			s := DeriveEpochSecrets(initSecret, e.hex(t, "commit_secret_hex"), nil, context)
			checkSecrets(t, index, s, e, "_hex")
			for _, x := range e.objects("exporters") {
				if got := s.Exporter(x.str("label"), x.hex(t, "context_hex"), x.int("length")); !bytes.Equal(got, x.hex(t, "out_hex")) {
					t.Errorf("epoch %d: exporter %q/%d", index, x.str("label"), x.int("length"))
				}
			}
			initSecret = s.InitSecret
		}
	}
}

func TestKeyPackageVectors(t *testing.T) {
	for _, v := range loadCases(t, "mls-key-packages.json") {
		t.Run(v.name(), func(t *testing.T) {
			k, err := ParseKeyPackage(v.hex(t, "key_package_hex"))
			if got, want := errorClass(err), expectedError(v); got != want {
				t.Fatalf("error %q, want %q", got, want)
			}
			if err != nil {
				return
			}
			e := v.object("expect")
			if int(k.CipherSuite) != e.int("cipher_suite") || string(k.Identity) != e.str("identity") ||
				!bytes.Equal(k.SignatureKey, e.hex(t, "signature_key_hex")) || !bytes.Equal(k.InitKey, e.hex(t, "init_key_hex")) ||
				!bytes.Equal(k.EncryptionKey, e.hex(t, "encryption_key_hex")) || !bytes.Equal(k.Reference(), e.hex(t, "reference_hex")) ||
				!bytes.Equal(k.Encode(), v.hex(t, "key_package_hex")) {
				t.Errorf("parsed %+v", k)
			}
		})
	}
}

func groupCases(t *testing.T) []vector {
	return append(loadCases(t, "mls-group.json"), loadCases(t, "mls-group-go.json")...)
}

func TestGroupVectors(t *testing.T) {
	for _, v := range groupCases(t) {
		t.Run(v.name(), func(t *testing.T) {
			m := v.object("member")
			k, err := DecodeKeyPackage(m.hex(t, "key_package_hex"))
			if err != nil {
				t.Fatal(err)
			}
			bundle := NewKeyPackageBundle(k, m.hex(t, "init_private_hex"), m.hex(t, "encryption_private_hex"), m.hex(t, "signature_private_hex"))
			var group *Group
			for index, step := range v.objects("steps") {
				removed := false
				if step.has("welcome_hex") {
					var welcome *Welcome
					if welcome, err = DecodeWelcome(step.hex(t, "welcome_hex")); err == nil {
						var joined *Group
						if joined, err = Join(welcome, bundle); err == nil {
							group = joined
						}
					}
				} else {
					var message *CommitMessage
					if message, err = DecodeCommitMessage(step.hex(t, "commit_hex")); err == nil {
						var next *Group
						if next, removed, err = group.Process(message); err == nil && !removed {
							group = next
						}
					}
				}
				if got, want := errorClass(err), expectedError(step); got != want {
					t.Fatalf("step %d: error %q, want %q", index, got, want)
				}
				if removed != step.has("removed") {
					t.Fatalf("step %d: removed %v", index, removed)
				}
				if step.has("expect") {
					checkState(t, index, group, step.object("expect"))
				}
			}
		})
	}
}

func checkState(t *testing.T, index int, group *Group, e vector) {
	t.Helper()
	if int(group.Epoch()) != e.int("epoch") || int(group.OwnLeaf()) != e.int("own_leaf") {
		t.Errorf("step %d: epoch %d leaf %d", index, group.Epoch(), group.OwnLeaf())
	}
	want, _ := e["members"].([]any)
	members := group.Members()
	if len(members) != len(want) {
		t.Errorf("step %d: %d members, want %d", index, len(members), len(want))
	}
	for i := range min(len(members), len(want)) {
		identity, _ := want[i].(string)
		if (members[i] == nil) != (want[i] == nil) || (members[i] != nil && string(members[i].Identity) != identity) {
			t.Errorf("step %d: leaf %d", index, i)
		}
	}
	if !bytes.Equal(group.EpochAuthenticator(), e.hex(t, "epoch_authenticator_hex")) {
		t.Errorf("step %d: epoch authenticator", index)
	}
	for _, x := range e.objects("exporters") {
		if got := group.Exporter(x.str("label"), x.hex(t, "context_hex"), x.int("length")); !bytes.Equal(got, x.hex(t, "out_hex")) {
			t.Errorf("step %d: exporter %q", index, x.str("label"))
		}
	}
}

func TestAudienceVectors(t *testing.T) {
	for _, v := range loadCases(t, "mls-audience.json") {
		t.Run(v.name(), func(t *testing.T) {
			key, err := mlkem.NewDecapsulationKey768(v.hex(t, "private_key_hex"))
			if err != nil || !bytes.Equal(key.EncapsulationKey().Bytes(), v.hex(t, "public_key_hex")) {
				t.Fatalf("public key from seed: %v", err)
			}
			base, err := OpenAudience(v.hex(t, "envelope_hex"), v.hex(t, "private_key_hex"), v.hex(t, "group_id_hex"), uint64(v.int("epoch")))
			if got, want := errorClass(err), expectedError(v); got != want {
				t.Fatalf("error %q, want %q", got, want)
			}
			if err == nil && !bytes.Equal(base, v.hex(t, "base_key_hex")) {
				t.Error("base key")
			}
		})
	}
}
