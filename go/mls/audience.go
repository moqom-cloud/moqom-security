// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

package mls

// Sender keys: how a viewer in a large broadcast decrypts without being in the
// group. Each viewer makes an ML-KEM-1024 key pair and hands the public half to
// the group's committer, which seals each epoch's SFrame base key to it. From
// the base key and the key ID in a frame the viewer derives any publisher's
// key exactly as a member does (RFC 9605 §5.2).

// AudienceSuite is the suite envelopes are sealed in, the group's: viewers'
// keys are ML-KEM-1024, like members' are.
const AudienceSuite = SuiteMLDSA

const audienceLabel = "MOQOM audience key"

// AudienceKeyLength is a viewer's public key length.
const AudienceKeyLength = 1568

func audienceContext(groupID []byte, epoch uint64) []byte {
	var w writer
	w.vector(groupID)
	w.uint64(epoch)
	return w.bytes
}

// GenerateAudienceKeyPair is a viewer's key pair: the private half as a
// 64-byte ML-KEM-1024 seed, and the public half it hands out.
func GenerateAudienceKeyPair() (private, public []byte, err error) {
	return AudienceSuite.GenerateKeyPair()
}

// SealAudience seals an epoch's base key to a viewer:
// EncryptWithLabel(pk, "MOQOM audience key", vector(group_id) || uint64(epoch), base_key),
// encoded as an HPKECiphertext.
func SealAudience(baseKey, publicKey, groupID []byte, epoch uint64) ([]byte, error) {
	sealed, err := AudienceSuite.EncryptWithLabel(publicKey, audienceLabel, audienceContext(groupID, epoch), baseKey)
	if err != nil {
		return nil, err
	}
	var w writer
	sealed.write(&w)
	return w.bytes, nil
}

// OpenAudience opens an envelope sealed for groupID at epoch. Any other group
// or epoch is ErrDecryptionFailed.
func OpenAudience(envelope, privateKey, groupID []byte, epoch uint64) ([]byte, error) {
	r := &reader{data: envelope}
	sealed := readHPKECiphertext(r)
	if err := r.finish(); err != nil {
		return nil, err
	}
	return AudienceSuite.DecryptWithLabel(privateKey, audienceLabel, audienceContext(groupID, epoch), sealed)
}
