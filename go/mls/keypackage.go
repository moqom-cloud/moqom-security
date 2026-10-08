// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

package mls

import (
	"bytes"
	"fmt"
)

// KeyPackage is what a device publishes so that it can be added: signed by
// its own signature key, and naming its cipher suite, which is the only suite
// of group it can join. Two KEM keys of that suite, as in the RFC: the init
// key is used once, to receive a Welcome, and the encryption key becomes the
// leaf key commit secrets are sealed to.
type KeyPackage struct {
	CipherSuite   CipherSuite
	Identity      []byte
	SignatureKey  []byte
	InitKey       []byte
	EncryptionKey []byte
	Signature     []byte
}

func (k *KeyPackage) toBeSigned() []byte {
	var w writer
	w.uint16(protocolVersion)
	w.uint16(uint16(k.CipherSuite))
	w.vector(k.Identity)
	w.vector(k.SignatureKey)
	w.vector(k.InitKey)
	w.vector(k.EncryptionKey)
	return w.bytes
}

// Encode is the package as it travels.
func (k *KeyPackage) Encode() []byte {
	w := writer{bytes: k.toBeSigned()}
	w.vector(k.Signature)
	return w.bytes
}

// DecodeKeyPackage reads a key package without verifying it. A version or
// suite not implemented is ErrUnsupported.
func DecodeKeyPackage(data []byte) (*KeyPackage, error) {
	r := &reader{data: data}
	suite, err := r.cipherSuite()
	if err != nil {
		return nil, err
	}
	k := &KeyPackage{
		CipherSuite:   suite,
		Identity:      r.vector(),
		SignatureKey:  r.vector(),
		InitKey:       r.vector(),
		EncryptionKey: r.vector(),
		Signature:     r.vector(),
	}
	if err := r.finish(); err != nil {
		return nil, err
	}
	return k, nil
}

// ParseKeyPackage decodes and verifies a key package.
func ParseKeyPackage(data []byte) (*KeyPackage, error) {
	k, err := DecodeKeyPackage(data)
	if err != nil {
		return nil, err
	}
	if err := k.Verify(); err != nil {
		return nil, err
	}
	return k, nil
}

// Verify checks the package's keys are the size and shape its suite says
// (ErrInvalidKeyPackage if not) and that it is signed by the key it carries
// (ErrBadSignature if not).
func (k *KeyPackage) Verify() error {
	s := k.CipherSuite
	switch {
	case len(k.SignatureKey) != s.SignatureKeyLength():
		return fmt.Errorf("%w: signature key length", ErrInvalidKeyPackage)
	case !s.isValidPublicKey(k.InitKey) || !s.isValidPublicKey(k.EncryptionKey):
		return fmt.Errorf("%w: KEM key", ErrInvalidKeyPackage)
	case bytes.Equal(k.InitKey, k.EncryptionKey):
		return fmt.Errorf("%w: init key reused as encryption key", ErrInvalidKeyPackage)
	}
	if !s.VerifyWithLabel(k.SignatureKey, "KeyPackageTBS", k.toBeSigned(), k.Signature) {
		return fmt.Errorf("%w: key package", ErrBadSignature)
	}
	return nil
}

// Reference is KeyPackageRef, RFC 9420 §5.2.
func (k *KeyPackage) Reference() []byte {
	return k.CipherSuite.RefHash("MLS 1.0 KeyPackage Reference", k.Encode())
}

func (k *KeyPackage) leaf() *Leaf {
	return &Leaf{Identity: k.Identity, SignatureKey: k.SignatureKey, EncryptionKey: k.EncryptionKey}
}

// KeyPackageBundle is a key package and the private keys behind it. Fresh per
// session, and never published.
type KeyPackageBundle struct {
	KeyPackage        *KeyPackage
	initPrivate       []byte
	encryptionPrivate []byte
	signaturePrivate  []byte
}

// GenerateKeyPackage makes a key package for identity in suite, which is the
// only suite of group it can be added to.
func GenerateKeyPackage(identity string, suite CipherSuite) (*KeyPackageBundle, error) {
	if !suite.Known() {
		return nil, fmt.Errorf("%w: suite %#04x", ErrUnsupported, uint16(suite))
	}
	signaturePrivate, signatureKey, err := suite.GenerateSignatureKeyPair()
	if err != nil {
		return nil, err
	}
	initPrivate, initKey, err := suite.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	encryptionPrivate, encryptionKey, err := suite.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	k := &KeyPackage{CipherSuite: suite, Identity: []byte(identity), SignatureKey: signatureKey, InitKey: initKey, EncryptionKey: encryptionKey}
	if k.Signature, err = suite.SignWithLabel(signaturePrivate, "KeyPackageTBS", k.toBeSigned()); err != nil {
		return nil, err
	}
	return &KeyPackageBundle{KeyPackage: k, initPrivate: initPrivate, encryptionPrivate: encryptionPrivate, signaturePrivate: signaturePrivate}, nil
}

// NewKeyPackageBundle reassembles a bundle from a key package and its private
// keys, in the forms GenerateKeyPair and GenerateSignatureKeyPair return.
func NewKeyPackageBundle(k *KeyPackage, initPrivate, encryptionPrivate, signaturePrivate []byte) *KeyPackageBundle {
	return &KeyPackageBundle{KeyPackage: k, initPrivate: initPrivate, encryptionPrivate: encryptionPrivate, signaturePrivate: signaturePrivate}
}

// PrivateKeys returns the bundle's private keys, for a caller that persists
// it.
func (b *KeyPackageBundle) PrivateKeys() (initPrivate, encryptionPrivate, signaturePrivate []byte) {
	return b.initPrivate, b.encryptionPrivate, b.signaturePrivate
}
