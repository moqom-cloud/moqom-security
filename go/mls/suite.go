// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

package mls

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/hpke"
	"crypto/mldsa"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
)

const protocolVersion = 0x0001 // mls10

// CipherSuite is an MLS cipher suite identifier, RFC 9420 §17.1.
type CipherSuite uint16

const (
	// SuiteX25519 is MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519, RFC 9420's
	// mandatory suite, kept for groups founded in it.
	SuiteX25519 CipherSuite = 0x0001
	// SuiteXWing is MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519,
	// draft-ietf-mls-pq-ciphersuites' first suite (HPKE KEM 0x647a, X-Wing),
	// kept for groups founded in it. The draft's value is still TBD, so this
	// is from RFC 9420's private-use range and must change with every other
	// implementation's when IANA assigns one.
	SuiteXWing CipherSuite = 0xF0A1
	// SuiteMLDSA is MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65, the draft's
	// TBD10: HPKE KEM 0x0041 (pure ML-KEM-768), HKDF-SHA384, AES-256-GCM and
	// ML-DSA-65 signatures (pure, empty context). Private-use, like
	// SuiteXWing, until IANA assigns the draft's value.
	SuiteMLDSA CipherSuite = 0xF0AA
)

// FoundingSuite is the suite every new group is founded in.
const FoundingSuite = SuiteMLDSA

const aeadNonceLength = 12

// Known reports whether the suite is one this package implements.
func (s CipherSuite) Known() bool {
	return s == SuiteX25519 || s == SuiteXWing || s == SuiteMLDSA
}

// Name is the suite's registered name.
func (s CipherSuite) Name() string {
	switch s {
	case SuiteX25519:
		return "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"
	case SuiteXWing:
		return "MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519"
	case SuiteMLDSA:
		return "MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65"
	}
	return fmt.Sprintf("unknown suite %#04x", uint16(s))
}

func (s CipherSuite) String() string { return fmt.Sprintf("%s (%#04x)", s.Name(), uint16(s)) }

func (s CipherSuite) sha384() bool { return s == SuiteMLDSA }

func (s CipherSuite) newHash() hash.Hash {
	if s.sha384() {
		return sha512.New384()
	}
	return sha256.New()
}

// HashLength is KDF.Nh: 48 for SHA-384, 32 for SHA-256.
func (s CipherSuite) HashLength() int {
	if s.sha384() {
		return 48
	}
	return 32
}

func (s CipherSuite) aeadKeyLength() int {
	if s.sha384() {
		return 32
	}
	return 16
}

// PublicKeyLength is an init or leaf encryption key's length, HPKE's Npk.
func (s CipherSuite) PublicKeyLength() int {
	switch s {
	case SuiteX25519:
		return 32
	case SuiteXWing:
		return mlkem.EncapsulationKeySize768 + 32
	}
	return mlkem.EncapsulationKeySize768
}

// EncapsulationLength is HPKE's Nenc.
func (s CipherSuite) EncapsulationLength() int {
	switch s {
	case SuiteX25519:
		return 32
	case SuiteXWing:
		return mlkem.CiphertextSize768 + 32
	}
	return mlkem.CiphertextSize768
}

// SignatureKeyLength is a signature public key's length: 1,952 for ML-DSA-65,
// 32 for Ed25519.
func (s CipherSuite) SignatureKeyLength() int {
	if s == SuiteMLDSA {
		return 1952
	}
	return ed25519.PublicKeySize
}

func (s CipherSuite) hash(data []byte) []byte {
	h := s.newHash()
	h.Write(data)
	return h.Sum(nil)
}

func (s CipherSuite) extract(salt, ikm []byte) []byte {
	prk, err := hkdf.Extract(s.newHash, ikm, salt)
	if err != nil {
		panic(err)
	}
	return prk
}

func (s CipherSuite) expand(secret, info []byte, length int) []byte {
	out, err := hkdf.Expand(s.newHash, secret, string(info), length)
	if err != nil {
		panic(err)
	}
	return out
}

// ExpandWithLabel is RFC 9420 §5.1.3's.
func (s CipherSuite) ExpandWithLabel(secret []byte, label string, context []byte, length int) []byte {
	var info writer
	info.uint16(uint16(length))
	info.vector([]byte("MLS 1.0 " + label))
	info.vector(context)
	return s.expand(secret, info.bytes, length)
}

// DeriveSecret is RFC 9420 §5.1.3's.
func (s CipherSuite) DeriveSecret(secret []byte, label string) []byte {
	return s.ExpandWithLabel(secret, label, nil, s.HashLength())
}

// RefHash is RFC 9420 §5.2's.
func (s CipherSuite) RefHash(label string, value []byte) []byte {
	var input writer
	input.vector([]byte(label))
	input.vector(value)
	return s.hash(input.bytes)
}

func (s CipherSuite) mac(key, data []byte) []byte {
	m := hmac.New(s.newHash, key)
	m.Write(data)
	return m.Sum(nil)
}

func (s CipherSuite) randomSecret() []byte { return randomBytes(s.HashLength()) }

func randomBytes(n int) []byte {
	out := make([]byte, n)
	_, _ = rand.Read(out)
	return out
}

// Signatures

// GenerateSignatureKeyPair returns a fresh signature key: the private half as
// a 32-byte ML-DSA-65 seed (FIPS 204's xi) or Ed25519 seed, and the public
// half as it travels.
func (s CipherSuite) GenerateSignatureKeyPair() (private, public []byte, err error) {
	if s == SuiteMLDSA {
		key, err := mldsa.GenerateKey(mldsa.MLDSA65())
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %v", ErrCryptoFailure, err)
		}
		return key.Bytes(), key.PublicKey().Bytes(), nil
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrCryptoFailure, err)
	}
	return key.Seed(), public, nil
}

func signContent(label string, content []byte) []byte {
	var tbs writer
	tbs.vector([]byte("MLS 1.0 " + label))
	tbs.vector(content)
	return tbs.bytes
}

// SignWithLabel is RFC 9420 §5.1.2's, with a private key as
// GenerateSignatureKeyPair returns it.
func (s CipherSuite) SignWithLabel(private []byte, label string, content []byte) ([]byte, error) {
	message := signContent(label, content)
	if s == SuiteMLDSA {
		key, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), private)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrCryptoFailure, err)
		}
		signature, err := key.Sign(rand.Reader, message, &mldsa.Options{})
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrCryptoFailure, err)
		}
		return signature, nil
	}
	if len(private) != ed25519.SeedSize {
		return nil, fmt.Errorf("%w: Ed25519 seed length", ErrCryptoFailure)
	}
	return ed25519.Sign(ed25519.NewKeyFromSeed(private), message), nil
}

// VerifyWithLabel is RFC 9420 §5.1.2's.
func (s CipherSuite) VerifyWithLabel(public []byte, label string, content, signature []byte) bool {
	if len(public) != s.SignatureKeyLength() {
		return false
	}
	message := signContent(label, content)
	if s == SuiteMLDSA {
		key, err := mldsa.NewPublicKey(mldsa.MLDSA65(), public)
		if err != nil {
			return false
		}
		return mldsa.Verify(key, message, signature, nil) == nil
	}
	return ed25519.Verify(public, message, signature)
}

// The KEM

func (s CipherSuite) kem() hpke.KEM {
	switch s {
	case SuiteX25519:
		return hpke.DHKEM(ecdh.X25519())
	case SuiteXWing:
		return hpke.MLKEM768X25519()
	}
	return hpke.MLKEM768()
}

func (s CipherSuite) kdf() hpke.KDF {
	if s.sha384() {
		return hpke.HKDFSHA384()
	}
	return hpke.HKDFSHA256()
}

func (s CipherSuite) aead() hpke.AEAD {
	if s.sha384() {
		return hpke.AES256GCM()
	}
	return hpke.AES128GCM()
}

// GenerateKeyPair returns a fresh KEM key pair: the private half as RFC 9180's
// SerializePrivateKey gives it (the X25519 scalar, X-Wing's 32-byte seed, or
// ML-KEM-768's 64-byte seed d || z) and the public half as it travels.
func (s CipherSuite) GenerateKeyPair() (private, public []byte, err error) {
	key, err := s.kem().GenerateKey()
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrCryptoFailure, err)
	}
	private, err = key.Bytes()
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrCryptoFailure, err)
	}
	return private, key.PublicKey().Bytes(), nil
}

// isValidPublicKey reports whether a key is the suite's KEM's: the right
// length and, for ML-KEM-768 alone or as X-Wing's first half, passing FIPS
// 203's encapsulation key check.
func (s CipherSuite) isValidPublicKey(public []byte) bool {
	if len(public) != s.PublicKeyLength() {
		return false
	}
	if s == SuiteX25519 {
		return true
	}
	_, err := mlkem.NewEncapsulationKey768(public[:mlkem.EncapsulationKeySize768])
	return err == nil
}

// HPKECiphertext is RFC 9420 §5.1.3's.
type HPKECiphertext struct {
	KEMOutput  []byte
	Ciphertext []byte
}

func (c HPKECiphertext) write(w *writer) {
	w.vector(c.KEMOutput)
	w.vector(c.Ciphertext)
}

func readHPKECiphertext(r *reader) HPKECiphertext {
	return HPKECiphertext{KEMOutput: r.vector(), Ciphertext: r.vector()}
}

func encryptContext(label string, context []byte) []byte {
	var info writer
	info.vector([]byte("MLS 1.0 " + label))
	info.vector(context)
	return info.bytes
}

// EncryptWithLabel is RFC 9420 §5.1.3's: HPKE base mode, empty AAD.
func (s CipherSuite) EncryptWithLabel(public []byte, label string, context, plaintext []byte) (HPKECiphertext, error) {
	if len(public) != s.PublicKeyLength() {
		return HPKECiphertext{}, fmt.Errorf("%w: public key length", ErrMalformed)
	}
	key, err := s.kem().NewPublicKey(public)
	if err != nil {
		return HPKECiphertext{}, fmt.Errorf("%w: %v", ErrCryptoFailure, err)
	}
	enc, sender, err := hpke.NewSender(key, s.kdf(), s.aead(), encryptContext(label, context))
	if err != nil {
		return HPKECiphertext{}, fmt.Errorf("%w: %v", ErrCryptoFailure, err)
	}
	ciphertext, err := sender.Seal(nil, plaintext)
	if err != nil {
		return HPKECiphertext{}, fmt.Errorf("%w: %v", ErrCryptoFailure, err)
	}
	return HPKECiphertext{KEMOutput: enc, Ciphertext: ciphertext}, nil
}

// DecryptWithLabel is RFC 9420 §5.1.3's, with a private key as
// GenerateKeyPair returns it.
func (s CipherSuite) DecryptWithLabel(private []byte, label string, context []byte, ciphertext HPKECiphertext) ([]byte, error) {
	if len(ciphertext.KEMOutput) != s.EncapsulationLength() {
		return nil, fmt.Errorf("%w: encapsulation length", ErrDecryptionFailed)
	}
	key, err := s.kem().NewPrivateKey(private)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}
	recipient, err := hpke.NewRecipient(ciphertext.KEMOutput, key, s.kdf(), s.aead(), encryptContext(label, context))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}
	plaintext, err := recipient.Open(nil, ciphertext.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}
	return plaintext, nil
}

// AES-GCM takes its size from the key, so these serve both AEADs.

func aeadSeal(key, nonce, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCryptoFailure, err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCryptoFailure, err)
	}
	return gcm.Seal(nil, nonce, plaintext, nil), nil
}

func aeadOpen(key, nonce, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}
	return plaintext, nil
}
