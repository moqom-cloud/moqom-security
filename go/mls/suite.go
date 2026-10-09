// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

package mls

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/hpke"
	"crypto/mldsa"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"hash"
)

const protocolVersion = 0x0001 // mls10

// CipherSuite is an MLS cipher suite identifier, RFC 9420 §17.1.
type CipherSuite uint16

// SuiteMLDSA is MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87,
// draft-ietf-mls-pq-ciphersuites' category-5 suite: HPKE KEM 0x0042 (pure
// ML-KEM-1024, draft-ietf-hpke-pq), HKDF-SHA512 (HPKE KDF 0x0003),
// AES-256-GCM, SHA-512 and ML-DSA-87 signatures (pure, empty context). The
// draft's value is still TBD, so this is from RFC 9420's private-use range and
// must change with every other implementation's when IANA assigns one.
//
// It is the only suite. The AES-128 suites, RFC 9420's 0x0001 and the draft's
// X-Wing 0xF0A1, and MOQOM's earlier ML-KEM suites 0xF0AA and 0xF0AB are
// refused as unsupported.
const SuiteMLDSA CipherSuite = 0xF0AC

// FoundingSuite is the suite every group is founded in.
const FoundingSuite = SuiteMLDSA

const aeadNonceLength = 12

// Known reports whether the suite is one this package implements.
func (s CipherSuite) Known() bool {
	return s == SuiteMLDSA
}

// Name is the suite's registered name.
func (s CipherSuite) Name() string {
	if s == SuiteMLDSA {
		return "MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87"
	}
	return fmt.Sprintf("unknown suite %#04x", uint16(s))
}

func (s CipherSuite) String() string { return fmt.Sprintf("%s (%#04x)", s.Name(), uint16(s)) }

func (CipherSuite) newHash() hash.Hash { return sha512.New() }

// HashLength is KDF.Nh: 64, for SHA-512.
func (CipherSuite) HashLength() int { return 64 }

// aeadKeyLength is AEAD.Nk: 32, for AES-256-GCM.
const aeadKeyLength = 32

func (CipherSuite) aeadKeyLength() int { return aeadKeyLength }

// PublicKeyLength is an init or leaf encryption key's length, HPKE's Npk.
func (CipherSuite) PublicKeyLength() int { return mlkem.EncapsulationKeySize1024 }

// EncapsulationLength is HPKE's Nenc.
func (CipherSuite) EncapsulationLength() int { return mlkem.CiphertextSize1024 }

// SignatureKeyLength is a signature public key's length: 2,592, for ML-DSA-87.
func (CipherSuite) SignatureKeyLength() int { return 2592 }

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

// ExpandWithLabel is RFC 9420 §5.1.3's. A length that is negative or past 255
// times the suite's hash length, HKDF-Expand's limit, is ErrInvalidLength.
func (s CipherSuite) ExpandWithLabel(secret []byte, label string, context []byte, length int) ([]byte, error) {
	if limit := s.maxExpandLength(); length < 0 || length > limit {
		return nil, fmt.Errorf("%w: %d bytes, at most %d", ErrInvalidLength, length, limit)
	}
	return s.expandWithLabel(secret, label, context, length), nil
}

// maxExpandLength is HKDF-Expand's limit of 255 times the hash length, which
// for every suite here also fits ExpandWithLabel's 16-bit length.
func (s CipherSuite) maxExpandLength() int { return 255 * s.HashLength() }

// expandWithLabel is ExpandWithLabel for a length the caller fixes within
// maxExpandLength.
func (s CipherSuite) expandWithLabel(secret []byte, label string, context []byte, length int) []byte {
	var info writer
	info.uint16(uint16(length))
	info.vector([]byte("MLS 1.0 " + label))
	info.vector(context)
	return s.expand(secret, info.bytes, length)
}

// DeriveSecret is RFC 9420 §5.1.3's.
func (s CipherSuite) DeriveSecret(secret []byte, label string) []byte {
	return s.expandWithLabel(secret, label, nil, s.HashLength())
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
// a 32-byte ML-DSA-87 seed (FIPS 204's xi), and the public half as it travels.
func (s CipherSuite) GenerateSignatureKeyPair() (private, public []byte, err error) {
	if !s.Known() {
		return nil, nil, fmt.Errorf("%w: cipher suite %#04x", ErrUnsupported, uint16(s))
	}
	key, err := mldsa.GenerateKey(mldsa.MLDSA87())
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrCryptoFailure, err)
	}
	return key.Bytes(), key.PublicKey().Bytes(), nil
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
	if !s.Known() {
		return nil, fmt.Errorf("%w: cipher suite %#04x", ErrUnsupported, uint16(s))
	}
	key, err := mldsa.NewPrivateKey(mldsa.MLDSA87(), private)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCryptoFailure, err)
	}
	signature, err := key.Sign(rand.Reader, signContent(label, content), &mldsa.Options{})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCryptoFailure, err)
	}
	return signature, nil
}

// VerifyWithLabel is RFC 9420 §5.1.2's.
func (s CipherSuite) VerifyWithLabel(public []byte, label string, content, signature []byte) bool {
	if !s.Known() || len(public) != s.SignatureKeyLength() {
		return false
	}
	key, err := mldsa.NewPublicKey(mldsa.MLDSA87(), public)
	if err != nil {
		return false
	}
	return mldsa.Verify(key, signContent(label, content), signature, nil) == nil
}

// The KEM

func (CipherSuite) kem() hpke.KEM { return hpke.MLKEM1024() }

func (CipherSuite) kdf() hpke.KDF { return hpke.HKDFSHA512() }

func (CipherSuite) aead() hpke.AEAD { return hpke.AES256GCM() }

// GenerateKeyPair returns a fresh KEM key pair: the private half as RFC 9180's
// SerializePrivateKey gives it (ML-KEM-1024's 64-byte seed d || z) and the
// public half as it travels.
func (s CipherSuite) GenerateKeyPair() (private, public []byte, err error) {
	if !s.Known() {
		return nil, nil, fmt.Errorf("%w: cipher suite %#04x", ErrUnsupported, uint16(s))
	}
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
// length, and passing FIPS 203's encapsulation key check.
func (s CipherSuite) isValidPublicKey(public []byte) bool {
	if !s.Known() || len(public) != s.PublicKeyLength() {
		return false
	}
	_, err := mlkem.NewEncapsulationKey1024(public)
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
	if !s.Known() {
		return HPKECiphertext{}, fmt.Errorf("%w: cipher suite %#04x", ErrUnsupported, uint16(s))
	}
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
	if !s.Known() || len(ciphertext.KEMOutput) != s.EncapsulationLength() {
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

// AES-256-GCM only: a key of any other length is refused, so nothing can
// fall back to AES-128 by passing a 16-byte key.

func aeadSeal(key, nonce, plaintext []byte) ([]byte, error) {
	if len(key) != aeadKeyLength {
		return nil, fmt.Errorf("%w: AEAD key length %d", ErrCryptoFailure, len(key))
	}
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
	if len(key) != aeadKeyLength {
		return nil, fmt.Errorf("%w: AEAD key length %d", ErrDecryptionFailed, len(key))
	}
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
