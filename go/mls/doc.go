// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

// Package mls is moqom-mls in Go: the subset of MLS (RFC 9420) that MOQOM's
// end-to-end encrypted rooms use to agree SFrame keys, wire-compatible with
// the Swift (MoqomMLS) and Rust (moqom-mls) implementations.
//
// The primitives and the key schedule are RFC 9420's and are held to the
// working group's vectors. The group protocol borrows the RFC's structure --
// epochs, commits carrying Add and Remove proposals and a fresh commit secret,
// Welcomes carrying the joiner secret, signed content, transcript hashes and a
// confirmation tag -- over a flat member list instead of a ratchet tree and
// MOQOM's own TLS-style framing. It does not interoperate with other MLS
// implementations and is not RFC 9420 conformant; see docs/moqom-mls.md.
//
// Every group is founded in MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87
// (0xF0AC, private use): HPKE over pure ML-KEM-1024, HKDF-SHA512, AES-256-GCM,
// SHA-512 and ML-DSA-87 signatures. It is the only suite: the AES-128 suites
// (RFC 9420's 0x0001 and the draft's X-Wing, 0xF0A1) and MOQOM's earlier
// ML-KEM suites 0xF0AA and 0xF0AB are refused as unsupported. Everything is
// the standard library's: crypto/hpke, crypto/mldsa, crypto/hkdf, crypto/hmac
// and crypto/aes.
package mls
