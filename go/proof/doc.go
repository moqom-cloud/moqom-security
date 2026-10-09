// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

// Package proof is moqom-proof: device-bound proof of possession for MoQ
// sessions.
//
// A device holds a signing key; a join token names it by RFC 7638 thumbprint in
// `cnf.jkt`. At connect, and again on every in-session renewal, the device
// signs a single-use proof shaped like an RFC 9449 DPoP proof: a compact JWS,
// typed MOQT-POP, carrying the public key and committing to the token by hash
// (`ath`), to the peer's leaf certificate by hash (`rel`), to a time (`iat`) and
// to a nonce (`jti`) the checker accepts once.
//
// One algorithm: ML-DSA-87 (JOSE "ML-DSA-87", JWK kty "AKP"), so every proof is
// post-quantum. ES256, ML-DSA-65 and every other algorithm are refused.
//
// [Prover] makes proofs; a [Checker] from [NewChecker] checks them against a
// caller-supplied [NonceStore], such as [NewDefaultMemoryNonceStore]. Settings
// that cannot work (no store, no algorithms, a window or capacity that is not
// positive) are refused when the checker or store is made, with
// [ErrConfiguration]. See docs/moqom-proof.md for the wire format.
package proof
