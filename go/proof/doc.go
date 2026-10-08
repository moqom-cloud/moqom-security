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
// Two algorithms: ML-DSA-65 (JOSE "ML-DSA-65", JWK kty "AKP"), the default, and
// ES256 on P-256, accepted while devices holding older keys roll over.
//
// [Prover] makes proofs; [Checker] checks them against a caller-supplied
// [NonceStore]. See docs/moqom-proof.md for the wire format.
package proof
