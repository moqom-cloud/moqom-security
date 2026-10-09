// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

// Package token is moqom-token: it mints and verifies the credential a MOQOM
// client joins a relay with.
//
// A token is a compact JWS (RFC 7515) over JSON claims, typed "MOQT", signed
// with ML-DSA-87 (FIPS 204, JOSE "ML-DSA-87", JWK kty "AKP"), the only
// algorithm a token is signed or verified with. The key a token names by `kid`
// decides the algorithm it is verified with; the header's `alg` must agree and
// is never trusted on its own.
//
// The claims carry who the holder is (`sub`), the tenant (`aud`), the device key
// the token is bound to (`cnf.jkt`, an RFC 7638 thumbprint), what they may do in
// MoQ (`moqt`, see Grant), and a lifetime of at most fifteen minutes.
//
// Signer.Sign and Verifier.Verify are the whole API. Verify checks the
// signature before it reads a claim, and returns claims only from a token whose
// signature verified and whose claims passed every check.
//
// The same library exists in Rust (crate moqom-token) and Swift (MoqomToken),
// and all three pass the vectors in vectors/token. See docs/moqom-token.md.
package token
