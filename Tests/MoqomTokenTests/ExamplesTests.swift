// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

// The examples on moqom.dev, against the public API only.

import CryptoKit
import Foundation
import MoqomToken
import Testing

@Suite struct ExamplesTests {
    @Test func mintAndVerify() throws {
        // Generate a key once and keep its 32-byte seed in your secret store.
        let seed = try MLDSA65.PrivateKey().seedRepresentation

        // Load it under the key ID your JWK set publishes.
        let signer = try Signer(seed: seed, keyID: "2026-10")

        let now = Int64(Date().timeIntervalSince1970)
        let jws = try signer.sign(Claims(
            issuer: "https://api.example.com",
            subject: "ada",
            tenant: "acme",
            id: "c6c1f2d0",
            issuedAt: now,
            expires: now + 600,
            // The RFC 7638 thumbprint of the device's key, from MoqomProof.
            thumbprint: "MpXqvQAmv7Y3Kk9dHnJpLwRtUvXyZaBcDeFgHiJkLmM",
            grant: Grant(room: "room-42", publish: 3, owner: true)
        ))

        // A relay reads the published JWK set and verifies.
        let document = Data(#"{"keys":[\#(signer.publicKey.jwk)]}"#.utf8)
        let keys = try PublicKey.parseSet(document)
        let verifier = Verifier(issuer: "https://api.example.com", tenant: "acme", keys: keys)
        let claims = try verifier.verify(jws, now: Date())
        #expect(claims.subject == "ada" && claims.grant.room == "room-42")
    }

    @Test func expiredAndWrongKey() throws {
        let signer = Signer(privateKey: try MLDSA65.PrivateKey())
        let now = Date()
        let iat = Int64(now.timeIntervalSince1970)
        let jws = try signer.sign(Claims(
            subject: "ada", tenant: "acme", issuedAt: iat, expires: iat + 600,
            thumbprint: "MpXqvQAmv7Y3Kk9dHnJpLwRtUvXyZaBcDeFgHiJkLmM"
        ))
        let verifier = Verifier(keys: [signer.publicKey])

        // Eleven minutes on, the ten-minute token is past its expiry and the 30-second skew.
        #expect(throws: TokenError.expired) {
            try verifier.verify(jws, now: now + 11 * 60)
        }

        // A verifier that does not hold the token's key ID.
        let other = try MLDSA65.PrivateKey()
        #expect(throws: TokenError.unknownKey) {
            try Verifier(keys: [Signer(privateKey: other).publicKey]).verify(jws, now: now)
        }

        // Another key published under the same key ID.
        let impostor = Signer(privateKey: other, keyID: signer.keyID).publicKey
        #expect(throws: TokenError.badSignature) {
            try Verifier(keys: [impostor]).verify(jws, now: now)
        }
    }
}
