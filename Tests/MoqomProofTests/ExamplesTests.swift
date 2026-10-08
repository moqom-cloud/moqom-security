// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

// The examples on moqom.dev, through the public API only.

import CryptoKit
import Foundation
import MoqomProof
import Testing

@Suite("moqom-proof examples")
struct ExamplesTests {
    @Test("a device proves, a relay checks, and a replay is refused")
    func proveAndCheck() throws {
        // On the device.
        let device = Prover(.mlDSA65(try MLDSA65.PrivateKey()))
        let jkt = device.thumbprint // the control plane puts this in the token's cnf.jkt
        let token = Data("eyJhbGciOiJNTC1EU0EtNjUi...".utf8)
        let relayCertificate = Data(SHA256.hash(data: Data("the relay's leaf certificate, DER".utf8)))
        let now = Date()
        let proof = try device.prove(token: token, certificateHash: relayCertificate, nonce: Prover.nonce(), issuedAt: now)

        // On the relay.
        let checker = Checker(store: MemoryNonceStore())
        let expiry = now.addingTimeInterval(15 * 60)
        try checker.check(proof, token: token, certificateHash: relayCertificate, thumbprint: jkt, now: now, until: expiry)
        #expect(throws: ProofError.replayed) {
            try checker.check(proof, token: token, certificateHash: relayCertificate, thumbprint: jkt, now: now, until: expiry)
        }
    }

    @Test("a software device key is stored as its seed and loaded again")
    func storeAKey() throws {
        let key = try MLDSA65.PrivateKey()
        let seed = key.seedRepresentation

        let loaded = Prover(.mlDSA65(try MLDSA65.PrivateKey(seedRepresentation: seed, publicKey: nil)))
        #expect(seed.count == 32)
        #expect(loaded.algorithm == .mlDSA65)
        #expect(loaded.thumbprint == Prover(.mlDSA65(key)).thumbprint)
    }

    @Test("each refusal names the check that failed")
    func refusals() throws {
        let device = Prover(.mlDSA65(try MLDSA65.PrivateKey()))
        let stranger = Prover(.mlDSA65(try MLDSA65.PrivateKey()))
        let token = Data("eyJhbGciOiJNTC1EU0EtNjUi...".utf8)
        let relay = Data(SHA256.hash(data: Data("relay A's leaf certificate".utf8)))
        let other = Data(SHA256.hash(data: Data("relay B's leaf certificate".utf8)))
        let now = Date()
        let expiry = now.addingTimeInterval(15 * 60)
        let checker = Checker(store: MemoryNonceStore())
        func check(_ proof: Data) throws(ProofError) {
            try checker.check(proof, token: token, certificateHash: relay, thumbprint: device.thumbprint, now: now, until: expiry)
        }

        let wrongToken = try device.prove(token: Data("another token".utf8), certificateHash: relay, nonce: Prover.nonce(), issuedAt: now)
        #expect(throws: ProofError.wrongToken) { try check(wrongToken) }
        let wrongPeer = try device.prove(token: token, certificateHash: other, nonce: Prover.nonce(), issuedAt: now)
        #expect(throws: ProofError.wrongCertificate) { try check(wrongPeer) }
        let wrongKey = try stranger.prove(token: token, certificateHash: relay, nonce: Prover.nonce(), issuedAt: now)
        #expect(throws: ProofError.wrongKey) { try check(wrongKey) }
        let stale = try device.prove(token: token, certificateHash: relay, nonce: Prover.nonce(), issuedAt: now.addingTimeInterval(-10 * 60))
        #expect(throws: ProofError.expired) { try check(stale) }
        #expect(ProofError.expired.errorClass == "expired")
    }

    @Test("an ES256 key is accepted by default and refused by a checker limited to ML-DSA-65")
    func rollover() throws {
        let older = Prover(.es256(P256.Signing.PrivateKey()))
        let token = Data("eyJhbGciOiJNTC1EU0EtNjUi...".utf8)
        let relay = Data(SHA256.hash(data: Data("the relay's leaf certificate, DER".utf8)))
        let now = Date()
        let expiry = now.addingTimeInterval(15 * 60)
        let proof = try older.prove(token: token, certificateHash: relay, nonce: Prover.nonce(), issuedAt: now)

        let both = Checker(store: MemoryNonceStore())
        let strict = Checker(store: MemoryNonceStore(), algorithms: [.mlDSA65])
        try both.check(proof, token: token, certificateHash: relay, thumbprint: older.thumbprint, now: now, until: expiry)
        #expect(throws: ProofError.unsupported) {
            try strict.check(proof, token: token, certificateHash: relay, thumbprint: older.thumbprint, now: now, until: expiry)
        }
    }

    @Test("checkers that share a store refuse a proof another has accepted")
    func sharedStore() throws {
        let store = MemoryNonceStore()
        let first = Checker(store: store)
        let second = Checker(store: store)

        let device = Prover(.mlDSA65(try MLDSA65.PrivateKey()))
        let token = Data("eyJhbGciOiJNTC1EU0EtNjUi...".utf8)
        let relay = Data(SHA256.hash(data: Data("the relay's leaf certificate, DER".utf8)))
        let now = Date()
        let expiry = now.addingTimeInterval(15 * 60)
        let proof = try device.prove(token: token, certificateHash: relay, nonce: Prover.nonce(), issuedAt: now)

        try first.check(proof, token: token, certificateHash: relay, thumbprint: device.thumbprint, now: now, until: expiry)
        #expect(throws: ProofError.replayed) {
            try second.check(proof, token: token, certificateHash: relay, thumbprint: device.thumbprint, now: now, until: expiry)
        }
        #expect(store.remembered == 1)
    }
}
