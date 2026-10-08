// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

import CryptoKit
import Foundation
import Testing

@testable import MoqomProof

@Suite("moqom-proof")
struct ProverTests {
    static let certificate = Data(repeating: 0x2A, count: 32)
    static let now = Date(timeIntervalSince1970: 1_700_000_000)
    static let until = now.addingTimeInterval(600)

    static func provers() throws -> [Prover] {
        [Prover(.mlDSA65(try MLDSA65.PrivateKey())), Prover(.es256(P256.Signing.PrivateKey()))]
    }

    @Test("a proof round-trips in each algorithm, once")
    func roundTrip() throws {
        for prover in try Self.provers() {
            let token = Data("a.token".utf8)
            let proof = try prover.prove(
                token: token, certificateHash: Self.certificate, nonce: Prover.nonce(), issuedAt: Self.now
            )
            let checker = Checker(store: MemoryNonceStore())
            try checker.check(
                proof, token: token, certificateHash: Self.certificate,
                thumbprint: prover.thumbprint, now: Self.now, until: Self.until
            )
            #expect(throws: ProofError.replayed) {
                try checker.check(
                    proof, token: token, certificateHash: Self.certificate,
                    thumbprint: prover.thumbprint, now: Self.now, until: Self.until
                )
            }
        }
    }

    @Test("an ML-DSA-65 proof fits the limit with room to spare")
    func size() throws {
        let prover = Prover(.mlDSA65(try MLDSA65.PrivateKey()))
        let proof = try prover.prove(
            token: Data(repeating: 0x74, count: 5000), certificateHash: Self.certificate,
            nonce: Prover.nonce(), issuedAt: Self.now
        )
        #expect(proof.count < Checker.maximumProofBytes * 3 / 4)
    }

    @Test("a checker can be limited to ML-DSA-65")
    func onlyMLDSA() throws {
        let prover = Prover(.es256(P256.Signing.PrivateKey()))
        let proof = try prover.prove(
            token: Data("t".utf8), certificateHash: Self.certificate, nonce: "n", issuedAt: Self.now
        )
        let checker = Checker(store: MemoryNonceStore(), algorithms: [.mlDSA65])
        #expect(throws: ProofError.unsupported) {
            try checker.check(
                proof, token: Data("t".utf8), certificateHash: Self.certificate,
                thumbprint: prover.thumbprint, now: Self.now, until: Self.until
            )
        }
    }

    @Test("the JWK members are the ones its kind has")
    func members() throws {
        let prover = Prover(.mlDSA65(try MLDSA65.PrivateKey()))
        #expect(Set(prover.jwk.members.keys) == ["kty", "alg", "pub"])
        #expect(try prover.jwk.thumbprint() == prover.thumbprint)
        let legacy = Prover(.es256(P256.Signing.PrivateKey()))
        #expect(Set(legacy.jwk.members.keys) == ["kty", "crv", "x", "y"])
    }

    @Test("the store sweeps expired nonces and fails closed")
    func store() throws {
        let store = MemoryNonceStore(capacity: 2)
        try store.spend("a", until: Self.now, now: Self.now)
        try store.spend("b", until: Self.now, now: Self.now)
        let later = Self.now.addingTimeInterval(1)
        try store.spend("c", until: Self.until, now: later)
        try store.spend("d", until: Self.until, now: later)
        #expect(throws: ProofError.overloaded) { try store.spend("e", until: Self.until, now: later) }
    }

    @Test("nonces are fresh, and a proof needs one")
    func nonces() throws {
        #expect(Prover.nonce() != Prover.nonce())
        let prover = Prover(.mlDSA65(try MLDSA65.PrivateKey()))
        #expect(throws: ProofError.self) {
            try prover.prove(token: Data(), certificateHash: Self.certificate, nonce: "")
        }
    }

    /// Skipped where there is no enclave: a simulator, or a Mac without one.
    @Test("a Secure Enclave ML-DSA-65 key proves like a software one", .enabled(if: SecureEnclave.isAvailable))
    func secureEnclave() throws {
        let prover = Prover(.secureEnclaveMLDSA65(try SecureEnclave.MLDSA65.PrivateKey()))
        let proof = try prover.prove(
            token: Data("t".utf8), certificateHash: Self.certificate, nonce: "n", issuedAt: Self.now
        )
        try Checker(store: MemoryNonceStore()).check(
            proof, token: Data("t".utf8), certificateHash: Self.certificate,
            thumbprint: prover.thumbprint, now: Self.now, until: Self.until
        )
    }
}
