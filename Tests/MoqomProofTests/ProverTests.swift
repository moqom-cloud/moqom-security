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
        [Prover(.mlDSA87(try MLDSA87.PrivateKey()))]
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

    @Test("an ML-DSA-87 proof fits the limit with room to spare")
    func size() throws {
        let prover = Prover(.mlDSA87(try MLDSA87.PrivateKey()))
        let proof = try prover.prove(
            token: Data(repeating: 0x74, count: 5000), certificateHash: Self.certificate,
            nonce: Prover.nonce(), issuedAt: Self.now
        )
        #expect(proof.count < Checker.maximumProofBytes * 3 / 4)
    }

    @Test("ML-DSA-87 is the only algorithm, and P-256 and ML-DSA-65 keys have no thumbprint")
    func onlyMLDSA() throws {
        #expect(ProofAlgorithm.allCases == [.mlDSA87])
        #expect(ProofAlgorithm(rawValue: "ES256") == nil)
        #expect(ProofAlgorithm(rawValue: "ML-DSA-65") == nil)
        let raw = P256.Signing.PrivateKey().publicKey.rawRepresentation
        let ec = ProofJWK(kty: "EC", alg: nil, pub: raw.base64URL)
        #expect(throws: ProofError.unsupported) { try ec.thumbprint() }
        let previous = ProofJWK(kty: "AKP", alg: "ML-DSA-65", pub: try MLDSA65.PrivateKey().publicKey.rawRepresentation.base64URL)
        #expect(throws: ProofError.unsupported) { try previous.thumbprint() }
    }

    @Test("the JWK members are the ones its kind has")
    func members() throws {
        let prover = Prover(.mlDSA87(try MLDSA87.PrivateKey()))
        #expect(Set(prover.jwk.members.keys) == ["kty", "alg", "pub"])
        #expect(try prover.jwk.thumbprint() == prover.thumbprint)
    }

    @Test("the store sweeps expired nonces and fails closed")
    func store() throws {
        let store = try MemoryNonceStore(capacity: 2)
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
        let prover = Prover(.mlDSA87(try MLDSA87.PrivateKey()))
        #expect(throws: ProofError.self) {
            try prover.prove(token: Data(), certificateHash: Self.certificate, nonce: "")
        }
    }

    @Test("settings that cannot work are refused at construction")
    func configuration() throws {
        func refused(_ make: () throws -> Void) {
            do {
                try make()
                Issue.record("accepted")
            } catch {
                #expect((error as? ProofError)?.errorClass == "configuration", "\(error)")
            }
        }
        refused { _ = try MemoryNonceStore(capacity: 0) }
        refused { _ = try MemoryNonceStore(capacity: -1) }
        refused { _ = try Checker(store: MemoryNonceStore(), window: 0) }
        refused { _ = try Checker(store: MemoryNonceStore(), window: -1) }
        refused { _ = try Checker(store: MemoryNonceStore(), window: .nan) }
        refused { _ = try Checker(store: MemoryNonceStore(), window: .infinity) }
        refused { _ = try Checker(store: MemoryNonceStore(), algorithms: []) }

        let checker = Checker(store: MemoryNonceStore())
        #expect(checker.algorithms == Set(ProofAlgorithm.allCases))
        #expect(checker.window == Checker.defaultWindow)
        #expect(!checker.requireCertificate)
        #expect(MemoryNonceStore().capacity == MemoryNonceStore.defaultCapacity)
    }

    /// A caller that passes an `until` earlier than the end of the proof's
    /// window must not get the proof accepted twice once the store sweeps.
    @Test("a short until cannot reopen replay")
    func shortUntil() throws {
        let prover = Prover(.mlDSA87(try MLDSA87.PrivateKey()))
        let store = try MemoryNonceStore(capacity: 2)
        let checker = Checker(store: store)
        let token = Data("a.token".utf8)
        let proof = try prover.prove(
            token: token, certificateHash: Self.certificate, nonce: Prover.nonce(), issuedAt: Self.now
        )
        func check(at time: Date) throws(ProofError) {
            try checker.check(
                proof, token: token, certificateHash: Self.certificate,
                thumbprint: prover.thumbprint, now: time, until: time
            )
        }
        try check(at: Self.now)
        // Fill the store so that the next spend sweeps whatever has expired.
        try store.spend("filler", until: Self.now, now: Self.now)
        #expect(throws: ProofError.replayed) { try check(at: Self.now.addingTimeInterval(Checker.defaultWindow)) }
        #expect(store.remembered == 1)
    }

    /// Skipped where there is no enclave: a simulator, or a Mac without one.
    @Test("a Secure Enclave ML-DSA-87 key proves like a software one", .enabled(if: SecureEnclave.isAvailable))
    func secureEnclave() throws {
        let prover = Prover(.secureEnclaveMLDSA87(try SecureEnclave.MLDSA87.PrivateKey()))
        let proof = try prover.prove(
            token: Data("t".utf8), certificateHash: Self.certificate, nonce: "n", issuedAt: Self.now
        )
        try Checker(store: MemoryNonceStore()).check(
            proof, token: Data("t".utf8), certificateHash: Self.certificate,
            thumbprint: prover.thumbprint, now: Self.now, until: Self.until
        )
    }
}
