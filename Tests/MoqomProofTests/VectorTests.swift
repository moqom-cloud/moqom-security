// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

// Every case in vectors/proof.

import CryptoKit
import Foundation
import Testing

@testable import MoqomProof

@Suite("moqom-proof vectors")
struct VectorTests {
    struct File<Case: Decodable>: Decodable {
        var window_seconds: Double?
        var cases: [Case]
    }

    struct KeyCase: Decodable {
        var name: String
        var alg: String
        var seed_hex: String?
        var private_hex: String?
        var jwk: ProofJWK
        var thumbprint: String
    }

    struct ThumbprintCase: Decodable {
        var name: String
        var jwk: ProofJWK
        var thumbprint: String?
        var error: String?
    }

    struct ProofCase: Decodable {
        var name: String
        var token: String
        var certificate_hash_hex: String
        var thumbprint: String
        var now: Double
        var until: Double
        var spent: [String]?
        var require_certificate: Bool?
        var proof: String
        var error: String?
    }

    static func read<Case: Decodable>(_ name: String) throws -> File<Case> {
        let url = URL(filePath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appending(path: "vectors/proof/\(name)")
        let file = try JSONDecoder().decode(File<Case>.self, from: Data(contentsOf: url))
        #expect(!file.cases.isEmpty, "\(name) has no cases")
        return file
    }

    @Test("keys derive the committed JWK and thumbprint")
    func keys() throws {
        let file: File<KeyCase> = try Self.read("keys.json")
        for vector in file.cases {
            let prover: Prover
            switch ProofAlgorithm(rawValue: vector.alg) {
            case .mlDSA65:
                prover = Prover(.mlDSA65(try MLDSA65.PrivateKey(
                    seedRepresentation: Data(hex: try #require(vector.seed_hex)), publicKey: nil
                )))
            case .es256:
                prover = Prover(.es256(try P256.Signing.PrivateKey(
                    rawRepresentation: Data(hex: try #require(vector.private_hex))
                )))
            case nil:
                Issue.record("\(vector.name): unknown alg")
                continue
            }
            #expect(prover.jwk == vector.jwk, "\(vector.name)")
            #expect(prover.thumbprint == vector.thumbprint, "\(vector.name)")
        }
    }

    @Test("thumbprints")
    func thumbprints() throws {
        let file: File<ThumbprintCase> = try Self.read("thumbprints.json")
        for vector in file.cases {
            do {
                let got = try vector.jwk.thumbprint()
                #expect(vector.error == nil && got == vector.thumbprint, "\(vector.name): \(got)")
            } catch {
                #expect(error.errorClass == vector.error, "\(vector.name): \(error)")
            }
        }
    }

    @Test("proofs")
    func proofs() throws {
        let file: File<ProofCase> = try Self.read("proofs.json")
        for vector in file.cases {
            let store = MemoryNonceStore()
            let now = Date(timeIntervalSince1970: vector.now)
            let until = Date(timeIntervalSince1970: vector.until)
            for nonce in vector.spent ?? [] {
                try store.spend(nonce, until: until, now: now)
            }
            let checker = try Checker(
                store: store,
                window: try #require(file.window_seconds),
                requireCertificate: vector.require_certificate ?? false
            )
            func check() -> String? {
                do {
                    try checker.check(
                        Data(vector.proof.utf8),
                        token: Data(vector.token.utf8),
                        certificateHash: vector.certificate_hash_hex.isEmpty ? nil : Data(hex: vector.certificate_hash_hex),
                        thumbprint: vector.thumbprint,
                        now: now,
                        until: until
                    )
                    return nil
                } catch {
                    return error.errorClass
                }
            }
            #expect(check() == vector.error, "\(vector.name)")
            let spent = vector.spent?.count ?? 0
            if vector.error == nil {
                #expect(store.remembered == spent + 1, "\(vector.name)")
                #expect(check() == "replayed", "\(vector.name)")
            } else {
                #expect(store.remembered == spent, "\(vector.name): a refused proof spent its nonce")
            }
        }
    }
}

extension Data {
    init(hex: String) {
        var bytes: [UInt8] = []
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            bytes.append(UInt8(hex[index ..< next], radix: 16)!)
            index = next
        }
        self.init(bytes)
    }
}
