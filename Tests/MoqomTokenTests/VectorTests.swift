// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

// Every case in `vectors/token`, which the Go implementation generates.

import CryptoKit
import Foundation
import Testing
@testable import MoqomToken

private struct Key: Decodable {
    let kid: String
    let alg: String
    let seed_hex: String
    let public_hex: String
    let kid_derived: Bool
}

private struct VerifyCase: Decodable {
    let name: String
    let token: String
    let now: Int64
    let issuer: String
    let tenant: String?
    let keys: [String]
    let error: String?
}

private struct SignCase: Decodable {
    let name: String
    let kid: String
    let signing_input: String?
    let token: String?
    let error: String?
}

private struct File<Case: Decodable>: Decodable {
    let keys: [Key]
    let cases: [Case]
}

/// A case's `claims` object, as the bytes it was written with.
private func claims(of file: Data) throws -> [String: Data] {
    let object = try #require(try JSONSerialization.jsonObject(with: file) as? [String: Any])
    let cases = try #require(object["cases"] as? [[String: Any]])
    var byName: [String: Data] = [:]
    for c in cases {
        guard let name = c["name"] as? String, let claims = c["claims"] else { continue }
        byName[name] = try JSONSerialization.data(withJSONObject: claims)
    }
    return byName
}

private func hex(_ text: String) -> Data {
    var data = Data()
    var index = text.startIndex
    while index < text.endIndex {
        let next = text.index(index, offsetBy: 2)
        data.append(UInt8(text[index ..< next], radix: 16)!)
        index = next
    }
    return data
}

private func read<Case: Decodable>(_ name: String) throws -> (File<Case>, Data, [String: PublicKey], [String: Signer]) {
    let url = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        .appendingPathComponent("vectors/token/\(name)")
    let raw = try Data(contentsOf: url)
    let file = try JSONDecoder().decode(File<Case>.self, from: raw)
    var keys: [String: PublicKey] = [:]
    var signers: [String: Signer] = [:]
    for key in file.keys {
        let publicBytes = hex(key.public_hex)
        if key.kid_derived { #expect(PublicKey.derivedID(for: publicBytes) == key.kid) }
        switch key.alg {
        case "ML-DSA-65":
            let signer = try Signer(seed: hex(key.seed_hex), keyID: key.kid)
            #expect(signer.publicKey.rawRepresentation == publicBytes, "\(key.kid): seed and public key")
            signers[key.kid] = signer
            keys[key.kid] = try PublicKey(id: key.kid, algorithm: .mlDSA65, rawRepresentation: publicBytes)
        case "EdDSA":
            let derived = try Curve25519.Signing.PrivateKey(rawRepresentation: hex(key.seed_hex)).publicKey
            #expect(derived.rawRepresentation == publicBytes)
            keys[key.kid] = try PublicKey(id: key.kid, algorithm: .ed25519, rawRepresentation: publicBytes)
        default:
            Issue.record("algorithm \(key.alg)")
        }
    }
    return (file, raw, keys, signers)
}

@Suite("moqom-token vectors")
struct VectorTests {
    @Test("every verify vector")
    func verify() throws {
        let (file, raw, keys, _) = try read("verify.json") as (File<VerifyCase>, Data, [String: PublicKey], [String: Signer])
        let expected = try claims(of: raw)
        #expect(file.cases.count > 40)
        for c in file.cases {
            let verifier = Verifier(issuer: c.issuer, tenant: c.tenant ?? "", keys: c.keys.compactMap { keys[$0] })
            let now = Date(timeIntervalSince1970: TimeInterval(c.now))
            switch Result(catching: { () throws(TokenError) in try verifier.verify(c.token, now: now) }) {
            case let .success(verified):
                #expect(c.error == nil, "\(c.name): accepted, want \(c.error ?? "")")
                let want = try Claims(json: try #require(expected[c.name]))
                #expect(verified == want, "\(c.name)")
            case let .failure(error):
                #expect(error.errorClass == c.error, "\(c.name): \(error)")
            }
        }
    }

    @Test("every sign vector")
    func sign() throws {
        let (file, raw, keys, signers) = try read("sign.json") as (File<SignCase>, Data, [String: PublicKey], [String: Signer])
        let given = try claims(of: raw)
        for c in file.cases {
            let claims = try Claims(json: try #require(given[c.name]))
            let signer = try #require(signers[c.kid])
            let signed: String
            do {
                signed = try signer.sign(claims)
            } catch {
                #expect((error as? TokenError)?.errorClass == c.error, "\(c.name): \(error)")
                continue
            }
            #expect(c.error == nil, "\(c.name): signed, want \(c.error ?? "")")
            let dot = try #require(signed.lastIndex(of: "."))
            #expect(String(signed[..<dot]) == c.signing_input, "\(c.name)")
            let verifier = Verifier(keys: [try #require(keys[c.kid])])
            let vector = try #require(c.token)
            for token in [vector, signed] {
                #expect(try verifier.verify(token, now: claims.issuedAtDate) == claims, "\(c.name)")
            }
        }
    }

    @Test("a JWK set round-trips, and keys of the wrong kind are refused")
    func jwks() throws {
        let signer = try Signer(seed: Data(repeating: 1, count: 32))
        let legacy = try PublicKey(id: "old", algorithm: .ed25519, rawRepresentation: Data(repeating: 7, count: 32))
        let document = Data("{\"keys\":[\(signer.publicKey.jwk),\(legacy.jwk)]}".utf8)
        #expect(try PublicKey.parseSet(document) == [signer.publicKey, legacy])
        for refused in [
            #"[{"kty":"AKP","alg":"ML-DSA-44","kid":"k","pub":"AAAA"}]"#,
            #"[{"kty":"AKP","alg":"ML-DSA-65","kid":"k","pub":"AAAA"}]"#,
            #"[{"kty":"OKP","crv":"P-256","kid":"k","x":"AAAA"}]"#,
            #"["not an object"]"#,
        ] {
            #expect(throws: PublicKey.SetError.self) { try PublicKey.parseSet(Data(refused.utf8)) }
        }
    }

    @Test("a raw key of the wrong length is refused, as in a set")
    func rawKeyLength() throws {
        let mlDSA = try Signer(seed: Data(repeating: 1, count: 32)).publicKey.rawRepresentation
        #expect(throws: Never.self) { try PublicKey(id: "k", algorithm: .mlDSA65, rawRepresentation: mlDSA) }
        #expect(throws: Never.self) { try PublicKey(id: "k", algorithm: .ed25519, rawRepresentation: Data(repeating: 7, count: 32)) }
        let refused: [(Algorithm, Data)] = [
            (.mlDSA65, mlDSA.dropLast()), (.mlDSA65, mlDSA + [0]), (.mlDSA65, Data(repeating: 7, count: 32)), (.mlDSA65, Data()),
            (.ed25519, Data(repeating: 7, count: 31)), (.ed25519, Data(repeating: 7, count: 33)), (.ed25519, mlDSA), (.ed25519, Data()),
        ]
        for (algorithm, raw) in refused {
            do {
                _ = try PublicKey(id: "k", algorithm: algorithm, rawRepresentation: raw)
                Issue.record("\(algorithm) key of \(raw.count) bytes accepted")
            } catch {
                guard case .invalid(kid: "k", reason: _) = error else {
                    Issue.record("\(error)")
                    continue
                }
                #expect(error.errorClass == "key_invalid")
            }
        }
        do {
            _ = try PublicKey(algorithm: .ed25519, rawRepresentation: Data(repeating: 7, count: 31))
        } catch {
            #expect(error == .invalid(kid: PublicKey.derivedID(for: Data(repeating: 7, count: 31)),
                                      reason: "a EdDSA public key is 32 bytes"))
        }
    }

    @Test("every key set vector")
    func keySets() throws {
        let (file, _, _, _) = try read("keysets.json") as (File<KeySetCase>, Data, [String: PublicKey], [String: Signer])
        #expect(file.cases.count > 30)
        for c in file.cases {
            switch Result(catching: { () throws(PublicKey.SetError) in try PublicKey.parseSet(Data(c.document.utf8)) }) {
            case let .success(keys):
                #expect(c.error == nil, "\(c.name): accepted, want \(c.error ?? "")")
                #expect(keys.map(\.id) == c.kids, "\(c.name)")
            case let .failure(error):
                #expect(error.errorClass == c.error, "\(c.name): \(error)")
            }
        }
    }

    @Test("a verifier looks up its keys, and a signer gives back its seed")
    func lookup() throws {
        let seed = Data(repeating: 1, count: 32)
        let signer = try Signer(seed: seed)
        #expect(signer.seed == seed)
        #expect(Verifier(keys: []).isEmpty)
        let verifier = Verifier(keys: [signer.publicKey])
        #expect(!verifier.isEmpty)
        #expect(verifier.key(signer.keyID) == signer.publicKey)
        #expect(verifier.key("other") == nil)
    }
}

private struct KeySetCase: Decodable {
    let name: String
    let document: String
    let kids: [String]?
    let error: String?
}
