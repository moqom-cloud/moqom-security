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
    let pool: String?
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
        #expect(key.alg == Algorithm.mlDSA87.rawValue, "\(key.kid): algorithm \(key.alg)")
        let signer = try Signer(seed: hex(key.seed_hex), keyID: key.kid)
        #expect(signer.publicKey.rawRepresentation == publicBytes, "\(key.kid): seed and public key")
        signers[key.kid] = signer
        keys[key.kid] = try PublicKey(id: key.kid, algorithm: .mlDSA87, rawRepresentation: publicBytes)
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
            let verifier = Verifier(issuer: c.issuer, tenant: c.tenant ?? "", pool: c.pool, keys: c.keys.compactMap { keys[$0] })
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
        let next = try Signer(seed: Data(repeating: 2, count: 32), keyID: "next")
        let document = Data("{\"keys\":[\(signer.publicKey.jwk),\(next.publicKey.jwk)]}".utf8)
        #expect(try PublicKey.parseSet(document) == [signer.publicKey, next.publicKey])
        for refused in [
            #"[{"kty":"AKP","alg":"ML-DSA-44","kid":"k","pub":"AAAA"}]"#,
            #"[{"kty":"AKP","alg":"ML-DSA-65","kid":"k","pub":"AAAA"}]"#,
            #"[{"kty":"OKP","crv":"Ed25519","kid":"k","x":"AAAA"}]"#,
            #"[{"kty":"OKP","crv":"P-256","kid":"k","x":"AAAA"}]"#,
            #"["not an object"]"#,
        ] {
            #expect(throws: PublicKey.SetError.self) { try PublicKey.parseSet(Data(refused.utf8)) }
        }
    }

    @Test("a raw key of the wrong length is refused, as in a set")
    func rawKeyLength() throws {
        let mlDSA = try Signer(seed: Data(repeating: 1, count: 32)).publicKey.rawRepresentation
        #expect(mlDSA.count == 2592)
        #expect(throws: Never.self) { try PublicKey(id: "k", algorithm: .mlDSA87, rawRepresentation: mlDSA) }
        let refused: [Data] = [mlDSA.dropLast(), mlDSA + [0], mlDSA.prefix(1952), Data(repeating: 7, count: 32), Data()]
        for raw in refused {
            do {
                _ = try PublicKey(id: "k", algorithm: .mlDSA87, rawRepresentation: raw)
                Issue.record("ML-DSA-87 key of \(raw.count) bytes accepted")
            } catch {
                guard case .invalid(kid: "k", reason: _) = error else {
                    Issue.record("\(error)")
                    continue
                }
                #expect(error.errorClass == "key_invalid")
            }
        }
        do {
            _ = try PublicKey(algorithm: .mlDSA87, rawRepresentation: Data(repeating: 7, count: 31))
            Issue.record("a 31-byte key accepted")
        } catch {
            #expect(error == .invalid(kid: PublicKey.derivedID(for: Data(repeating: 7, count: 31)),
                                      reason: "a ML-DSA-87 public key is 2592 bytes"))
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

private struct SealKeySpec: Decodable {
    let kid: String
    let id_hex: String
    let secret_hex: String
}

private struct SealCase: Decodable {
    let name: String
    let kid: String?
    let nonce_hex: String?
    let token: String?
    let sealed: String?
    let keys: [String]
    let accept_unsealed: Bool?
    let now: Int64?
    let error: String?
}

private struct SealFile: Decodable {
    let keys: [Key]
    let seal_keys: [SealKeySpec]
    let cases: [SealCase]
}

@Suite("moqom-token seal vectors")
struct SealVectorTests {
    @Test("every seal vector")
    func seal() throws {
        let (_, raw, signing, _) = try read("seal.json") as (File<SealCase>, Data, [String: PublicKey], [String: Signer])
        let file = try JSONDecoder().decode(SealFile.self, from: raw)
        let expected = try claims(of: raw)
        var seals: [String: SealKey] = [:]
        for spec in file.seal_keys {
            seals[spec.kid] = try SealKey(id: hex(spec.id_hex), secret: hex(spec.secret_hex))
        }
        #expect(file.cases.count > 15)
        for c in file.cases {
            let token = c.token ?? ""
            if let kid = c.kid {
                let nonce = try AES.GCM.Nonce(data: hex(try #require(c.nonce_hex)))
                #expect(try #require(seals[kid]).seal(token, nonce: nonce) == c.sealed, "\(c.name): sealing")
            }
            let held = c.keys.compactMap { seals[$0] }
            let presented = Data((c.sealed ?? token).utf8)
            guard let now = c.now else {
                switch Result(catching: { () throws(TokenError) in try SealKey.open(presented, keys: held) }) {
                case let .success(opened):
                    #expect(c.error == nil && opened == token, "\(c.name): opened, want \(c.error ?? "the token")")
                case let .failure(error):
                    #expect(error.errorClass == c.error, "\(c.name): \(error)")
                }
                continue
            }
            let verifier = Verifier(keys: Array(signing.values), sealKeys: held, acceptsUnsealed: c.accept_unsealed ?? false)
            let at = Date(timeIntervalSince1970: TimeInterval(now))
            switch Result(catching: { () throws(TokenError) in try verifier.verify(presented, now: at) }) {
            case let .success(verified):
                #expect(c.error == nil, "\(c.name): accepted, want \(c.error ?? "")")
                #expect(verified == (try Claims(json: try #require(expected[c.name]))), "\(c.name)")
            case let .failure(error):
                #expect(error.errorClass == c.error, "\(c.name): \(error)")
            }
        }
    }

    @Test("a seal key round-trips through its JWK and never describes its secret")
    func jwk() throws {
        let key = SealKey.generate()
        let read = try SealKey.parseSet(Data("{\"keys\":[\(key.jwk)]}".utf8))
        #expect(read.map(\.id) == [key.id] && read[0].secret == key.secret)
        #expect(!key.description.contains(key.secret.base64URL))
        #expect(throws: PublicKey.SetError.self) { try SealKey.parseSet(Data("[\(key.jwk),\(key.jwk)]".utf8)) }
        let signer = try Signer(seed: Data(repeating: 1, count: 32))
        let claims = try Claims(json: Data(#"{"iss":"i","sub":"ada","aud":"acme","jti":"j","iat":1800000000,"exp":1800000600,"cnf":{"jkt":"MpXqvQAmv7Y3Kk9dHnJpLwRtUvXyZaBcDeFgHiJkLmM"},"moqt":{"pub":3,"cap":0}}"#.utf8))
        let signed = try signer.sign(claims)
        let first = try key.seal(signed), second = try key.seal(signed)
        #expect(first != second && SealKey.isSealed(Data(first.utf8)))
        #expect(try SealKey.open(Data(first.utf8), keys: [key]) == signed)
    }
}
