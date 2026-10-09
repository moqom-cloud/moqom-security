// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

// Every case in vectors/sframe, the RFC's and ours.

import CryptoKit
import Foundation
import Testing

@testable import MoqomSFrame

private func suite(_ raw: UInt16) throws -> SFrameCipherSuite {
    try #require(SFrameCipherSuite(rawValue: raw))
}

private func outcome(_ body: () throws(SFrameError) -> Data) -> Result<Data, SFrameError> {
    do { return .success(try body()) } catch { return .failure(error) }
}

private func expect(_ result: Result<Data, SFrameError>, pt: String?, error: String?, _ name: String) {
    switch result {
    case let .success(plaintext):
        #expect(error == nil, "\(name): opened, expected \(error ?? "")")
        #expect(plaintext.hexString == pt, "\(name)")
    case let .failure(failure):
        #expect(failure.errorClass == error, "\(name): \(failure)")
    }
}

@Suite("SFrame vectors: RFC 9605 Appendix C")
struct RFC9605VectorTests {
    let cases: [RFCCase]

    init() throws {
        cases = try loadVectors("rfc9605.json", as: RFCCase.self).cases
    }

    @Test("C.1 header encoding and decoding")
    func headers() throws {
        let headers = cases.filter { $0.kind == "header" }
        #expect(headers.count == 289)
        for vector in headers {
            let header = SFrameHeader(keyID: try #require(vector.kid), counter: try #require(vector.ctr))
            #expect(header.encoded.hexString == vector.header_hex, "\(vector.name)")
            let (parsed, length) = try SFrameHeader.read(from: hex(try #require(vector.header_hex)))
            #expect(parsed == header, "\(vector.name)")
            #expect(length == header.encoded.count)
        }
    }

    @Test("C.3 SFrame encryption and decryption, AES-256-GCM")
    func sframe() throws {
        let vectors = cases.filter { $0.kind == "sframe" && $0.skip == nil }
        #expect(vectors.map(\.cipher_suite) == [0x0005])
        for vector in vectors {
            let suite = try suite(try #require(vector.cipher_suite))
            let kid = try #require(vector.kid), ctr = try #require(vector.ctr)
            let base = hex(try #require(vector.base_key_hex))
            let metadata = hex(try #require(vector.metadata_hex))
            let key = SFrameKey(keyID: kid, uncheckedBaseKey: base, suite: suite)

            #expect(SFrameKey.label("SFrame 1.0 Secret key ", keyID: kid, suite: suite).hexString == vector.sframe_key_label_hex)
            #expect(SFrameKey.label("SFrame 1.0 Secret salt ", keyID: kid, suite: suite).hexString == vector.sframe_salt_label_hex)
            #expect(key.key.withUnsafeBytes { Data($0) }.hexString == vector.sframe_key_hex)
            #expect(key.salt.hexString == vector.sframe_salt_hex)
            #expect(key.nonce(counter: ctr).hexString == vector.nonce_hex)

            let header = SFrameHeader(keyID: kid, counter: ctr).encoded
            #expect((header + metadata).hexString == vector.aad_hex)
            let ct = try header + key.seal(hex(try #require(vector.pt_hex)), counter: ctr, aad: header + metadata)
            #expect(ct.hexString == vector.ct_hex, "\(vector.name)")

            let receiver = SFrameReceiver()
            receiver.add(key)
            #expect(try receiver.unprotectRaw(hex(try #require(vector.ct_hex)), aad: metadata).hexString == vector.pt_hex)
        }
    }

    @Test("C.3's sframe_secret is HKDF-Extract of the base key")
    func secret() throws {
        for vector in cases where vector.kind == "sframe" && vector.skip == nil {
            let base = SymmetricKey(data: hex(try #require(vector.base_key_hex)))
            #expect(try suite(try #require(vector.cipher_suite)) == .aes256GcmSha512)
            let secret = HKDF<SHA512>.extract(inputKeyMaterial: base, salt: Data()).withUnsafeBytes { Data($0) }
            #expect(secret.hexString == vector.sframe_secret_hex)
        }
    }

    @Test("every skipped case is AES-CTR + HMAC or the refused AES-128-GCM")
    func skipped() {
        let skipped = cases.filter { $0.skip != nil }
        #expect(skipped.count == 7)
        #expect(skipped.allSatisfy { [1, 2, 3, 4].contains($0.cipher_suite ?? 0) })
    }

    @Test("AES-128-GCM is refused, not negotiated down to")
    func aes128Refused() {
        #expect(SFrameCipherSuite(rawValue: 0x0004) == nil)
        #expect(SFrameCipherSuite.allCases == [.aes256GcmSha512])
    }
}

@Suite("SFrame vectors: MoQ")
struct MoQVectorTests {
    @Test("metadata.json")
    func metadata() throws {
        for vector in try loadVectors("metadata.json", as: MetadataCase.self).cases {
            let result = outcome { () throws(SFrameError) in try vector.metadata.metadata.encoded() }
            switch result {
            case let .success(bytes): #expect(bytes.hexString == vector.encoded_hex, "\(vector.name)")
            case let .failure(error): #expect(error.errorClass == vector.error, "\(vector.name)")
            }
            #expect((vector.encoded_hex == nil) != (vector.error == nil))
        }
    }

    @Test("kid.json")
    func keyIDs() throws {
        for vector in try loadVectors("kid.json", as: KeyIDCase.self).cases {
            #expect(SFrameKeyID.mls(leaf: vector.leaf, epoch: vector.epoch) == vector.kid, "\(vector.name)")
            #expect(SFrameKeyID.epochTag(of: vector.kid) == vector.epoch_tag)
            #expect(SFrameHeader(keyID: vector.kid, counter: 0).encoded.hexString == vector.header_hex)
        }
    }

    @Test("nonce.json")
    func nonces() throws {
        for vector in try loadVectors("nonce.json", as: NonceCase.self).cases {
            let key = try SFrameKey(keyID: vector.kid, baseKey: hex(vector.base_key_hex), suite: try suite(vector.cipher_suite))
            #expect(key.key.withUnsafeBytes { Data($0) }.hexString == vector.sframe_key_hex, "\(vector.name)")
            #expect(key.salt.hexString == vector.sframe_salt_hex)
            #expect(key.nonce(counter: vector.ctr).hexString == vector.nonce_hex, "\(vector.name)")
            #expect(SFrameHeader(keyID: vector.kid, counter: vector.ctr).encoded.hexString == vector.header_hex)
        }
    }

    @Test("seal-open.json")
    func seals() throws {
        for vector in try loadVectors("seal-open.json", as: SealCase.self).cases {
            let suite = try suite(vector.cipher_suite)
            let sealer = try SFrameContext(suite: suite, keyID: vector.kid, baseKey: hex(vector.base_key_hex))
            let opener = try SFrameContext(suite: suite, keyID: vector.kid, baseKey: hex(vector.base_key_hex))
            let metadata = vector.metadata.metadata
            for seal in vector.seals {
                #expect(try sealer.seal(hex(seal.pt_hex), metadata: metadata).hexString == seal.object_hex, "\(vector.name)")
                #expect(try opener.open(hex(seal.object_hex), metadata: metadata).hexString == seal.pt_hex, "\(vector.name)")
            }
        }
    }

    @Test("open.json")
    func opens() throws {
        for vector in try loadVectors("open.json", as: OpenCase.self).cases {
            let context = try SFrameContext(suite: try suite(vector.cipher_suite), keyID: vector.kid, baseKey: hex(vector.base_key_hex))
            let metadata = vector.metadata.metadata
            let result = outcome { () throws(SFrameError) in try context.open(hex(vector.object_hex), metadata: metadata) }
            expect(result, pt: vector.pt_hex, error: vector.error, vector.name)
        }
    }

    @Test("replay.json")
    func replays() throws {
        for vector in try loadVectors("replay.json", as: ReplayCase.self).cases {
            let context = try SFrameContext(
                suite: try suite(vector.cipher_suite),
                keyID: vector.kid,
                baseKey: hex(vector.base_key_hex),
                replayWindow: vector.replay_window
            )
            let metadata = vector.metadata.metadata
            for (index, step) in vector.steps.enumerated() {
                let result = outcome { () throws(SFrameError) in try context.open(hex(step.object_hex), metadata: metadata) }
                expect(result, pt: step.pt_hex, error: step.error, "\(vector.name) step \(index)")
            }
        }
    }
}
