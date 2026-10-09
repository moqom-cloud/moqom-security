// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

import CryptoKit
import Foundation
import Testing

@testable import MoqomMLS

/// The parts of the MLS subset that claim to be exactly RFC 9420, held to the
/// working group's published vectors. Anything not tested here is not claimed.
///
/// Suite 5 is not implemented; its SHA-512 KDF fields are run through
/// MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87, which shares them. Suite 1's
/// vectors are not: it is an AES-128 suite, and is not implemented.
@Suite("MLS conformance (mlswg/mls-implementations vectors)")
struct PublishedVectorTests {
    private func suite(_ v: Vector) -> MLSCipherSuite {
        precondition(v.int("cipher_suite") == 5)
        return .mls256MLKEM1024MLDSA87
    }

    private static func suite5(_ file: String) throws -> [Vector] {
        try Vectors.cases(file).filter { $0.int("cipher_suite") == 5 }
    }

    @Test("crypto-basics: RefHash, ExpandWithLabel, DeriveSecret, DeriveTreeSecret", arguments: try suite5("mlswg-crypto-basics.json"))
    func kdf(_ v: Vector) throws {
        let suite = suite(v)
        var e = v.object("ref_hash")
        #expect(suite.refHash(label: e.string("label"), value: e.hex("value")) == e.hex("out"))

        e = v.object("expand_with_label")
        #expect(try suite.expandWithLabel(
            e.hex("secret"), label: e.string("label"), context: e.hex("context"), length: e.int("length")
        ) == e.hex("out"))

        e = v.object("derive_secret")
        #expect(suite.deriveSecret(e.hex("secret"), label: e.string("label")) == e.hex("out"))

        // No secret tree is built on this (application data is SFrame), but the
        // vector pins ExpandWithLabel with a non-empty, non-hash context.
        e = v.object("derive_tree_secret")
        var generation = MLSWriter()
        generation.uint32(UInt32(e.int("generation")))
        #expect(try suite.expandWithLabel(
            e.hex("secret"), label: e.string("label"), context: generation.bytes, length: e.int("length")
        ) == e.hex("out"))
    }

    @Test("key-schedule: every epoch, every secret, the GroupContext and the exporter", arguments: try suite5("mlswg-key-schedule.json"))
    func keySchedule(_ v: Vector) throws {
        let suite = suite(v)
        var initSecret = v.hex("initial_init_secret")
        for (index, e) in v.objects("epochs").enumerated() {
            // Suite 5's GroupContext names suite 5, so it is taken as serialised.
            let secrets = MLSEpochSecrets.derive(
                initSecret: initSecret, commitSecret: e.hex("commit_secret"), pskSecret: e.hex("psk_secret"),
                suite: suite, encodedContext: e.hex("group_context")
            )
            #expect(secrets.joinerSecret == e.hex("joiner_secret"), "joiner, epoch \(index)")
            #expect(secrets.welcomeSecret == e.hex("welcome_secret"), "welcome, epoch \(index)")
            #expect(secrets.senderDataSecret == e.hex("sender_data_secret"))
            #expect(secrets.encryptionSecret == e.hex("encryption_secret"))
            #expect(secrets.exporterSecret == e.hex("exporter_secret"))
            #expect(secrets.externalSecret == e.hex("external_secret"))
            #expect(secrets.confirmationKey == e.hex("confirmation_key"))
            #expect(secrets.membershipKey == e.hex("membership_key"))
            #expect(secrets.resumptionPSK == e.hex("resumption_psk"))
            #expect(secrets.epochAuthenticator == e.hex("epoch_authenticator"))
            #expect(secrets.initSecret == e.hex("init_secret"), "init, epoch \(index)")
            #expect(MLSEpochSecrets.welcomeSecret(
                joinerSecret: secrets.joinerSecret, pskSecret: e.hex("psk_secret"), suite: suite
            ) == e.hex("welcome_secret"))

            // The label is a string that happens to look like hex, and is used
            // as its UTF-8 bytes rather than decoded.
            let x = e.object("exporter")
            #expect(try secrets.exporter(
                label: x.string("label"), context: x.hex("context"), length: x.int("length")
            ) == x.hex("secret"), "exporter, epoch \(index)")
            initSecret = secrets.initSecret
        }
    }

    @Test("deserialization: every published vlbytes header, both directions", arguments: try Vectors.cases("mlswg-deserialization.json"))
    func deserialization(_ v: Vector) throws {
        var writer = MLSWriter()
        writer.length(v.int("length"))
        #expect(writer.bytes == v.hex("vlbytes_header"))
        var reader = MLSReader(v.hex("vlbytes_header"))
        #expect(try reader.length() == v.int("length"))
        #expect(reader.isAtEnd)
    }

    @Test("vector lengths use the RFC's minimum-length encoding")
    func variableLengths() throws {
        for count in [0, 63, 64, 16383, 16384] {
            var writer = MLSWriter()
            writer.vector(Data(count: count))
            var reader = MLSReader(writer.bytes)
            #expect(try reader.vector().count == count)
            #expect(reader.isAtEnd)
        }
        // 0x40 0x05 is five encoded in two bytes, which the RFC forbids.
        var reader = MLSReader(Data([0x40, 0x05, 1, 2, 3, 4, 5]))
        #expect(throws: MLSError.self) { _ = try reader.vector() }
    }

    @Test("GroupContext round-trips through its encoding, in every suite", arguments: MLSCipherSuite.supported)
    func groupContextRoundTrip(suite: MLSCipherSuite) throws {
        let context = MLSGroupContext(
            cipherSuite: suite,
            groupID: Data("room".utf8), epoch: 7, treeHash: Data(repeating: 1, count: 32),
            confirmedTranscriptHash: Data(repeating: 2, count: 32)
        )
        var reader = MLSReader(context.encoded)
        #expect(try MLSGroupContext.read(from: &reader) == context)
    }
}
