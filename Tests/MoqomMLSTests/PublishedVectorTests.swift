// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

import CryptoKit
import Foundation
import Testing

@testable import MoqomMLS

/// The parts of the MLS subset that claim to be exactly RFC 9420, held to the
/// working group's published vectors. Anything not tested here is not claimed.
///
/// Suite 7 is not implemented; its SHA-384 KDF fields are run through
/// MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65, which shares them.
@Suite("MLS conformance (mlswg/mls-implementations vectors)")
struct PublishedVectorTests {
    private func suite(_ v: Vector) -> MLSCipherSuite {
        v.int("cipher_suite") == 1 ? .mls128DHKEMX25519 : .mls192MLKEM768MLDSA65
    }

    @Test("crypto-basics: RefHash, ExpandWithLabel, DeriveSecret, DeriveTreeSecret", arguments: try Vectors.cases("mlswg-crypto-basics.json"))
    func kdf(_ v: Vector) {
        let suite = suite(v)
        var e = v.object("ref_hash")
        #expect(suite.refHash(label: e.string("label"), value: e.hex("value")) == e.hex("out"))

        e = v.object("expand_with_label")
        #expect(suite.expandWithLabel(
            e.hex("secret"), label: e.string("label"), context: e.hex("context"), length: e.int("length")
        ) == e.hex("out"))

        e = v.object("derive_secret")
        #expect(suite.deriveSecret(e.hex("secret"), label: e.string("label")) == e.hex("out"))

        // No secret tree is built on this (application data is SFrame), but the
        // vector pins ExpandWithLabel with a non-empty, non-hash context.
        e = v.object("derive_tree_secret")
        var generation = MLSWriter()
        generation.uint32(UInt32(e.int("generation")))
        #expect(suite.expandWithLabel(
            e.hex("secret"), label: e.string("label"), context: generation.bytes, length: e.int("length")
        ) == e.hex("out"))
    }

    @Test("crypto-basics, suite 1: SignWithLabel and EncryptWithLabel")
    func suite1Asymmetric() throws {
        let v = try #require(try Vectors.cases("mlswg-crypto-basics.json").first { $0.int("cipher_suite") == 1 })
        let suite = MLSCipherSuite.mls128DHKEMX25519

        // Ed25519 in CryptoKit is randomised, so our own signature cannot be
        // compared byte for byte; verifying both directions is the check.
        let s = v.object("sign_with_label")
        #expect(suite.verifyWithLabel(s.hex("pub"), label: s.string("label"), content: s.hex("content"), signature: s.hex("signature")))
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: s.hex("priv"))
        #expect(key.publicKey.rawRepresentation == s.hex("pub"))
        let ours = try suite.signWithLabel(s.hex("priv"), label: s.string("label"), content: s.hex("content"))
        #expect(suite.verifyWithLabel(s.hex("pub"), label: s.string("label"), content: s.hex("content"), signature: ours))
        #expect(!suite.verifyWithLabel(s.hex("pub"), label: "Other", content: s.hex("content"), signature: ours))

        let e = v.object("encrypt_with_label")
        let opened = try suite.decryptWithLabel(
            e.hex("priv"), label: e.string("label"), context: e.hex("context"),
            ciphertext: HPKECiphertext(kemOutput: e.hex("kem_output"), ciphertext: e.hex("ciphertext"))
        )
        #expect(opened == e.hex("plaintext"))
        let sealed = try suite.encryptWithLabel(e.hex("pub"), label: e.string("label"), context: e.hex("context"), plaintext: Data("x".utf8))
        #expect(try suite.decryptWithLabel(e.hex("priv"), label: e.string("label"), context: e.hex("context"), ciphertext: sealed) == Data("x".utf8))
    }

    @Test("key-schedule: every epoch, every secret, the GroupContext and the exporter", arguments: try Vectors.cases("mlswg-key-schedule.json"))
    func keySchedule(_ v: Vector) {
        let suite = suite(v)
        var initSecret = v.hex("initial_init_secret")
        for (index, e) in v.objects("epochs").enumerated() {
            if v.int("cipher_suite") == 1 {
                let context = MLSGroupContext(
                    cipherSuite: suite, groupID: v.hex("group_id"), epoch: UInt64(index),
                    treeHash: e.hex("tree_hash"), confirmedTranscriptHash: e.hex("confirmed_transcript_hash")
                )
                #expect(context.encoded == e.hex("group_context"), "group context, epoch \(index)")
            }
            // Suite 7's GroupContext names suite 7, so it is taken as serialised.
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
            #expect(secrets.exporter(
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
