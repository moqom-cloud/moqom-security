// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

import CryptoKit
import Foundation
import Testing

@testable import MoqomMLS

/// The vectors every language passes: Swift's own transcripts, and the files Go
/// generated, which are what check Swift against Go's `crypto/hpke` and Go's
/// group code.
@Suite("MLS shared vectors")
struct SharedVectorTests {
    private let suite = MLSCipherSuite.mls192MLKEM768MLDSA65

    private func failure(_ body: () throws -> Void) -> String? {
        do {
            try body()
            return nil
        } catch let error as MLSError {
            return error.vectorClass
        } catch {
            return "\(error)"
        }
    }

    @Test("labelled primitives", arguments: try Vectors.cases("mls-crypto.json") + Vectors.cases("mls-crypto-go.json") + Vectors.cases("mls-crypto-rust.json"))
    func crypto(_ v: Vector) throws {
        switch v.string("op") {
        case "expand_with_label":
            #expect(suite.expandWithLabel(v.hex("secret_hex"), label: v.string("label"), context: v.hex("context_hex"), length: v.int("length")) == v.hex("out_hex"))
        case "derive_secret":
            #expect(suite.deriveSecret(v.hex("secret_hex"), label: v.string("label")) == v.hex("out_hex"))
        case "ref_hash":
            #expect(suite.refHash(label: v.string("label"), value: v.hex("value_hex")) == v.hex("out_hex"))
        case "sign_with_label":
            let key = try MLDSA65.PrivateKey(seedRepresentation: v.hex("seed_hex"), publicKey: nil)
            #expect(key.publicKey.rawRepresentation == v.hex("public_key_hex"))
            let ok = suite.verifyWithLabel(v.hex("public_key_hex"), label: v.string("label"), content: v.hex("content_hex"), signature: v.hex("signature_hex"))
            #expect(ok == (v.error == nil))
            if v.error == nil {
                let ours = try suite.signWithLabel(v.hex("seed_hex"), label: v.string("label"), content: v.hex("content_hex"))
                #expect(suite.verifyWithLabel(v.hex("public_key_hex"), label: v.string("label"), content: v.hex("content_hex"), signature: ours))
            }
        case "encrypt_with_label":
            let suite = v.has("cipher_suite") ? try #require(MLSCipherSuite(identifier: UInt16(v.int("cipher_suite")))) : suite
            let publicKey = suite == .mls128MLKEM768X25519
                ? try XWingMLKEM768X25519.PrivateKey(seedRepresentation: v.hex("seed_hex"), publicKey: nil).publicKey.rawRepresentation
                : try MLKEM768.PrivateKey(seedRepresentation: v.hex("seed_hex"), publicKey: nil).publicKey.rawRepresentation
            #expect(publicKey == v.hex("public_key_hex"))
            var opened: Data?
            let error = failure {
                opened = try suite.decryptWithLabel(
                    v.hex("seed_hex"), label: v.string("label"), context: v.hex("context_hex"),
                    ciphertext: HPKECiphertext(kemOutput: v.hex("kem_output_hex"), ciphertext: v.hex("ciphertext_hex"))
                )
            }
            #expect(error == v.error)
            if v.error == nil { #expect(opened == v.hex("plaintext_hex")) }
        default:
            Issue.record("unknown op \(v.string("op"))")
        }
    }

    @Test("key schedule", arguments: try Vectors.cases("mls-key-schedule.json"))
    func keySchedule(_ v: Vector) {
        var initSecret = v.hex("initial_init_secret_hex")
        for (index, e) in v.objects("epochs").enumerated() {
            let context = MLSGroupContext(
                cipherSuite: suite, groupID: v.hex("group_id_hex"), epoch: UInt64(index),
                treeHash: e.hex("tree_hash_hex"), confirmedTranscriptHash: e.hex("confirmed_transcript_hash_hex")
            )
            #expect(context.encoded == e.hex("group_context_hex"))
            let s = MLSEpochSecrets.derive(initSecret: initSecret, commitSecret: e.hex("commit_secret_hex"), context: context)
            let expected: [(Data, String)] = [
                (s.joinerSecret, "joiner_secret_hex"), (s.welcomeSecret, "welcome_secret_hex"), (s.epochSecret, "epoch_secret_hex"),
                (s.senderDataSecret, "sender_data_secret_hex"), (s.encryptionSecret, "encryption_secret_hex"),
                (s.exporterSecret, "exporter_secret_hex"), (s.externalSecret, "external_secret_hex"),
                (s.confirmationKey, "confirmation_key_hex"), (s.membershipKey, "membership_key_hex"),
                (s.resumptionPSK, "resumption_psk_hex"), (s.epochAuthenticator, "epoch_authenticator_hex"),
                (s.initSecret, "init_secret_hex"),
            ]
            for (value, key) in expected { #expect(value == e.hex(key), "\(key), epoch \(index)") }
            for x in e.objects("exporters") {
                #expect(s.exporter(label: x.string("label"), context: x.hex("context_hex"), length: x.int("length")) == x.hex("out_hex"))
            }
            initSecret = s.initSecret
        }
    }

    @Test("key packages", arguments: try Vectors.cases("mls-key-packages.json"))
    func keyPackage(_ v: Vector) throws {
        var package: MLSKeyPackage?
        let error = failure {
            package = try MLSKeyPackage.decode(v.hex("key_package_hex"))
            try package!.verify()
        }
        #expect(error == v.error)
        guard v.error == nil, let package else { return }
        let e = v.object("expect")
        #expect(Int(package.cipherSuite.identifier) == e.int("cipher_suite"))
        #expect(package.identityString == e.string("identity"))
        #expect(package.signatureKey == e.hex("signature_key_hex"))
        #expect(package.initKey == e.hex("init_key_hex"))
        #expect(package.encryptionKey == e.hex("encryption_key_hex"))
        #expect(package.reference == e.hex("reference_hex"))
        #expect(package.encoded == v.hex("key_package_hex"))
    }

    @Test("a member follows a group from its Welcome", arguments: try Vectors.cases("mls-group.json") + Vectors.cases("mls-group-go.json"))
    func group(_ v: Vector) throws {
        let m = v.object("member")
        let bundle = MLSKeyPackageBundle(
            keyPackage: try MLSKeyPackage.decode(m.hex("key_package_hex")),
            initPrivate: m.hex("init_private_hex"),
            encryptionPrivate: m.hex("encryption_private_hex"),
            signaturePrivate: m.hex("signature_private_hex")
        )
        var group: MLSGroup?
        for (index, step) in v.objects("steps").enumerated() {
            var removed = false
            let error = failure {
                if step.has("welcome_hex") {
                    group = try MLSGroup.join(try MLSWelcome.decode(step.hex("welcome_hex")), bundle: bundle)
                } else {
                    let current = try #require(group)
                    switch try current.process(try MLSCommitMessage.decode(step.hex("commit_hex"))) {
                    case let .advanced(next): group = next
                    case .removed: removed = true
                    }
                }
            }
            #expect(error == step.error, "step \(index)")
            #expect(removed == step.has("removed"), "step \(index)")
            guard step.has("expect"), let group else { continue }
            let e = step.object("expect")
            #expect(Int(group.epoch) == e.int("epoch"), "step \(index)")
            #expect(Int(group.ownLeaf) == e.int("own_leaf"), "step \(index)")
            #expect(group.members.leaves.map { $0?.identityString } == (e.fields["members"] as! [Any]).map { $0 as? String })
            #expect(group.epochAuthenticator == e.hex("epoch_authenticator_hex"), "step \(index)")
            for x in e.objects("exporters") {
                #expect(group.exporter(label: x.string("label"), context: x.hex("context_hex"), length: x.int("length")) == x.hex("out_hex"))
            }
        }
    }

    @Test("audience envelopes", arguments: try Vectors.cases("mls-audience.json"))
    func audience(_ v: Vector) throws {
        let key = try MLKEM768.PrivateKey(seedRepresentation: v.hex("private_key_hex"), publicKey: nil)
        #expect(key.publicKey.rawRepresentation == v.hex("public_key_hex"))
        var opened: Data?
        let error = failure {
            opened = try MLSAudience.open(v.hex("envelope_hex"), privateKey: v.hex("private_key_hex"), groupID: v.hex("group_id_hex"), epoch: v.uint64("epoch"))
        }
        #expect(error == v.error)
        if v.error == nil { #expect(opened == v.hex("base_key_hex")) }
    }
}
