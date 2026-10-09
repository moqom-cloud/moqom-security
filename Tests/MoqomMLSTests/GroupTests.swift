// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

import CryptoKit
import Foundation
import Testing

@testable import MoqomMLS
import MoqomSFrame

/// The group protocol on top of the RFC primitives: what MOQOM claims about
/// membership changes, held to it directly rather than through a room.
@Suite("MLS group")
struct MLSGroupTests {
    private let room = Data("acme/room-42".utf8)

    private func bundle(_ who: String, _ suite: MLSCipherSuite) throws -> MLSKeyPackageBundle {
        try MLSKeyPackageBundle.generate(identity: who, cipherSuite: suite)
    }

    /// A, then B by Welcome, then C by Welcome; every member at the same epoch.
    private func threeMembers(_ suite: MLSCipherSuite) throws -> (MLSGroup, MLSGroup, MLSGroup) {
        var alice = try MLSGroup.create(groupID: room, bundle: bundle("alice/a", suite))
        #expect(alice.cipherSuite == suite)
        let bob = try bundle("bob/b", suite)
        let addBob = try alice.commit(adding: [bob.keyPackage])
        alice = addBob.next
        var bobGroup = try MLSGroup.join(try #require(addBob.welcome), bundle: bob)

        let carol = try bundle("carol/c", suite)
        let addCarol = try alice.commit(adding: [carol.keyPackage])
        alice = addCarol.next
        guard case let .advanced(next) = try bobGroup.process(addCarol.message) else {
            Issue.record("bob was not advanced")
            throw MLSError.notAddressed
        }
        bobGroup = next
        let carolGroup = try MLSGroup.join(try #require(addCarol.welcome), bundle: carol)
        #expect(bobGroup.cipherSuite == suite && carolGroup.cipherSuite == suite)
        return (alice, bobGroup, carolGroup)
    }

    @Test(
        "Add by Welcome: every member derives the same epoch and the same SFrame keys",
        arguments: MLSCipherSuite.supported
    )
    func addAgrees(suite: MLSCipherSuite) throws {
        let (alice, bob, carol) = try threeMembers(suite)
        #expect(alice.epoch == 2 && bob.epoch == 2 && carol.epoch == 2)
        #expect(alice.epochAuthenticator == bob.epochAuthenticator)
        #expect(alice.epochAuthenticator == carol.epochAuthenticator)
        #expect(Set(alice.roster.map(\.member.identityString)) == ["alice/a", "bob/b", "carol/c"])

        let sender = SFrameSender(key: alice.sframeKey(for: alice.ownLeaf, suite: .aes256GcmSha512))
        let sealed = try sender.protectRaw(Data("frame".utf8), aad: Data([1]))
        for member in [bob, carol] {
            let receiver = SFrameReceiver()
            for key in member.sframeKeys(suite: .aes256GcmSha512) { receiver.add(key) }
            #expect(try receiver.unprotectRaw(sealed, aad: Data([1])) == Data("frame".utf8))
        }
    }

    @Test(
        "Remove: the removed member cannot follow, and the new epoch's keys are not theirs",
        arguments: MLSCipherSuite.supported
    )
    func removeIsForwardSecret(suite: MLSCipherSuite) throws {
        let (alice, bob, carol) = try threeMembers(suite)
        let bobLeaf = try #require(alice.leaf(of: "bob/b"))
        let removal = try alice.commit(removing: [bobLeaf])
        #expect(removal.welcome == nil)

        guard case .removed = try bob.process(removal.message) else {
            Issue.record("bob followed his own removal")
            return
        }
        guard case let .advanced(carolNext) = try carol.process(removal.message) else {
            Issue.record("carol was not advanced")
            return
        }
        #expect(carolNext.epochAuthenticator == removal.next.epochAuthenticator)
        #expect(carolNext.memberCount == 2)

        // Everything Bob could still hold is the epoch before. None of it opens
        // a frame from the epoch after.
        let sender = SFrameSender(key: removal.next.sframeKey(for: removal.next.ownLeaf, suite: .aes256GcmSha512))
        let sealed = try sender.protectRaw(Data("after".utf8), aad: Data())
        let bobReceiver = SFrameReceiver()
        for key in bob.sframeKeys(suite: .aes256GcmSha512) { bobReceiver.add(key) }
        #expect(throws: SFrameError.self) { _ = try bobReceiver.unprotectRaw(sealed, aad: Data()) }
        #expect(bob.epochAuthenticator != removal.next.epochAuthenticator)
    }

    @Test("a joiner's keys are not any earlier epoch's", arguments: MLSCipherSuite.supported)
    func joinerCannotReadHistory(suite: MLSCipherSuite) throws {
        var alice = try MLSGroup.create(groupID: room, bundle: bundle("alice/a", suite))
        let before = alice.sframeKey(for: 0, suite: .aes256GcmSha512)
        let sealed = try SFrameSender(key: before).protectRaw(Data("history".utf8), aad: Data())
        let bob = try bundle("bob/b", suite)
        let add = try alice.commit(adding: [bob.keyPackage])
        alice = add.next
        let joined = try MLSGroup.join(try #require(add.welcome), bundle: bob)
        let receiver = SFrameReceiver()
        for key in joined.sframeKeys(suite: .aes256GcmSha512) { receiver.add(key) }
        #expect(throws: SFrameError.self) { _ = try receiver.unprotectRaw(sealed, aad: Data()) }
    }

    @Test(
        "an empty commit is an Update: new epoch, new keys, same members",
        arguments: MLSCipherSuite.supported
    )
    func updateRotates(suite: MLSCipherSuite) throws {
        let (alice, bob, _) = try threeMembers(suite)
        let update = try bob.commit()
        guard case let .advanced(aliceNext) = try alice.process(update.message) else {
            Issue.record("alice was not advanced")
            return
        }
        #expect(aliceNext.epoch == alice.epoch + 1)
        #expect(aliceNext.memberCount == alice.memberCount)
        #expect(aliceNext.epochAuthenticator == update.next.epochAuthenticator)
        #expect(aliceNext.sframeKey(for: 0, suite: .aes256GcmSha512).keyID
            != alice.sframeKey(for: 0, suite: .aes256GcmSha512).keyID)
    }

    @Test("a commit for an epoch already left is refused as stale", arguments: MLSCipherSuite.supported)
    func staleCommitRefused(suite: MLSCipherSuite) throws {
        let (alice, bob, carol) = try threeMembers(suite)
        let first = try alice.commit()
        let second = try bob.commit()
        guard case let .advanced(carolNext) = try carol.process(first.message) else {
            Issue.record("carol was not advanced")
            return
        }
        #expect(throws: MLSError.wrongEpoch(expected: carolNext.epoch, got: second.message.epoch)) {
            _ = try carolNext.process(second.message)
        }
    }

    @Test(
        "a commit with a forged signature or confirmation tag is refused",
        arguments: MLSCipherSuite.supported
    )
    func tamperedCommitRefused(suite: MLSCipherSuite) throws {
        let (alice, bob, _) = try threeMembers(suite)
        let commit = try alice.commit()
        var bytes = commit.message.encoded
        bytes[bytes.index(before: bytes.endIndex)] ^= 1
        let forgedTag = try MLSCommitMessage.decode(bytes)
        #expect(throws: MLSError.confirmationMismatch) { _ = try bob.process(forgedTag) }

        let forgedSignature = MLSCommitMessage(
            groupID: commit.message.groupID, epoch: commit.message.epoch, sender: commit.message.sender,
            commit: commit.message.commit, signature: Data(repeating: 0, count: 64),
            confirmationTag: commit.message.confirmationTag
        )
        #expect(throws: MLSError.badSignature) { _ = try bob.process(forgedSignature) }
    }

    @Test("a key package with a broken signature cannot be added", arguments: MLSCipherSuite.supported)
    func badKeyPackageRefused(suite: MLSCipherSuite) throws {
        let alice = try MLSGroup.create(groupID: room, bundle: bundle("alice/a", suite))
        let bob = try bundle("bob/b", suite).keyPackage
        let forged = MLSKeyPackage(
            cipherSuite: bob.cipherSuite,
            identity: Data("mallory/m".utf8), signatureKey: bob.signatureKey, initKey: bob.initKey,
            encryptionKey: bob.encryptionKey, signature: bob.signature
        )
        #expect(!forged.isValid)
        #expect(throws: MLSError.badSignature) { _ = try alice.commit(adding: [forged]) }
        #expect(try MLSKeyPackage.decode(bob.encoded) == bob)
    }

    @Test("a Welcome opens only for the key package it was made for", arguments: MLSCipherSuite.supported)
    func welcomeAddressed(suite: MLSCipherSuite) throws {
        let alice = try MLSGroup.create(groupID: room, bundle: bundle("alice/a", suite))
        let bob = try bundle("bob/b", suite)
        let other = try bundle("bob/b", suite)
        let add = try alice.commit(adding: [bob.keyPackage])
        let welcome = try MLSWelcome.decode(try #require(add.welcome).encoded)
        #expect(welcome.isAddressed(to: bob.keyPackage))
        #expect(!welcome.isAddressed(to: other.keyPackage))
        #expect(throws: MLSError.notAddressed) { _ = try MLSGroup.join(welcome, bundle: other) }
    }

    @Test("a returning device is removed and re-added in one commit", arguments: MLSCipherSuite.supported)
    func replaceStaleLeaf(suite: MLSCipherSuite) throws {
        let (alice, _, carol) = try threeMembers(suite)
        let stale = try #require(alice.leaf(of: "bob/b"))
        let bobAgain = try bundle("bob/b", suite)
        let commit = try alice.commit(adding: [bobAgain.keyPackage], removing: [stale])
        let rejoined = try MLSGroup.join(try #require(commit.welcome), bundle: bobAgain)
        guard case let .advanced(carolNext) = try carol.process(commit.message) else {
            Issue.record("carol was not advanced")
            return
        }
        #expect(rejoined.epochAuthenticator == carolNext.epochAuthenticator)
        #expect(carolNext.memberCount == 3)
    }

    // MARK: - RFC 9605 §5.2

    @Test("KIDs follow RFC 9605 Figure 9 (E = 4, context 0)")
    func keyIDLayout() {
        #expect(MLSSFrameKeys.keyID(leaf: 3, epoch: 14) == 0x3E)
        #expect(MLSSFrameKeys.keyID(leaf: 7, epoch: 14) == 0x7E)
        #expect(MLSSFrameKeys.keyID(leaf: 20, epoch: 14) == 0x14E)
        #expect(MLSSFrameKeys.keyID(leaf: 3, epoch: 15) == 0x3F)
        #expect(MLSSFrameKeys.keyID(leaf: 5, epoch: 15) == 0x5F)
        #expect(MLSSFrameKeys.keyID(leaf: 33, epoch: 17) == 0x211)
        #expect(MLSSFrameKeys.keyID(leaf: 51, epoch: 17) == 0x331)
        #expect(MLSSFrameKeys.epochTag(ofKeyID: 0x331) == 1)
    }

    @Test(
        "the SFrame base key is the exporter's, with the sender told apart only by KID",
        arguments: MLSCipherSuite.supported
    )
    func baseKeyIsExporter(suite: MLSCipherSuite) throws {
        let (alice, _, _) = try threeMembers(suite)
        let base = try alice.exporter(label: "SFrame 1.0 Base Key", length: 32)
        let sealed = try SFrameSender(key: alice.sframeKey(for: 1, suite: .aes256GcmSha512))
            .protectRaw(Data("x".utf8), aad: Data())
        let receiver = SFrameReceiver()
        receiver.add(try SFrameKey(keyID: MLSSFrameKeys.keyID(leaf: 1, epoch: alice.epoch), baseKey: base))
        #expect(try receiver.unprotectRaw(sealed, aad: Data()) == Data("x".utf8))
    }

    // MARK: - Exporter limit and stored bundles

    @Test("the exporter refuses a length past 255 times the hash length", arguments: MLSCipherSuite.supported)
    func exporterLength(suite: MLSCipherSuite) throws {
        let group = try MLSGroup.create(groupID: room, bundle: bundle("alice/a", suite))
        let maximum = 255 * suite.hashLength
        #expect(try group.exporter(label: "x", length: maximum).count == maximum)
        #expect(try group.exporter(label: "x", length: 0).isEmpty)
        for length in [maximum + 1, 1 << 16, 1 << 17, -1] {
            #expect(throws: MLSError.invalidLength(length: length, maximum: maximum)) {
                try group.exporter(label: "x", length: length)
            }
        }
        do {
            _ = try group.exporter(label: "x", length: maximum + 1)
        } catch {
            #expect(error.errorClass == "invalid-length")
        }
    }

    @Test("ExpandWithLabel refuses a length past 255 times the hash length or out of 16 bits", arguments: MLSCipherSuite.supported)
    func expandWithLabelLength(suite: MLSCipherSuite) throws {
        let secret = Data(repeating: 1, count: suite.hashLength)
        let maximum = 255 * suite.hashLength
        for length in [0, maximum] {
            #expect(try suite.expandWithLabel(secret, label: "x", context: Data(), length: length).count == length)
        }
        for length in [maximum + 1, 1 << 16, 1 << 17, -1, Int.min, Int.max] {
            #expect(throws: MLSError.invalidLength(length: length, maximum: maximum)) {
                try suite.expandWithLabel(secret, label: "x", context: Data(), length: length)
            }
        }
        do {
            _ = try suite.expandWithLabel(secret, label: "x", context: Data(), length: maximum + 1)
        } catch {
            #expect(error.errorClass == "invalid-length")
        }
    }

    @Test("a bundle stored as its key package and private keys joins and follows", arguments: MLSCipherSuite.supported)
    func storedBundle(suite: MLSCipherSuite) throws {
        let alice = try MLSGroup.create(groupID: room, bundle: bundle("alice/a", suite))
        let original = try bundle("bob/b", suite)

        let keys = original.privateKeys
        let restored = MLSKeyPackageBundle(
            keyPackage: try MLSKeyPackage.decode(original.keyPackage.encoded),
            initPrivate: keys.initPrivate,
            encryptionPrivate: keys.encryptionPrivate,
            signaturePrivate: keys.signaturePrivate
        )
        #expect(restored.keyPackage == original.keyPackage)
        #expect(restored.privateKeys == keys)

        let add = try alice.commit(adding: [original.keyPackage])
        var bob = try MLSGroup.join(try #require(add.welcome), bundle: restored)
        #expect(bob.epochAuthenticator == add.next.epochAuthenticator)

        let update = try add.next.commit()
        guard case let .advanced(next) = try bob.process(update.message) else {
            Issue.record("bob was not advanced")
            return
        }
        bob = next
        #expect(bob.epochAuthenticator == update.next.epochAuthenticator)

        let rotate = try bob.commit()
        guard case let .advanced(aliceNext) = try update.next.process(rotate.message) else {
            Issue.record("alice was not advanced")
            return
        }
        #expect(aliceNext.epochAuthenticator == rotate.next.epochAuthenticator)
    }
}
