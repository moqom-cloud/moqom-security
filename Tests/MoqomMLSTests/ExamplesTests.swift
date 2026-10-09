// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

import Foundation
import MoqomMLS
import MoqomSFrame
import Testing

/// The examples on moqom.dev, through the public API only.
@Suite("MLS examples")
struct ExamplesTests {
    /// Alice founds a group and adds Bob from his key package. Bob joins from
    /// the Welcome, Alice rotates her leaf key with an empty commit, and both
    /// end on the same epoch with the same epoch authenticator and SFrame keys.
    @Test func group() throws {
        let room = Data("acme/room-42".utf8)
        let alice = try MLSKeyPackageBundle.generate(identity: "alice/phone")
        let bob = try MLSKeyPackageBundle.generate(identity: "bob/laptop")

        // Alice reads Bob's published key package and commits to add him.
        let bobPackage = try MLSKeyPackage.decode(bob.keyPackage.encoded)
        try bobPackage.verify()
        var aliceGroup = try MLSGroup.create(groupID: room, bundle: alice)
        let add = try aliceGroup.commit(adding: [bobPackage])
        aliceGroup = add.next // once the delivery service accepts add.message

        // Bob joins from the Welcome.
        let welcome = try MLSWelcome.decode(try #require(add.welcome).encoded)
        var bobGroup = try MLSGroup.join(welcome, bundle: bob)

        // An empty commit refreshes Alice's leaf key; Bob follows it.
        let update = try aliceGroup.commit()
        aliceGroup = update.next
        guard case let .advanced(next) = try bobGroup.process(MLSCommitMessage.decode(update.message.encoded)) else {
            Issue.record("Bob was removed")
            return
        }
        bobGroup = next

        #expect(aliceGroup.epoch == 2 && bobGroup.epoch == 2)
        #expect(aliceGroup.epochAuthenticator == bobGroup.epochAuthenticator)
        #expect(aliceGroup.sframeBaseKey(suite: .aes256GcmSha512)
            == (try bobGroup.exporter(label: "SFrame 1.0 Base Key", length: 32)))

        // Alice sends under her own KID; Bob holds every member's key.
        let sender = SFrameSender(key: aliceGroup.sframeKey(for: aliceGroup.ownLeaf, suite: .aes256GcmSha512))
        let receiver = SFrameReceiver()
        for key in bobGroup.sframeKeys(suite: .aes256GcmSha512) { receiver.add(key) }
        let track = SFrameTrack(namespace: ["moqom", "demo", "alice"], name: "video")
        let metadata = SFrameMetadata(track: track, group: 0, object: 0, priority: 128)
        let object = try sender.protect(Data("hello".utf8), metadata: metadata)
        #expect(try receiver.unprotect(object, metadata: metadata) == Data("hello".utf8))
    }

    /// Removing a member: the removed member's `process` returns `.removed`.
    @Test func remove() throws {
        let alice = try MLSKeyPackageBundle.generate(identity: "alice/phone")
        let bob = try MLSKeyPackageBundle.generate(identity: "bob/laptop")
        let aliceGroup = try MLSGroup.create(groupID: Data("acme/room-42".utf8), bundle: alice)
        let add = try aliceGroup.commit(adding: [bob.keyPackage])
        let bobGroup = try MLSGroup.join(try #require(add.welcome), bundle: bob)

        let leaf = try #require(add.next.leaf(of: "bob/laptop"))
        let removal = try add.next.commit(removing: [leaf])
        guard case .removed = try bobGroup.process(removal.message) else {
            Issue.record("Bob followed his own removal")
            return
        }
    }

    /// A broadcast viewer is not a member. The committer seals each epoch's
    /// SFrame base key to the viewer's ML-KEM-1024 key, for one group and epoch.
    @Test func audience() throws {
        let groupID = Data("acme/room-42".utf8)
        let base = Data(count: 32) // from group.sframeBaseKey(suite: .aes256GcmSha512)

        let viewer = try MLSAudience.generateKeyPair()
        let envelope = try MLSAudience.seal(base, to: viewer.publicKey, groupID: groupID, epoch: 7)

        #expect(try MLSAudience.open(envelope, privateKey: viewer.privateKey, groupID: groupID, epoch: 7) == base)
        #expect(throws: MLSError.decryptionFailed) {
            try MLSAudience.open(envelope, privateKey: viewer.privateKey, groupID: groupID, epoch: 8)
        }
    }
}
