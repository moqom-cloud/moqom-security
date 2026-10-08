// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

// The examples on moqom.dev, run as tests so they cannot go stale.

import Foundation
import MoqomSFrame
import Testing

@Suite("SFrame examples")
struct ExamplesTests {
    @Test("seal and open a MoQ object, refusing tampering and replay")
    func sealAndOpen() throws {
        // In a room the base key is exported from the MLS group under
        // SFrameKeyID.mlsExporterLabel. Both ends derive the same key from it.
        let baseKey = Data(repeating: 0x2A, count: 32)
        let key = SFrameKey(keyID: SFrameKeyID.mls(leaf: 3, epoch: 14), baseKey: baseKey)
        let sender = SFrameSender(key: key)
        let receiver = SFrameReceiver()
        receiver.add(key)

        let metadata = SFrameMetadata(group: 5, object: 2, priority: 64, properties: [
            .integer(0x78, 1_000_000), // capture time
            .integer(0x7A, 1), // temporal layer
        ])
        let object = try sender.protect(Data("frame".utf8), metadata: metadata)
        #expect(object.prefix(2) == Data([0x80, 0x3E])) // KID 62, counter 0
        #expect(object.count == 2 + 5 + 16)

        // A relay that relabels the object's group, or flips a bit, is caught.
        var moved = metadata
        moved.group = 6
        #expect(throws: SFrameError.authenticationFailure) {
            try receiver.unprotect(object, metadata: moved)
        }
        var damaged = object
        damaged[damaged.endIndex - 1] ^= 0x01
        #expect(throws: SFrameError.authenticationFailure) {
            try receiver.unprotect(damaged, metadata: metadata)
        }

        // Neither failure used up the counter, so the real object still opens.
        #expect(try receiver.unprotect(object, metadata: metadata) == Data("frame".utf8))
        #expect(throws: SFrameError.replay(counter: 0)) {
            try receiver.unprotect(object, metadata: metadata)
        }
    }

    @Test("the replay window accepts reordering up to 1,023 behind")
    func replayWindow() throws {
        let context = SFrameContext(
            suite: .aes128GcmSha256, keyID: 1, baseKey: Data(repeating: 0x2A, count: 16)
        )
        let metadata = SFrameMetadata(group: 0, object: 0, priority: 128)
        let objects = try (0 ... 1024).map { counter in
            try context.seal(Data([UInt8(truncatingIfNeeded: counter)]), metadata: metadata)
        }

        _ = try context.open(objects[1024], metadata: metadata)
        _ = try context.open(objects[1], metadata: metadata) // 1,023 behind: accepted
        #expect(throws: SFrameError.replay(counter: 0)) { // 1,024 behind: refused
            try context.open(objects[0], metadata: metadata)
        }
        #expect(throws: SFrameError.replay(counter: 1)) { // already seen
            try context.open(objects[1], metadata: metadata)
        }
    }
}
