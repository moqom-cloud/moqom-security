// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

// Behaviour the vectors do not pin: counter ownership, rekeying, key removal
// and resolution.

import Foundation
import Testing

@testable import MoqomSFrame

@Suite("SFrame header")
struct SFrameHeaderTests {
    @Test("small values ride inside the config byte")
    func compactForm() throws {
        // One byte total. This is the case that matters for audio, where the
        // payload is sixty bytes and a five-byte header would be eight percent
        // of the packet.
        let header = SFrameHeader(keyID: 3, counter: 5)
        #expect(header.encoded == Data([0x35]))

        let (parsed, length) = try SFrameHeader.read(from: header.encoded)
        #expect(parsed == header)
        #expect(length == 1)
    }

    @Test("a header inside a larger buffer is read from its start index")
    func slice() throws {
        let buffer = Data([0xFF, 0x99, 0x01, 0x23, 0x45, 0x67, 0xAA])
        let (parsed, length) = try SFrameHeader.read(from: buffer.dropFirst())
        #expect(parsed == SFrameHeader(keyID: 0x0123, counter: 0x4567))
        #expect(length == 5)
    }
}

@Suite("SFrame protection")
struct SFrameProtectionTests {
    private func pair(
        keyID: UInt64 = 1,
        suite: SFrameCipherSuite = .aes256GcmSha512
    ) -> (SFrameSender, SFrameReceiver) {
        let key = SFrameKey(keyID: keyID, baseKey: Data(repeating: 0x2A, count: 32), suite: suite)
        let receiver = SFrameReceiver()
        receiver.add(key)
        return (SFrameSender(key: key), receiver)
    }

    @Test("every frame gets its own counter")
    func countersNeverRepeat() throws {
        // A repeated GCM nonce does not weaken the ciphertext, it breaks it:
        // two frames under one nonce leak their XOR and the authentication
        // subkey. This is why the counter is not something a caller can supply.
        let (sender, receiver) = pair()
        var counters: Set<UInt64> = []
        for index in 0 ..< 200 {
            let sealed = try sender.protect(Data([UInt8(index & 0xFF)]))
            let (header, _) = try SFrameHeader.read(from: sealed)
            counters.insert(header.counter)
            _ = try receiver.unprotect(sealed)
        }
        #expect(counters.count == 200)
        #expect(sender.issuedCounters == 200)
    }

    @Test("a flipped bit anywhere fails")
    func tamperingFails() throws {
        let (sender, receiver) = pair()
        let sealed = try sender.protect(Data(repeating: 0x11, count: 64))
        for index in 1 ..< sealed.count {
            var damaged = sealed
            damaged[damaged.startIndex + index] ^= 0x01
            #expect(throws: SFrameError.self) {
                _ = try receiver.unprotect(damaged)
            }
        }
    }

    @Test("a sender without a key refuses rather than sending in the clear")
    func noKey() throws {
        let sender = SFrameSender()
        #expect(throws: SFrameError.noKey) { _ = try sender.protect(Data([0x01])) }

        let key = SFrameKey(keyID: 2, baseKey: Data(repeating: 0x01, count: 32))
        sender.rekey(key)
        _ = try sender.protect(Data([0x01]))
        #expect(sender.issuedCounters == 1)

        sender.clearKey()
        #expect(sender.key == nil)
        #expect(throws: SFrameError.noKey) { _ = try sender.protect(Data([0x01])) }
    }

    @Test("rekeying restarts the counter under the new KID")
    func rekeyRestartsCounter() throws {
        let (sender, receiver) = pair(keyID: 1)
        _ = try sender.protect(Data([0x01]))
        _ = try sender.protect(Data([0x02]))
        let next = SFrameKey(keyID: 17, baseKey: Data(repeating: 0x2B, count: 32))
        sender.rekey(next)
        receiver.add(next)
        let sealed = try sender.protect(Data([0x03]))
        #expect(try SFrameHeader.read(from: sealed).0 == SFrameHeader(keyID: 17, counter: 0))
        #expect(try receiver.unprotect(sealed) == Data([0x03]))
    }

    @Test("a frame for a key we do not have says so, rather than failing opaquely")
    func unknownKeyIsDistinguishable() throws {
        // Distinguishable *to us*: key distribution and media are separate
        // channels and can race, so the caller is allowed to buffer and retry.
        // An authentication failure is never recoverable and must not be
        // treated the same way.
        let key = SFrameKey(keyID: 9, baseKey: Data(repeating: 0x01, count: 32))
        let sealed = try SFrameSender(key: key).protect(Data([0x01]))

        let receiver = SFrameReceiver()
        #expect(throws: SFrameError.unknownKey(9)) {
            _ = try receiver.unprotect(sealed)
        }

        receiver.add(key)
        #expect(try receiver.unprotect(sealed) == Data([0x01]))
    }

    @Test("removing a key stops anything still in flight under it")
    func removingAKeyRevokes() throws {
        let (sender, receiver) = pair(keyID: 4)
        let sealed = try sender.protect(Data([0x01]))
        receiver.remove(keyID: 4)
        #expect(throws: SFrameError.unknownKey(4)) {
            _ = try receiver.unprotect(sealed)
        }
    }

    @Test("a resolver supplies a key the receiver was never given")
    func resolver() throws {
        let base = Data(repeating: 0x33, count: 32)
        let kid = SFrameKeyID.mls(leaf: 2, epoch: 21)
        let sealed = try SFrameSender(key: SFrameKey(keyID: kid, baseKey: base)).protect(Data([0x07]))

        let receiver = SFrameReceiver()
        receiver.setResolver { keyID in
            SFrameKeyID.epochTag(of: keyID) == 5 ? SFrameKey(keyID: keyID, baseKey: base) : nil
        }
        #expect(try receiver.unprotect(sealed) == Data([0x07]))
        #expect(receiver.keyIDs == [kid])
        #expect(throws: SFrameError.replay(counter: 0)) { _ = try receiver.unprotect(sealed) }

        let elsewhere = try SFrameSender(key: SFrameKey(keyID: SFrameKeyID.mls(leaf: 2, epoch: 22), baseKey: base))
            .protect(Data([0x07]))
        #expect(throws: SFrameError.unknownKey(SFrameKeyID.mls(leaf: 2, epoch: 22))) {
            _ = try receiver.unprotect(elsewhere)
        }
    }

    @Test("metadata overloads bind the same bytes as the raw form")
    func metadataOverloads() throws {
        let (sender, receiver) = pair()
        let metadata = SFrameMetadata(group: 5, object: 2, priority: 64, properties: [.integer(0x78, 1000)])
        let sealed = try sender.protect(Data([0xAB]), metadata: metadata)
        #expect(try receiver.unprotect(sealed, metadata: metadata.encoded()) == Data([0xAB]))

        let invalid = SFrameMetadata(group: 0, object: 0, priority: 0, properties: [.bytes(0x78, Data())])
        #expect(throws: SFrameError.invalidMetadata) { _ = try sender.protect(Data([0xAB]), metadata: invalid) }
    }
}

@Suite("Replay window")
struct ReplayWindowTests {
    @Test("anything ahead of the window is new")
    func forwardIsAlwaysNew() {
        let window = ReplayWindow(size: 64)
        #expect(window.accepts(0))
        window.record(0)
        #expect(!window.accepts(0))
        #expect(window.accepts(1))
        #expect(window.accepts(1_000_000))
    }

    @Test("a counter older than the window is refused")
    func tooOldIsRefused() {
        // The window is what bounds how much reordering is tolerated. Past it,
        // there is no way to tell a very late frame from a replayed one, and
        // the safe answer is to refuse.
        let window = ReplayWindow(size: 8)
        window.record(100)
        #expect(window.accepts(95))
        #expect(!window.accepts(90))
    }

    @Test("every counter in a 1024 window is tracked across word boundaries")
    func fullWindow() {
        let window = ReplayWindow(size: 1024)
        for counter in stride(from: UInt64(5000), through: 3977, by: -1) {
            #expect(window.accepts(counter))
            window.record(counter)
        }
        for counter in UInt64(3977) ... 5000 {
            #expect(!window.accepts(counter))
        }
        #expect(!window.accepts(3976))
        window.record(5063)
        #expect(window.accepts(5001))
        #expect(!window.accepts(4040))
        #expect(!window.accepts(4039))
        window.record(5000 + 2048)
        #expect(window.accepts(6100))
        #expect(!window.accepts(5063))
    }

    @Test("a window above the maximum behaves as the maximum")
    func capped() {
        let window = ReplayWindow(size: .max)
        #expect(window.size == ReplayWindow.maximumSize)
    }
}
