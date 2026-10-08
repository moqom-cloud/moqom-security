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
    ) throws -> (SFrameSender, SFrameReceiver) {
        let key = try SFrameKey(keyID: keyID, baseKey: Data(repeating: 0x2A, count: 32), suite: suite)
        let receiver = SFrameReceiver()
        receiver.add(key)
        return (SFrameSender(key: key), receiver)
    }

    @Test("every frame gets its own counter")
    func countersNeverRepeat() throws {
        // A repeated GCM nonce does not weaken the ciphertext, it breaks it:
        // two frames under one nonce leak their XOR and the authentication
        // subkey. This is why the counter is not something a caller can supply.
        let (sender, receiver) = try pair()
        var counters: Set<UInt64> = []
        for index in 0 ..< 200 {
            let sealed = try sender.protectRaw(Data([UInt8(index & 0xFF)]), aad: Data())
            let (header, _) = try SFrameHeader.read(from: sealed)
            counters.insert(header.counter)
            _ = try receiver.unprotectRaw(sealed, aad: Data())
        }
        #expect(counters.count == 200)
        #expect(sender.issuedCounters == 200)
    }

    @Test("a flipped bit anywhere fails")
    func tamperingFails() throws {
        let (sender, receiver) = try pair()
        let sealed = try sender.protectRaw(Data(repeating: 0x11, count: 64), aad: Data())
        for index in 1 ..< sealed.count {
            var damaged = sealed
            damaged[damaged.startIndex + index] ^= 0x01
            #expect(throws: SFrameError.self) {
                _ = try receiver.unprotectRaw(damaged, aad: Data())
            }
        }
    }

    @Test("a sender without a key refuses rather than sending in the clear")
    func noKey() throws {
        let sender = SFrameSender()
        #expect(throws: SFrameError.noKey) { _ = try sender.protectRaw(Data([0x01]), aad: Data()) }

        let key = try SFrameKey(keyID: 2, baseKey: Data(repeating: 0x01, count: 32))
        sender.rekey(key)
        _ = try sender.protectRaw(Data([0x01]), aad: Data())
        #expect(sender.issuedCounters == 1)

        sender.clearKey()
        #expect(sender.key == nil)
        #expect(throws: SFrameError.noKey) { _ = try sender.protectRaw(Data([0x01]), aad: Data()) }
    }

    @Test("rekeying restarts the counter under the new KID")
    func rekeyRestartsCounter() throws {
        let (sender, receiver) = try pair(keyID: 1)
        _ = try sender.protectRaw(Data([0x01]), aad: Data())
        _ = try sender.protectRaw(Data([0x02]), aad: Data())
        let next = try SFrameKey(keyID: 17, baseKey: Data(repeating: 0x2B, count: 32))
        sender.rekey(next)
        receiver.add(next)
        let sealed = try sender.protectRaw(Data([0x03]), aad: Data())
        #expect(try SFrameHeader.read(from: sealed).0 == SFrameHeader(keyID: 17, counter: 0))
        #expect(try receiver.unprotectRaw(sealed, aad: Data()) == Data([0x03]))
    }

    @Test("a frame for a key we do not have says so, rather than failing opaquely")
    func unknownKeyIsDistinguishable() throws {
        // Distinguishable *to us*: key distribution and media are separate
        // channels and can race, so the caller is allowed to buffer and retry.
        // An authentication failure is never recoverable and must not be
        // treated the same way.
        let key = try SFrameKey(keyID: 9, baseKey: Data(repeating: 0x01, count: 32))
        let sealed = try SFrameSender(key: key).protectRaw(Data([0x01]), aad: Data())

        let receiver = SFrameReceiver()
        #expect(throws: SFrameError.unknownKey(9)) {
            _ = try receiver.unprotectRaw(sealed, aad: Data())
        }

        receiver.add(key)
        #expect(try receiver.unprotectRaw(sealed, aad: Data()) == Data([0x01]))
    }

    @Test("removing a key stops anything still in flight under it")
    func removingAKeyRevokes() throws {
        let (sender, receiver) = try pair(keyID: 4)
        let sealed = try sender.protectRaw(Data([0x01]), aad: Data())
        receiver.remove(keyID: 4)
        #expect(throws: SFrameError.unknownKey(4)) {
            _ = try receiver.unprotectRaw(sealed, aad: Data())
        }
    }

    @Test("a resolver supplies a key the receiver was never given")
    func resolver() throws {
        let base = Data(repeating: 0x33, count: 32)
        let kid = SFrameKeyID.mls(leaf: 2, epoch: 21)
        let sealed = try SFrameSender(key: SFrameKey(keyID: kid, baseKey: base)).protectRaw(Data([0x07]), aad: Data())

        let receiver = SFrameReceiver()
        receiver.setResolver { keyID in
            SFrameKeyID.epochTag(of: keyID) == 5 ? try? SFrameKey(keyID: keyID, baseKey: base) : nil
        }
        #expect(try receiver.unprotectRaw(sealed, aad: Data()) == Data([0x07]))
        #expect(receiver.keyIDs == [kid])
        #expect(throws: SFrameError.replay(counter: 0)) { _ = try receiver.unprotectRaw(sealed, aad: Data()) }

        let elsewhere = try SFrameSender(key: SFrameKey(keyID: SFrameKeyID.mls(leaf: 2, epoch: 22), baseKey: base))
            .protectRaw(Data([0x07]), aad: Data())
        #expect(throws: SFrameError.unknownKey(SFrameKeyID.mls(leaf: 2, epoch: 22))) {
            _ = try receiver.unprotectRaw(elsewhere, aad: Data())
        }
    }

    @Test("a resolved key is kept only once a frame authenticates under it")
    func resolverAfterAuthentication() throws {
        let base = Data(repeating: 0x33, count: 32)
        let receiver = SFrameReceiver()
        receiver.setResolver { keyID in try? SFrameKey(keyID: keyID, baseKey: base) }

        var forged = try SFrameSender(key: SFrameKey(keyID: 40, baseKey: base)).protectRaw(Data([0x07]), aad: Data())
        forged[forged.endIndex - 1] ^= 0x01
        #expect(throws: SFrameError.authenticationFailure) { _ = try receiver.unprotectRaw(forged, aad: Data()) }
        #expect(receiver.keyIDs.isEmpty)
    }

    @Test("metadata overloads bind the same bytes as the raw form")
    func metadataOverloads() throws {
        let (sender, receiver) = try pair()
        let track = SFrameTrack(namespace: ["moqom", "demo", "alice"], name: "video")
        let metadata = SFrameMetadata(track: track, group: 5, object: 2, priority: 64, properties: [.integer(0x78, 1000)])
        let sealed = try sender.protect(Data([0xAB]), metadata: metadata)
        #expect(try receiver.unprotectRaw(sealed, aad: metadata.encoded()) == Data([0xAB]))

        let invalid = SFrameMetadata(track: track, group: 0, object: 0, priority: 0, properties: [.bytes(0x78, Data())])
        #expect(throws: SFrameError.invalidMetadata) { _ = try sender.protect(Data([0xAB]), metadata: invalid) }
    }

    @Test("an object opens only on the track it was sealed for")
    func trackIsBound() throws {
        let (sender, receiver) = try pair()
        let alice = SFrameTrack(namespace: ["moqom", "demo", "alice"], name: "video")
        let bob = SFrameTrack(namespace: ["moqom", "demo", "bob"], name: "video")
        let metadata = SFrameMetadata(track: alice, group: 5, object: 2, priority: 64)
        let sealed = try sender.protect(Data([0xAB]), metadata: metadata)

        var moved = metadata
        moved.track = bob
        #expect(throws: SFrameError.authenticationFailure) { _ = try receiver.unprotect(sealed, metadata: moved) }
        moved.track = SFrameTrack(namespace: ["moqom", "demoalice"], name: "video")
        #expect(throws: SFrameError.authenticationFailure) { _ = try receiver.unprotect(sealed, metadata: moved) }
        moved.track = SFrameTrack(namespace: [Data](), name: Data("video".utf8))
        #expect(throws: SFrameError.invalidMetadata) { _ = try receiver.unprotect(sealed, metadata: moved) }
        #expect(try receiver.unprotect(sealed, metadata: metadata) == Data([0xAB]))
    }

    @Test("installing a key again carries its counter on")
    func rekeySameKeyResumes() throws {
        let key = try SFrameKey(keyID: 5, baseKey: Data(repeating: 0x2A, count: 32))
        let other = try SFrameKey(keyID: 6, baseKey: Data(repeating: 0x2A, count: 32))
        let sender = SFrameSender(key: key)
        var counters: [UInt64] = []
        func seal() throws { counters.append(try SFrameHeader.read(from: sender.protectRaw(Data(), aad: Data())).0.counter) }
        try seal(); try seal()
        sender.rekey(key)
        try seal()
        sender.clearKey()
        sender.rekey(other)
        try seal()
        sender.rekey(key)
        try seal()
        #expect(counters == [0, 1, 2, 0, 3])
    }

    @Test("a base key of the wrong length is refused")
    func baseKeyLength() throws {
        for suite in SFrameCipherSuite.allCases {
            for length in [0, 16, 32, 48] where length != suite.keyLength {
                #expect(throws: SFrameError.invalidBaseKey) {
                    _ = try SFrameKey(keyID: 1, baseKey: Data(count: length), suite: suite)
                }
                #expect(throws: SFrameError.invalidBaseKey) {
                    _ = try SFrameContext(suite: suite, keyID: 1, baseKey: Data(count: length))
                }
            }
            _ = try SFrameKey(keyID: 1, baseKey: Data(count: suite.keyLength), suite: suite)
        }
        #expect(SFrameError.invalidBaseKey.errorClass == "invalid_base_key")
        #expect(SFrameError.replay(counter: 3).errorClass == "replay")
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
