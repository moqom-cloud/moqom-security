// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

// SFrame, RFC 9605.
//
// End-to-end encryption for media, done at the frame rather than the packet.
// The relay forwards ciphertext it cannot read and still schedules it correctly,
// because everything the relay needs — track, group, object, priority, capture
// time, temporal layer — stays outside the encrypted payload and is
// authenticated as additional data. A relay can therefore drop, reorder, and
// prioritise, and cannot alter or forge.
//
// Two notes on what is implemented and what is not.
//
// Only the AES-GCM suites are here (0x0004 and 0x0005). The AES-CTR + HMAC
// suites in the RFC exist for hardware that has AES-CTR and not GCM, and for
// the truncated-tag variants that save bytes on very small audio packets. Every
// platform MOQOM targets has hardware GCM through CryptoKit, and rolling our
// own CTR-then-HMAC composition to save six bytes on an audio packet is a bad
// trade for a security primitive.
//
// The counter must never repeat under a key. That is not a strong
// recommendation, it is the whole security argument for GCM: a repeated nonce
// with a different plaintext leaks the XOR of the plaintexts and, worse, the
// authentication subkey. ``SFrameSender`` owns the counter for exactly this
// reason — there is no API that lets a caller choose one.

import CryptoKit
import Foundation

/// The AEAD and hash a context uses.
public enum SFrameCipherSuite: UInt16, Hashable, Sendable, CaseIterable {
    /// AES-128-GCM with SHA-256. 16-byte tag.
    case aes128GcmSha256 = 0x0004

    /// AES-256-GCM with SHA-512. 16-byte tag. The default.
    ///
    /// The larger key costs nothing measurable on hardware AES and removes a
    /// question nobody wants to answer later about multi-user key separation at
    /// 128 bits.
    case aes256GcmSha512 = 0x0005

    /// Key length in bytes, which is also the length of an MLS-exported base key.
    public var keyLength: Int {
        switch self {
        case .aes128GcmSha256: 16
        case .aes256GcmSha512: 32
        }
    }

    /// Nonce length in bytes. 12 for both, as GCM wants.
    public var nonceLength: Int { 12 }

    /// Authentication tag length in bytes.
    public var tagLength: Int { 16 }
}

/// What went wrong.
public enum SFrameError: Error, Hashable, Sendable {
    /// The header is malformed or the ciphertext is too short to hold one.
    case malformedHeader

    /// No key is loaded for the KID in the header.
    ///
    /// Recoverable: the RFC allows buffering and retrying once the key
    /// arrives, because key distribution and media are separate channels and
    /// can legitimately race.
    case unknownKey(UInt64)

    /// Authentication failed.
    ///
    /// Never distinguish this from any other failure to a caller who might
    /// report it onward. Which frames fail to authenticate is information an
    /// attacker can use.
    case authenticationFailure

    /// This (KID, CTR) has been seen before, or is too old to accept.
    case replay(counter: UInt64)

    /// The counter space for this key is exhausted.
    ///
    /// Fatal by design. Wrapping the counter would reuse a nonce, and reusing a
    /// GCM nonce is catastrophic rather than merely weak, so the only correct
    /// response is to stop and rekey.
    case counterExhausted

    /// No key has been established to send under yet.
    ///
    /// The group is still being set up. The frame is dropped rather than sent
    /// in the clear.
    case noKey

    /// Object metadata that has no canonical encoding; see ``SFrameMetadata``.
    case invalidMetadata
}

/// The KID and CTR that precede an SFrame ciphertext.
public struct SFrameHeader: Hashable, Sendable {
    public let keyID: UInt64
    public let counter: UInt64

    public init(keyID: UInt64, counter: UInt64) {
        self.keyID = keyID
        self.counter = counter
    }

    /// Encoded per RFC 9605 §4.3.
    ///
    /// A value below 8 rides in the config byte itself; anything larger is
    /// appended in the minimum number of bytes. Small KIDs and small counters
    /// therefore cost one byte in total, which matters when the payload is a
    /// 60-byte audio packet.
    public var encoded: Data {
        var config: UInt8 = 0
        var body = Data()

        if keyID < 8 {
            config |= UInt8(keyID) << 4
        } else {
            let bytes = Self.compact(keyID)
            config |= 0x80
            config |= UInt8(bytes.count - 1) << 4
            body.append(bytes)
        }

        if counter < 8 {
            config |= UInt8(counter)
        } else {
            let bytes = Self.compact(counter)
            config |= 0x08
            config |= UInt8(bytes.count - 1)
            body.append(bytes)
        }

        return Data([config]) + body
    }

    /// Parse a header, returning it and how many bytes it took.
    ///
    /// A value in more bytes than it needs is read rather than refused: the
    /// header bytes as received are what the tag authenticates, so a
    /// non-minimal form cannot be produced by anyone without the key.
    public static func read(from data: Data) throws(SFrameError) -> (SFrameHeader, Int) {
        guard let config = data.first else { throw SFrameError.malformedHeader }

        let extendedKeyID = config & 0x80 != 0
        let keyField = Int((config >> 4) & 0x07)
        let extendedCounter = config & 0x08 != 0
        let counterField = Int(config & 0x07)

        var offset = data.startIndex + 1
        let end = data.endIndex

        let keyID: UInt64
        if extendedKeyID {
            let length = keyField + 1
            guard end - offset >= length else { throw SFrameError.malformedHeader }
            keyID = Self.integer(data[offset ..< offset + length])
            offset += length
        } else {
            keyID = UInt64(keyField)
        }

        let counter: UInt64
        if extendedCounter {
            let length = counterField + 1
            guard end - offset >= length else { throw SFrameError.malformedHeader }
            counter = Self.integer(data[offset ..< offset + length])
            offset += length
        } else {
            counter = UInt64(counterField)
        }

        return (SFrameHeader(keyID: keyID, counter: counter), offset - data.startIndex)
    }

    /// Big-endian, minimum length, at least one byte.
    private static func compact(_ value: UInt64) -> Data {
        var bytes = withUnsafeBytes(of: value.bigEndian) { Data($0) }
        while bytes.count > 1, bytes.first == 0 { bytes.removeFirst() }
        return bytes
    }

    private static func integer(_ bytes: some Collection<UInt8>) -> UInt64 {
        bytes.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
    }
}

/// KIDs for keys exported from an MLS group, RFC 9605 §5.2.
///
/// `KID = (context << (S + E)) + (index << E) + (epoch % (1 << E))` with
/// context 0 and E = 4: one SFrame context per member, which is all a MOQOM
/// session needs since a device has one leaf. A receiver holds the current
/// epoch and, briefly, the one before it, so sixteen distinguishable epochs is
/// far more than is live at once.
public enum SFrameKeyID {
    public static let epochBits: UInt64 = 4

    public static func mls(leaf: UInt32, epoch: UInt64) -> UInt64 {
        (UInt64(leaf) << epochBits) | (epoch & ((1 << epochBits) - 1))
    }

    /// The low bits of an epoch as a KID carries them.
    public static func epochTag(of keyID: UInt64) -> UInt64 {
        keyID & ((1 << epochBits) - 1)
    }

    /// The label an MLS group exports an epoch's `base_key` under, with an
    /// empty context and `AEAD.Nk` bytes (``SFrameCipherSuite/keyLength``).
    public static let mlsExporterLabel = "SFrame 1.0 Base Key"
}

/// A key and salt derived from a base key for one KID.
public struct SFrameKey: Sendable {
    public let keyID: UInt64
    public let suite: SFrameCipherSuite
    let key: SymmetricKey
    let salt: Data

    /// Derive per RFC 9605 §4.4.2.
    ///
    /// The KID and cipher suite are inside the derivation labels rather than
    /// only in the header, which is what stops a ciphertext produced under one
    /// KID or suite from ever authenticating under another.
    public init(keyID: UInt64, baseKey: Data, suite: SFrameCipherSuite = .aes256GcmSha512) {
        self.keyID = keyID
        self.suite = suite

        let keyLabel = Self.label("SFrame 1.0 Secret key ", keyID: keyID, suite: suite)
        let saltLabel = Self.label("SFrame 1.0 Secret salt ", keyID: keyID, suite: suite)

        switch suite {
        case .aes128GcmSha256:
            let secret = HKDF<SHA256>.extract(
                inputKeyMaterial: SymmetricKey(data: baseKey), salt: Data()
            )
            key = HKDF<SHA256>.expand(
                pseudoRandomKey: secret, info: keyLabel, outputByteCount: suite.keyLength
            )
            salt = HKDF<SHA256>.expand(
                pseudoRandomKey: secret, info: saltLabel, outputByteCount: suite.nonceLength
            ).withUnsafeBytes { Data($0) }
        case .aes256GcmSha512:
            let secret = HKDF<SHA512>.extract(
                inputKeyMaterial: SymmetricKey(data: baseKey), salt: Data()
            )
            key = HKDF<SHA512>.expand(
                pseudoRandomKey: secret, info: keyLabel, outputByteCount: suite.keyLength
            )
            salt = HKDF<SHA512>.expand(
                pseudoRandomKey: secret, info: saltLabel, outputByteCount: suite.nonceLength
            ).withUnsafeBytes { Data($0) }
        }
    }

    static func label(_ prefix: String, keyID: UInt64, suite: SFrameCipherSuite) -> Data {
        var label = Data(prefix.utf8)
        label.append(contentsOf: withUnsafeBytes(of: keyID.bigEndian) { Data($0) })
        label.append(contentsOf: withUnsafeBytes(of: suite.rawValue.bigEndian) { Data($0) })
        return label
    }

    /// The salt XORed with the counter, big-endian.
    func nonce(counter: UInt64) -> Data {
        var bytes = Data(repeating: 0, count: suite.nonceLength)
        let counterBytes = withUnsafeBytes(of: counter.bigEndian) { Data($0) }
        // The counter occupies the low-order end; the high-order bytes of the
        // salt pass through unchanged.
        let offset = bytes.count - counterBytes.count
        for index in 0 ..< bytes.count {
            let saltByte = salt[salt.startIndex + index]
            let counterByte = index >= offset
                ? counterBytes[counterBytes.startIndex + index - offset]
                : 0
            bytes[index] = saltByte ^ counterByte
        }
        return bytes
    }

    func seal(_ plaintext: Data, counter: UInt64, aad: Data) throws(SFrameError) -> Data {
        do {
            let sealed = try AES.GCM.seal(
                plaintext,
                using: key,
                nonce: AES.GCM.Nonce(data: nonce(counter: counter)),
                authenticating: aad
            )
            return sealed.ciphertext + sealed.tag
        } catch {
            throw SFrameError.authenticationFailure
        }
    }

    func open(_ ciphertext: Data, counter: UInt64, aad: Data) throws(SFrameError) -> Data {
        guard ciphertext.count >= suite.tagLength else {
            throw SFrameError.authenticationFailure
        }
        let split = ciphertext.index(ciphertext.endIndex, offsetBy: -suite.tagLength)
        do {
            let box = try AES.GCM.SealedBox(
                nonce: AES.GCM.Nonce(data: nonce(counter: counter)),
                ciphertext: ciphertext[..<split],
                tag: ciphertext[split...]
            )
            return try AES.GCM.open(box, using: key, authenticating: aad)
        } catch {
            throw SFrameError.authenticationFailure
        }
    }
}

/// Encrypts, owning the counter.
///
/// One sender per (key, media stream). Sharing one across two streams is safe
/// and sharing a *key* across two senders is not, because two independent
/// counters under one key will collide.
///
/// Managed key management rotates the key in place with ``rekey(_:)``. The
/// counter restarts with each key, which is safe because the nonce is the
/// key's own salt XOR the counter and the key is new.
public final class SFrameSender: @unchecked Sendable {
    private let lock = NSLock()
    private var current: SFrameKey?
    private var counter: UInt64 = 0

    public init(key: SFrameKey) {
        current = key
    }

    /// A sender with no key yet, which refuses to encrypt until it gets one.
    ///
    /// For a member whose group has not been established. Refusing is the
    /// point: the alternative is publishing plaintext into a room that is
    /// supposed to be end-to-end encrypted.
    public init() {}

    /// The key in force, or `nil` before the first one arrives.
    public var key: SFrameKey? {
        lock.withLock { current }
    }

    /// Counters issued under the current key. For deciding when to rekey.
    public var issuedCounters: UInt64 {
        lock.withLock { counter }
    }

    /// Switch to a new key. Frames already sealed keep their old KID and
    /// decrypt for as long as receivers hold the old key.
    public func rekey(_ key: SFrameKey) {
        lock.withLock {
            current = key
            counter = 0
        }
    }

    /// Go back to having no key, so frames are refused rather than sealed.
    ///
    /// For a member that has left or lost its group: carrying on under the old
    /// epoch's key would publish media that members who moved on discard, and
    /// would keep using a key the group has finished with.
    public func clearKey() {
        lock.withLock {
            current = nil
            counter = 0
        }
    }

    /// Encrypt one MoQ object, binding its metadata into the tag.
    public func protect(_ plaintext: Data, metadata: SFrameMetadata) throws(SFrameError) -> Data {
        try protect(plaintext, metadata: metadata.encoded())
    }

    /// Encrypt one frame.
    ///
    /// - Parameter metadata: Authenticated but not encrypted. Whatever the
    ///   relay is allowed to read and must not be able to change.
    public func protect(_ plaintext: Data, metadata: Data = Data()) throws(SFrameError) -> Data {
        lock.lock()
        guard let key = current else {
            lock.unlock()
            throw SFrameError.noKey
        }
        let issued = counter
        guard issued < UInt64.max else {
            lock.unlock()
            throw SFrameError.counterExhausted
        }
        counter = issued + 1
        lock.unlock()

        let header = SFrameHeader(keyID: key.keyID, counter: issued).encoded
        let ciphertext = try key.seal(plaintext, counter: issued, aad: header + metadata)
        return header + ciphertext
    }
}

/// Decrypts, holding keys for one or more KIDs and rejecting replays.
public final class SFrameReceiver: @unchecked Sendable {
    /// How far back a counter may be and still be accepted.
    ///
    /// Reordering is normal on a network, so a strict "must increase" rule
    /// would discard perfectly good frames. The window bounds how much
    /// out-of-order delivery is tolerated before a frame is assumed to be a
    /// replay. Windows above 65536 behave as 65536.
    public let replayWindow: UInt64

    private let lock = NSLock()
    private var keys: [UInt64: SFrameKey] = [:]
    private var seen: [UInt64: ReplayWindow] = [:]
    private var resolver: (@Sendable (UInt64) -> SFrameKey?)?

    public init(replayWindow: UInt64 = 1024) {
        self.replayWindow = replayWindow
    }

    /// Asked for a key the receiver does not hold, before giving up on a frame.
    ///
    /// For key schemes where a receiver can derive a sender's next key without
    /// being sent it — a sender-key ratchet — so a sender can move forward
    /// without a distribution message per step. A key it returns is added as
    /// though ``add(_:)`` had been called.
    public func setResolver(_ resolve: (@Sendable (UInt64) -> SFrameKey?)?) {
        lock.withLock { resolver = resolve }
    }

    /// The KIDs currently loaded.
    public var keyIDs: Set<UInt64> {
        lock.withLock { Set(keys.keys) }
    }

    public func add(_ key: SFrameKey) {
        lock.lock()
        defer { lock.unlock() }
        keys[key.keyID] = key
        seen[key.keyID] = ReplayWindow(size: replayWindow)
    }

    /// Forget a key.
    ///
    /// Anything still in flight under it stops decrypting, which is the point:
    /// this is what removing a participant from a group means.
    public func remove(keyID: UInt64) {
        lock.lock()
        defer { lock.unlock() }
        keys[keyID] = nil
        seen[keyID] = nil
    }

    /// Decrypt one MoQ object against the metadata it arrived with.
    public func unprotect(_ data: Data, metadata: SFrameMetadata) throws(SFrameError) -> Data {
        try unprotect(data, metadata: metadata.encoded())
    }

    /// Decrypt one frame.
    public func unprotect(_ data: Data, metadata: Data = Data()) throws(SFrameError) -> Data {
        let (header, length) = try SFrameHeader.read(from: data)

        lock.lock()
        if keys[header.keyID] == nil, let resolver {
            lock.unlock()
            let resolved = resolver(header.keyID)
            lock.lock()
            if let resolved, resolved.keyID == header.keyID, keys[header.keyID] == nil {
                keys[header.keyID] = resolved
                seen[header.keyID] = ReplayWindow(size: replayWindow)
            }
        }
        guard let key = keys[header.keyID] else {
            lock.unlock()
            throw SFrameError.unknownKey(header.keyID)
        }
        let window = seen[header.keyID] ?? ReplayWindow(size: replayWindow)
        seen[header.keyID] = window
        guard window.accepts(header.counter) else {
            lock.unlock()
            throw SFrameError.replay(counter: header.counter)
        }
        lock.unlock()

        let aad = data.prefix(length) + metadata
        let plaintext = try key.open(data.dropFirst(length), counter: header.counter, aad: aad)

        // Recorded only after authentication. Marking a counter used on a frame
        // that failed to authenticate would let anyone with a forged frame
        // knock out the real one behind it.
        lock.lock()
        if seen[header.keyID] === window {
            window.record(header.counter)
        }
        lock.unlock()

        return plaintext
    }
}

/// A sliding window of counters already seen.
///
/// The bitmap is a ring of 64-bit words indexed by counter, with one word more
/// than the window needs: advancing clears whole words, and the spare word is
/// what keeps that from clearing a counter still inside the window.
///
/// Only touched under ``SFrameReceiver``'s lock.
final class ReplayWindow: @unchecked Sendable {
    /// The largest window honoured, so a configuration mistake cannot ask for
    /// gigabytes of bitmap per KID. 8 KiB per KID at the cap.
    static let maximumSize: UInt64 = 1 << 16

    let size: UInt64
    private var highest: UInt64?
    private var words: [UInt64]

    init(size: UInt64) {
        self.size = min(size, Self.maximumSize)
        words = Array(repeating: 0, count: Int((self.size + 63) / 64) + 1)
    }

    private func slot(_ counter: UInt64) -> (word: Int, bit: UInt64) {
        (Int((counter / 64) % UInt64(words.count)), 1 << (counter % 64))
    }

    /// Whether a counter is new enough and has not been seen.
    func accepts(_ counter: UInt64) -> Bool {
        guard let highest else { return true }
        if counter > highest { return true }
        guard highest - counter < size else { return false }
        let (word, bit) = slot(counter)
        return words[word] & bit == 0
    }

    func record(_ counter: UInt64) {
        if let current = highest {
            if counter > current {
                let advanced = counter / 64 - current / 64
                if advanced >= UInt64(words.count) {
                    for index in words.indices { words[index] = 0 }
                } else if advanced > 0 {
                    for block in current / 64 + 1 ... counter / 64 {
                        words[Int(block % UInt64(words.count))] = 0
                    }
                }
                highest = counter
            } else if current - counter >= size {
                return
            }
        } else {
            highest = counter
        }
        let (word, bit) = slot(counter)
        words[word] |= bit
    }
}
