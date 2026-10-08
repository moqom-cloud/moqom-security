// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

import Foundation

/// One SFrame key, for sealing and opening MoQ objects under it.
///
/// The simplest use: both ends hold the same base key and KID. Sealing owns the
/// counter and opening keeps the replay window, exactly as ``SFrameSender`` and
/// ``SFrameReceiver`` do; a room with a key per sender uses those directly.
///
/// The counter starts at 0 for every new context. Never create two contexts
/// that seal under the same base key and KID, including one after a restart;
/// see ``SFrameSender``.
public final class SFrameContext: Sendable {
    public let key: SFrameKey
    private let sender: SFrameSender
    private let receiver: SFrameReceiver

    /// - Throws: ``SFrameError/invalidBaseKey`` unless `baseKey` is
    ///   ``SFrameCipherSuite/keyLength`` bytes.
    public init(
        suite: SFrameCipherSuite = .aes256GcmSha512,
        keyID: UInt64,
        baseKey: Data,
        replayWindow: UInt64 = 1024
    ) throws(SFrameError) {
        key = try SFrameKey(keyID: keyID, baseKey: baseKey, suite: suite)
        sender = SFrameSender(key: key)
        receiver = SFrameReceiver(replayWindow: replayWindow)
        receiver.add(key)
    }

    /// The SFrame object: header, ciphertext, tag.
    public func seal(_ payload: Data, metadata: SFrameMetadata) throws(SFrameError) -> Data {
        try sender.protect(payload, metadata: metadata)
    }

    /// The payload, if `object` authenticates under this key with `metadata`
    /// and its counter has not been seen.
    public func open(_ object: Data, metadata: SFrameMetadata) throws(SFrameError) -> Data {
        try receiver.unprotect(object, metadata: metadata)
    }
}
