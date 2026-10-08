// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

import Foundation

/// One SFrame key, for sealing and opening MoQ objects under it.
///
/// The simplest use: both ends hold the same base key and KID. Sealing owns the
/// counter and opening keeps the replay window, exactly as ``SFrameSender`` and
/// ``SFrameReceiver`` do; a room with a key per sender uses those directly.
public final class SFrameContext: Sendable {
    public let key: SFrameKey
    private let sender: SFrameSender
    private let receiver: SFrameReceiver

    public init(
        suite: SFrameCipherSuite = .aes256GcmSha512,
        keyID: UInt64,
        baseKey: Data,
        replayWindow: UInt64 = 1024
    ) {
        key = SFrameKey(keyID: keyID, baseKey: baseKey, suite: suite)
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
