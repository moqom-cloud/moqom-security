// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC
//
// SFrame keys from an MLS epoch, RFC 9605 §5.2.
//
// One `base_key` per epoch, shared by every member, and nothing derived per
// sender on top of it. What separates senders is the KID: SFrame's own key
// derivation (§4.4.2) puts the KID into the labels its key and salt come from,
// so two members holding the same base key still encrypt under different keys
// and nonces. An earlier version expanded a per-leaf base key first; RFC 9605
// has no such step and a peer following the RFC would have derived different
// keys.

import Foundation
import MoqomSFrame

/// The RFC 9605 §5.2 bridge: an epoch's base key, and the KID each member
/// sends under. The KID layout is ``SFrameKeyID``'s.
public enum MLSSFrameKeys {
    public static var epochBits: UInt64 { SFrameKeyID.epochBits }

    /// `base_key = MLS-Exporter("SFrame 1.0 Base Key", "", AEAD.Nk)`.
    public static func baseKey(_ secrets: MLSEpochSecrets, suite: SFrameCipherSuite) -> Data {
        secrets.exporter(label: SFrameKeyID.mlsExporterLabel, length: suite.keyLength)
    }

    /// `KID = (context << (S + E)) + (index << E) + (epoch % (1 << E))`, context 0.
    public static func keyID(leaf: UInt32, epoch: UInt64) -> UInt64 {
        SFrameKeyID.mls(leaf: leaf, epoch: epoch)
    }

    /// The low bits of an epoch as a KID carries them.
    public static func epochTag(ofKeyID keyID: UInt64) -> UInt64 {
        SFrameKeyID.epochTag(of: keyID)
    }

    public static func key(
        _ secrets: MLSEpochSecrets,
        leaf: UInt32,
        epoch: UInt64,
        suite: SFrameCipherSuite
    ) -> SFrameKey {
        key(baseKey: baseKey(secrets, suite: suite), leaf: leaf, epoch: epoch, suite: suite)
    }

    /// From a base key already exported, so a whole roster can be keyed with
    /// one export.
    public static func key(
        baseKey: Data,
        leaf: UInt32,
        epoch: UInt64,
        suite: SFrameCipherSuite
    ) -> SFrameKey {
        SFrameKey(keyID: keyID(leaf: leaf, epoch: epoch), baseKey: baseKey, suite: suite)
    }
}

extension MLSGroup {
    /// The epoch's SFrame base key, from which every member's key derives.
    /// What a broadcast's viewers are sealed; see ``MLSAudience``.
    public func sframeBaseKey(suite: SFrameCipherSuite) -> Data {
        MLSSFrameKeys.baseKey(secrets, suite: suite)
    }

    /// The SFrame key one member sends under in this epoch.
    public func sframeKey(for leaf: UInt32, suite: SFrameCipherSuite) -> SFrameKey {
        MLSSFrameKeys.key(secrets, leaf: leaf, epoch: epoch, suite: suite)
    }

    /// Every current member's SFrame key for this epoch, from one export.
    public func sframeKeys(suite: SFrameCipherSuite) -> [SFrameKey] {
        let base = MLSSFrameKeys.baseKey(secrets, suite: suite)
        return roster.map { MLSSFrameKeys.key(baseKey: base, leaf: $0.leaf, epoch: epoch, suite: suite) }
    }
}
