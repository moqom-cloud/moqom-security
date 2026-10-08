// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC
//
// The RFC 9420 §8 key schedule. The RFC 9605 §5.2 bridge from it to SFrame is
// `SFrameKeys.swift`.
//
// This file is the part of the MLS subset that is meant to be bit-exact with
// the RFC, and the tests hold it to that against the working group's
// `key-schedule.json` vectors: GroupContext serialisation, every epoch-derived
// secret, the init-secret chain across epochs, and the exporter. What feeds it
// — where the commit secret comes from, what the tree hash covers — is MOQOM's
// simplification and is documented in `Group.swift`.
//
// Old epochs are not kept. An `MLSEpochSecrets` is replaced, not appended to,
// which is what forward secrecy across epochs rests on: once a member has moved
// on, nothing in memory can derive the previous epoch's keys.

import CryptoKit
import Foundation

/// `GroupContext`, RFC 9420 §8.1.
///
/// The cipher suite is part of it, so every signature over a commit or a
/// GroupInfo, and every secret the key schedule derives, is bound to the suite
/// the group was founded with.
public struct MLSGroupContext: Hashable, Sendable {
    public let cipherSuite: MLSCipherSuite
    public let groupID: Data
    public let epoch: UInt64
    public let treeHash: Data
    public let confirmedTranscriptHash: Data

    public init(
        cipherSuite: MLSCipherSuite,
        groupID: Data,
        epoch: UInt64,
        treeHash: Data,
        confirmedTranscriptHash: Data
    ) {
        self.cipherSuite = cipherSuite
        self.groupID = groupID
        self.epoch = epoch
        self.treeHash = treeHash
        self.confirmedTranscriptHash = confirmedTranscriptHash
    }

    /// The serialised form. Extensions are always empty: none are implemented.
    public var encoded: Data {
        var writer = MLSWriter()
        writer.uint16(MLSCipherSuite.version)
        writer.uint16(cipherSuite.identifier)
        writer.vector(groupID)
        writer.uint64(epoch)
        writer.vector(treeHash)
        writer.vector(confirmedTranscriptHash)
        writer.vector(Data())
        return writer.bytes
    }

    static func read(from reader: inout MLSReader) throws(MLSError) -> MLSGroupContext {
        let suite = try reader.cipherSuite()
        let groupID = try reader.vector()
        let epoch = try reader.uint64()
        let treeHash = try reader.vector()
        let confirmed = try reader.vector()
        guard try reader.vector().isEmpty else { throw MLSError.unsupported }
        return MLSGroupContext(
            cipherSuite: suite,
            groupID: groupID,
            epoch: epoch,
            treeHash: treeHash,
            confirmedTranscriptHash: confirmed
        )
    }
}

/// Everything one epoch of the key schedule produces.
public struct MLSEpochSecrets: Sendable {
    /// The suite every secret here was derived with, and which the exporter
    /// goes on deriving with.
    public let cipherSuite: MLSCipherSuite
    public let joinerSecret: Data
    public let welcomeSecret: Data
    public let epochSecret: Data
    public let senderDataSecret: Data
    public let encryptionSecret: Data
    public let exporterSecret: Data
    public let externalSecret: Data
    public let confirmationKey: Data
    public let membershipKey: Data
    public let resumptionPSK: Data
    public let epochAuthenticator: Data
    /// The next epoch's `init_secret`.
    public let initSecret: Data

    /// One epoch, from the previous epoch's init secret and this commit's
    /// secret. `pskSecret` defaults to the suite's all-zero secret.
    public static func derive(
        initSecret previous: Data,
        commitSecret: Data,
        pskSecret: Data? = nil,
        context: MLSGroupContext
    ) -> MLSEpochSecrets {
        derive(
            initSecret: previous, commitSecret: commitSecret, pskSecret: pskSecret,
            suite: context.cipherSuite, encodedContext: context.encoded
        )
    }

    /// One epoch from its joiner secret, which is where a member arriving by
    /// Welcome starts.
    public static func derive(
        joinerSecret joiner: Data,
        pskSecret: Data? = nil,
        context: MLSGroupContext
    ) -> MLSEpochSecrets {
        derive(joinerSecret: joiner, pskSecret: pskSecret, suite: context.cipherSuite, encodedContext: context.encoded)
    }

    /// The same, over a GroupContext already serialised, which is how the
    /// tests run another suite's vectors through the same hash and KDF.
    static func derive(
        initSecret previous: Data,
        commitSecret: Data,
        pskSecret: Data?,
        suite: MLSCipherSuite,
        encodedContext: Data
    ) -> MLSEpochSecrets {
        let joiner = suite.expandLabel(
            suite.extract(salt: previous, ikm: commitSecret),
            label: "joiner",
            context: encodedContext,
            length: suite.hashLength
        )
        return derive(joinerSecret: joiner, pskSecret: pskSecret, suite: suite, encodedContext: encodedContext)
    }

    static func derive(
        joinerSecret joiner: Data,
        pskSecret: Data?,
        suite: MLSCipherSuite,
        encodedContext: Data
    ) -> MLSEpochSecrets {
        let member = suite.extract(salt: joiner, ikm: pskSecret ?? Data(count: suite.hashLength))
        let epoch = suite.expandLabel(
            member,
            label: "epoch",
            context: encodedContext,
            length: suite.hashLength
        )
        func derived(_ label: String) -> Data { suite.deriveSecret(epoch, label: label) }
        return MLSEpochSecrets(
            cipherSuite: suite,
            joinerSecret: joiner,
            welcomeSecret: suite.deriveSecret(member, label: "welcome"),
            epochSecret: epoch,
            senderDataSecret: derived("sender data"),
            encryptionSecret: derived("encryption"),
            exporterSecret: derived("exporter"),
            externalSecret: derived("external"),
            confirmationKey: derived("confirm"),
            membershipKey: derived("membership"),
            resumptionPSK: derived("resumption"),
            epochAuthenticator: derived("authentication"),
            initSecret: derived("init")
        )
    }

    /// The welcome secret for a joiner secret, without deriving the epoch.
    static func welcomeSecret(
        joinerSecret: Data,
        pskSecret: Data? = nil,
        suite: MLSCipherSuite
    ) -> Data {
        suite.deriveSecret(
            suite.extract(salt: joinerSecret, ikm: pskSecret ?? Data(count: suite.hashLength)),
            label: "welcome"
        )
    }

    /// The most `MLS-Exporter` can produce: HKDF-Expand's limit of 255 times
    /// the suite's hash length.
    var maximumExporterLength: Int { cipherSuite.maximumExpandLength }

    /// `MLS-Exporter`, RFC 9420 §8.5.
    ///
    /// Throws ``MLSError/invalidLength(length:maximum:)`` for a `length` that
    /// is negative or past 255 times the suite's hash length.
    public func exporter(label: Data, context: Data, length: Int) throws(MLSError) -> Data {
        guard (0 ... maximumExporterLength).contains(length) else {
            throw MLSError.invalidLength(length: length, maximum: maximumExporterLength)
        }
        return cipherSuite.expandLabel(
            cipherSuite.deriveSecret(exporterSecret, rawLabel: label),
            label: "exported",
            context: cipherSuite.hash(context),
            length: length
        )
    }

    public func exporter(label: String, context: Data = Data(), length: Int) throws(MLSError) -> Data {
        try exporter(label: Data(label.utf8), context: context, length: length)
    }

    /// The exporter with an empty context, for a length the caller fixes no
    /// larger than an AEAD key, as RFC 9605's `base_key` is. Traps past
    /// `maximumExporterLength`.
    func exporter(label: String, length: Int) -> Data {
        do {
            return try exporter(label: Data(label.utf8), context: Data(), length: length)
        } catch {
            preconditionFailure("an exporter length of \(length) is past the HKDF limit")
        }
    }
}
