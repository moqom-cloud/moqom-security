// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC
//
// Sender keys: how a viewer in a large broadcast decrypts without being in the
// group.
//
// A room's MLS group holds the devices that may publish. A viewer is not
// added: at broadcast scale every commit would carry a ciphertext per viewer
// and every arrival would be a commit. Instead each viewer makes an ML-KEM-768
// key pair, keeps the private half in memory, and hands the public half to the
// group's committer, which seals each epoch's SFrame base key to it with
// `EncryptWithLabel`. From the base key and the key ID in a frame the viewer
// derives any publisher's key exactly as a member does (RFC 9605 §5.2).
//
// What a viewer gives up against a member: it cannot see who else holds the
// keys. Members see each other's leaves and confirm it with the epoch
// authenticator; viewers are whatever list the committer is given.

import Foundation

/// An epoch's SFrame base key sealed to one viewer.
///
/// The envelope is an `HPKECiphertext`, sealed with
/// `EncryptWithLabel(pk, "MOQOM audience key", vector(group_id) || uint64(epoch), base_key)`
/// in `MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65`, so the group and epoch it is
/// for are bound into it.
public enum MLSAudience {
    /// Viewers' keys are ML-KEM-768 whatever suite the group is in, so the
    /// audience is post-quantum even in a group founded in an older suite.
    public static let suite = MLSCipherSuite.mls192MLKEM768MLDSA65
    static let label = "MOQOM audience key"

    /// A viewer's key pair: the private half as a 64-byte ML-KEM-768 seed,
    /// and the 1,184-byte public half it hands out.
    public static func generateKeyPair() throws(MLSError) -> (privateKey: Data, publicKey: Data) {
        try suite.generateKeyPair()
    }

    static func context(groupID: Data, epoch: UInt64) -> Data {
        var writer = MLSWriter()
        writer.vector(groupID)
        writer.uint64(epoch)
        return writer.bytes
    }

    /// Seal `baseKey` to the viewer holding `publicKey`'s private half.
    public static func seal(
        _ baseKey: Data,
        to publicKey: Data,
        groupID: Data,
        epoch: UInt64
    ) throws(MLSError) -> Data {
        let sealed = try suite.encryptWithLabel(
            publicKey, label: label, context: context(groupID: groupID, epoch: epoch), plaintext: baseKey
        )
        var writer = MLSWriter()
        sealed.write(to: &writer)
        return writer.bytes
    }

    /// Open an envelope sealed for `groupID` at `epoch`. Any other group or
    /// epoch fails as ``MLSError/decryptionFailed``.
    public static func open(
        _ envelope: Data,
        privateKey: Data,
        groupID: Data,
        epoch: UInt64
    ) throws(MLSError) -> Data {
        var reader = MLSReader(envelope)
        let sealed = try HPKECiphertext.read(from: &reader)
        try reader.finish()
        return try suite.decryptWithLabel(
            privateKey, label: label, context: context(groupID: groupID, epoch: epoch), ciphertext: sealed
        )
    }
}
