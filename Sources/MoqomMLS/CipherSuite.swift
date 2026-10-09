// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC
//
// The RFC 9420 primitives MOQOM's group key management is built from.
//
// One cipher suite, `MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87`: HPKE KEM
// 0x0042 (pure ML-KEM-1024, draft-ietf-hpke-pq-05), HKDF-SHA512 (HPKE KDF
// 0x0003), AES-256-GCM, SHA-512 as the MLS hash, and ML-DSA-87 signatures
// (FIPS 204, as draft-ietf-tls-mldsa uses it: pure, empty context). Both the
// secrets a group carries and the signatures that say who sent them are
// post-quantum at NIST category 5, and every key is 256 bits.
// draft-ietf-mls-pq-ciphersuites defines a suite of this name, but its value
// is not assigned yet, so the identifier below is from RFC 9420 §17.1's
// private-use range and has to change to the IANA value once there is one. A
// peer that implements the draft would not recognise it.
//
// The AES-128 suites, RFC 9420's mandatory 0x0001 and the draft's X-Wing
// "TBD1" (0xF0A1), and MOQOM's earlier ML-KEM suites 0xF0AA and 0xF0AB are not
// implemented: a key package, Welcome or group in any of them is refused as
// unsupported, never negotiated down to.
//
// Everything a group derives — the key schedule, the exporter, and so SFrame
// keys — goes through the suite's hash and KDF, so every function here is a
// method on the suite rather than a free function.
//
// Each function is the RFC's definition and nothing more. HPKE over pure
// ML-KEM-1024, and ML-DSA-87 signing, are checked against Go's `crypto/hpke`
// and `crypto/mldsa`, which is the only basis on which this file claims to
// match either draft. What is built on top of these primitives is MOQOM's own
// and is described in `Group.swift`.
//
// Everything is CryptoKit. CryptoKit has no HPKE KEM for pure ML-KEM, so the
// RFC 9180 key schedule is composed below from CryptoKit's ML-KEM-1024,
// HKDF-SHA512 and AES-256-GCM: no primitive is hand-rolled, only the schedule
// that joins them.

import CryptoKit
import Foundation

/// An MLS cipher suite this library implements.
///
/// A value carried by every key package and every group, never a setting:
/// there is one suite, every member uses it, and a key package in any other
/// is refused rather than added.
public struct MLSCipherSuite: Hashable, Sendable, CustomStringConvertible {
    /// The suite's two-byte identifier, as it appears on the wire.
    public let identifier: UInt16

    private init(wire identifier: UInt16) {
        self.identifier = identifier
    }

    /// `MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87`, draft-ietf-mls-pq-ciphersuites' category-5 suite.
    ///
    /// 0xF0AC is a private-use value (RFC 9420 §17.1), standing in until IANA
    /// assigns one. Only MOQOM's own libraries and control plane know it.
    public static let mls256MLKEM1024MLDSA87 = MLSCipherSuite(wire: 0xF0AC)

    /// The suite every group uses. There is no other choice: a group is
    /// post-quantum in both its secrets and its signatures, with AES-256.
    public static let `default` = mls256MLKEM1024MLDSA87

    /// Every suite implemented.
    public static let supported: [MLSCipherSuite] = [.mls256MLKEM1024MLDSA87]

    /// The suite with this identifier, or `nil` if it is not one implemented here.
    public init?(identifier: UInt16) {
        guard let suite = Self.supported.first(where: { $0.identifier == identifier }) else { return nil }
        self = suite
    }

    /// The registered name.
    public var name: String { "MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87" }

    public var description: String {
        "\(name) (0x\(String(identifier, radix: 16, uppercase: true)))"
    }

    /// Whether the KEM, and so every secret a commit or Welcome carries, is
    /// meant to resist a quantum computer. Always.
    public var hasPostQuantumKEM: Bool { true }

    /// Whether signatures, and so who a commit or key package says it is from,
    /// are meant to resist a quantum computer. Always.
    public var hasPostQuantumSignatures: Bool { true }

    /// The protocol version, `mls10`.
    public static let version: UInt16 = 0x0001

    // MARK: - Hash, KDF and MAC

    /// Hash output length, `KDF.Nh`: 64, for SHA-512.
    public var hashLength: Int { 64 }

    /// AEAD key length, `AEAD.Nk`: 32, for AES-256-GCM.
    var aeadKeyLength: Int { 32 }

    /// AEAD nonce length, `AEAD.Nn`.
    static let aeadNonceLength = 12

    func hash(_ data: Data) -> Data {
        Data(SHA512.hash(data: data))
    }

    /// `KDF.Extract(salt, ikm)`.
    func extract(salt: Data, ikm: Data) -> Data {
        Data(HKDF<SHA512>.extract(inputKeyMaterial: SymmetricKey(data: ikm), salt: salt))
    }

    /// `KDF.Expand(secret, info, length)`.
    func expand(_ secret: Data, info: Data, length: Int) -> Data {
        // CryptoKit traps on an output of zero bytes, which HKDF defines as empty.
        guard length > 0 else { return Data() }
        return HKDF<SHA512>.expand(pseudoRandomKey: SymmetricKey(data: secret), info: info, outputByteCount: length)
            .withUnsafeBytes { Data($0) }
    }

    /// The most `ExpandWithLabel` can produce: HKDF-Expand's limit of 255
    /// times the hash length, which also fits its 16-bit length.
    var maximumExpandLength: Int { 255 * hashLength }

    /// `ExpandWithLabel`, RFC 9420 §5.1.3.
    ///
    /// Throws ``MLSError/invalidLength(length:maximum:)`` for a `length` that
    /// is negative or past 255 times the suite's hash length.
    public func expandWithLabel(_ secret: Data, label: String, context: Data, length: Int) throws(MLSError) -> Data {
        guard (0 ... maximumExpandLength).contains(length) else {
            throw MLSError.invalidLength(length: length, maximum: maximumExpandLength)
        }
        return expandLabel(secret, label: label, context: context, length: length)
    }

    /// `ExpandWithLabel` for a length the caller fixes within
    /// `maximumExpandLength`.
    func expandLabel(_ secret: Data, label: String, context: Data, length: Int) -> Data {
        var info = MLSWriter()
        info.uint16(UInt16(length))
        info.vector(Data("MLS 1.0 \(label)".utf8))
        info.vector(context)
        return expand(secret, info: info.bytes, length: length)
    }

    /// `DeriveSecret`, RFC 9420 §5.1.3.
    public func deriveSecret(_ secret: Data, label: String) -> Data {
        expandLabel(secret, label: label, context: Data(), length: hashLength)
    }

    /// `DeriveSecret` with a label that is not UTF-8 text, for the exporter.
    func deriveSecret(_ secret: Data, rawLabel: Data) -> Data {
        var info = MLSWriter()
        info.uint16(UInt16(hashLength))
        info.vector(Data("MLS 1.0 ".utf8) + rawLabel)
        info.vector(Data())
        return expand(secret, info: info.bytes, length: hashLength)
    }

    /// `RefHash`, RFC 9420 §5.2.
    public func refHash(label: String, value: Data) -> Data {
        var input = MLSWriter()
        input.vector(Data(label.utf8))
        input.vector(value)
        return hash(input.bytes)
    }

    /// `MAC`: HMAC-SHA512.
    func mac(key: Data, data: Data) -> Data {
        Data(HMAC<SHA512>.authenticationCode(for: data, using: SymmetricKey(data: key)))
    }

    /// A fresh secret of the hash's length, which is what a commit secret,
    /// an init secret and a path secret are.
    func randomSecret() -> Data { Self.randomSecret(hashLength) }

    // MARK: - Signatures

    /// A signature public key's length: 2592, for ML-DSA-87.
    public var signatureKeyLength: Int { 2592 }

    /// A fresh signature key pair: the private half as ML-DSA-87's 32-byte
    /// FIPS 204 seed and the public half as it travels.
    public func generateSignatureKeyPair() throws(MLSError) -> (privateKey: Data, publicKey: Data) {
        do {
            let key = try MLDSA87.PrivateKey()
            return (key.seedRepresentation, key.publicKey.rawRepresentation)
        } catch {
            throw MLSError.cryptoFailure
        }
    }

    private static func signContent(label: String, content: Data) -> Data {
        var tbs = MLSWriter()
        tbs.vector(Data("MLS 1.0 \(label)".utf8))
        tbs.vector(content)
        return tbs.bytes
    }

    /// `SignWithLabel`, RFC 9420 §5.1.2, with a private key as
    /// ``generateSignatureKeyPair()`` returns it.
    public func signWithLabel(_ privateKey: Data, label: String, content: Data) throws(MLSError) -> Data {
        let message = Self.signContent(label: label, content: content)
        do {
            return try MLDSA87.PrivateKey(seedRepresentation: privateKey, publicKey: nil).signature(for: message)
        } catch {
            throw MLSError.cryptoFailure
        }
    }

    /// `VerifyWithLabel`, RFC 9420 §5.1.2.
    public func verifyWithLabel(_ publicKey: Data, label: String, content: Data, signature: Data) -> Bool {
        guard publicKey.count == signatureKeyLength,
              let key = try? MLDSA87.PublicKey(rawRepresentation: publicKey)
        else { return false }
        return key.isValidSignature(signature, for: Self.signContent(label: label, content: content))
    }

    // MARK: - The KEM

    /// `Npk`: an init key's or leaf encryption key's length, 1568 for ML-KEM-1024.
    public var publicKeyLength: Int { 1568 }

    /// `Nenc`: the KEM output in every HPKE ciphertext, 1568 for ML-KEM-1024.
    public var encapsulationLength: Int { 1568 }

    /// Whether `publicKey` is an ML-KEM-1024 key: the right length and passing
    /// FIPS 203's encapsulation key check, which every sender's encapsulation
    /// would otherwise fail on. CryptoKit runs that check when it
    /// encapsulates, not when it makes the key, so this encapsulates once and
    /// discards it.
    func isValidPublicKey(_ publicKey: Data) -> Bool {
        guard publicKey.count == publicKeyLength else { return false }
        return (try? MLKEM1024.PublicKey(rawRepresentation: publicKey).encapsulate()) != nil
    }

    /// A fresh KEM key pair: the private half as ML-KEM-1024's 64-byte seed and
    /// the public half as it travels.
    public func generateKeyPair() throws(MLSError) -> (privateKey: Data, publicKey: Data) {
        do {
            let key = try MLKEM1024.PrivateKey.generate()
            return (key.seedRepresentation, key.publicKey.rawRepresentation)
        } catch {
            throw MLSError.cryptoFailure
        }
    }

    private static func encryptContext(label: String, context: Data) -> Data {
        var info = MLSWriter()
        info.vector(Data("MLS 1.0 \(label)".utf8))
        info.vector(context)
        return info.bytes
    }

    /// `EncryptWithLabel`, RFC 9420 §5.1.3: HPKE base mode, empty AAD.
    public func encryptWithLabel(
        _ publicKey: Data,
        label: String,
        context: Data,
        plaintext: Data
    ) throws(MLSError) -> HPKECiphertext {
        guard publicKey.count == publicKeyLength else { throw MLSError.malformed }
        do {
            return try MLKEMHPKE.seal(
                to: publicKey, info: Self.encryptContext(label: label, context: context), plaintext: plaintext
            )
        } catch {
            throw MLSError.cryptoFailure
        }
    }

    /// `DecryptWithLabel`, RFC 9420 §5.1.3, with a private key as
    /// ``generateKeyPair()`` returns it.
    public func decryptWithLabel(
        _ privateKey: Data,
        label: String,
        context: Data,
        ciphertext: HPKECiphertext
    ) throws(MLSError) -> Data {
        guard ciphertext.kemOutput.count == encapsulationLength else { throw MLSError.decryptionFailed }
        do {
            return try MLKEMHPKE.open(
                ciphertext, seed: privateKey, info: Self.encryptContext(label: label, context: context)
            )
        } catch {
            throw MLSError.decryptionFailed
        }
    }

    // MARK: - Symmetric

    static func aeadSeal(key: Data, nonce: Data, plaintext: Data, aad: Data) throws(MLSError) -> Data {
        do {
            let box = try AES.GCM.seal(
                plaintext,
                using: SymmetricKey(data: key),
                nonce: AES.GCM.Nonce(data: nonce),
                authenticating: aad
            )
            return box.ciphertext + box.tag
        } catch {
            throw MLSError.cryptoFailure
        }
    }

    static func aeadOpen(key: Data, nonce: Data, ciphertext: Data, aad: Data) throws(MLSError) -> Data {
        guard ciphertext.count >= 16 else { throw MLSError.decryptionFailed }
        let split = ciphertext.index(ciphertext.endIndex, offsetBy: -16)
        do {
            let box = try AES.GCM.SealedBox(
                nonce: AES.GCM.Nonce(data: nonce),
                ciphertext: ciphertext[..<split],
                tag: ciphertext[split...]
            )
            return try AES.GCM.open(box, using: SymmetricKey(data: key), authenticating: aad)
        } catch {
            throw MLSError.decryptionFailed
        }
    }

    /// `count` random bytes, for a fresh secret or a group ID.
    public static func randomSecret(_ count: Int) -> Data {
        SymmetricKey(size: SymmetricKeySize(bitCount: count * 8)).withUnsafeBytes { Data($0) }
    }
}

/// HPKE (RFC 9180) base mode for KEM 0x0042, KDF 0x0003, AEAD 0x0002:
/// ML-KEM-1024, HKDF-SHA512, AES-256-GCM.
///
/// draft-ietf-hpke-pq-05 makes ML-KEM an HPKE KEM unchanged: `Encap` is
/// ML-KEM's encapsulation, the shared secret is ML-KEM's 32 bytes, and `enc`
/// is its 1568-byte ciphertext. What follows is RFC 9180 §5.1's key schedule
/// over that secret, for one message (sequence number 0), which is all
/// `EncryptWithLabel` sends.
enum MLKEMHPKE {
    /// `suite_id = "HPKE" || I2OSP(kem_id, 2) || I2OSP(kdf_id, 2) || I2OSP(aead_id, 2)`.
    private static let suiteID = Data("HPKE".utf8) + Data([0x00, 0x42, 0x00, 0x03, 0x00, 0x02])

    private static func labeledExtract(salt: Data, label: String, ikm: Data) -> Data {
        let labeled = Data("HPKE-v1".utf8) + suiteID + Data(label.utf8) + ikm
        return Data(HKDF<SHA512>.extract(inputKeyMaterial: SymmetricKey(data: labeled), salt: salt))
    }

    private static func labeledExpand(_ prk: Data, label: String, info: Data, length: Int) -> Data {
        let labeled = Data([UInt8(length >> 8), UInt8(length & 0xFF)])
            + Data("HPKE-v1".utf8) + suiteID + Data(label.utf8) + info
        return HKDF<SHA512>.expand(
            pseudoRandomKey: SymmetricKey(data: prk), info: labeled, outputByteCount: length
        ).withUnsafeBytes { Data($0) }
    }

    /// `KeySchedule(mode_base, shared_secret, info, "", "")`: the key and base nonce.
    static func keySchedule(sharedSecret: Data, info: Data) -> (key: Data, nonce: Data) {
        let pskIDHash = labeledExtract(salt: Data(), label: "psk_id_hash", ikm: Data())
        let infoHash = labeledExtract(salt: Data(), label: "info_hash", ikm: info)
        let context = Data([0x00]) + pskIDHash + infoHash
        let secret = labeledExtract(salt: sharedSecret, label: "secret", ikm: Data())
        return (
            labeledExpand(secret, label: "key", info: context, length: 32),
            labeledExpand(secret, label: "base_nonce", info: context, length: MLSCipherSuite.aeadNonceLength)
        )
    }

    static func seal(to publicKey: Data, info: Data, plaintext: Data) throws -> HPKECiphertext {
        let encapsulation = try MLKEM1024.PublicKey(rawRepresentation: publicKey).encapsulate()
        let shared = encapsulation.sharedSecret.withUnsafeBytes { Data($0) }
        let (key, nonce) = keySchedule(sharedSecret: shared, info: info)
        let ciphertext = try MLSCipherSuite.aeadSeal(key: key, nonce: nonce, plaintext: plaintext, aad: Data())
        return HPKECiphertext(kemOutput: encapsulation.encapsulated, ciphertext: ciphertext)
    }

    static func open(_ ciphertext: HPKECiphertext, seed: Data, info: Data) throws -> Data {
        let key = try MLKEM1024.PrivateKey(seedRepresentation: seed, publicKey: nil)
        let shared = try key.decapsulate(ciphertext.kemOutput).withUnsafeBytes { Data($0) }
        let schedule = keySchedule(sharedSecret: shared, info: info)
        return try MLSCipherSuite.aeadOpen(
            key: schedule.key, nonce: schedule.nonce, ciphertext: ciphertext.ciphertext, aad: Data()
        )
    }
}

/// `HPKECiphertext`, RFC 9420 §5.1.3.
public struct HPKECiphertext: Hashable, Sendable {
    public let kemOutput: Data
    public let ciphertext: Data

    public init(kemOutput: Data, ciphertext: Data) {
        self.kemOutput = kemOutput
        self.ciphertext = ciphertext
    }

    func write(to writer: inout MLSWriter) {
        writer.vector(kemOutput)
        writer.vector(ciphertext)
    }

    static func read(from reader: inout MLSReader) throws(MLSError) -> HPKECiphertext {
        HPKECiphertext(kemOutput: try reader.vector(), ciphertext: try reader.vector())
    }
}

/// What went wrong in group key management.
public enum MLSError: Error, Hashable, Sendable {
    /// Bytes that do not parse.
    case malformed
    /// A signature did not verify.
    case badSignature
    /// A confirmation tag or membership check did not match.
    case confirmationMismatch
    /// HPKE or AEAD refused to open something.
    case decryptionFailed
    /// A primitive failed where it should not be able to.
    case cryptoFailure
    /// A message for a different group or epoch than the one held.
    case wrongEpoch(expected: UInt64, got: UInt64)
    case wrongGroup
    /// A proposal names a member that is not there, or adds one twice.
    case invalidProposal
    /// The message is from someone who is not a member.
    case unknownSender
    /// Nothing in the message was addressed to this member.
    case notAddressed
    /// A key package whose keys are the wrong size or shape for its suite.
    case invalidKeyPackage
    /// The cipher suite or version is not one implemented.
    case unsupported
    /// A key package or Welcome in a different cipher suite from the group's.
    /// A group never mixes suites: a device in another suite publishes new key
    /// packages in the group's before it can be added.
    case cipherSuiteMismatch(group: UInt16, other: UInt16)
    /// An exporter or `expandWithLabel` length that is negative or past
    /// HKDF-Expand's limit of 255 times the suite's hash length.
    case invalidLength(length: Int, maximum: Int)

    /// The failure class the shared vectors and the Go and Rust libraries
    /// name this error with.
    public var errorClass: String {
        switch self {
        case .malformed: "malformed"
        case .badSignature: "bad-signature"
        case .confirmationMismatch: "confirmation-mismatch"
        case .decryptionFailed: "decryption-failed"
        case .cryptoFailure: "crypto-failure"
        case .wrongEpoch: "wrong-epoch"
        case .wrongGroup: "wrong-group"
        case .invalidProposal: "invalid-proposal"
        case .unknownSender: "unknown-sender"
        case .notAddressed: "not-addressed"
        case .invalidKeyPackage: "invalid-key-package"
        case .unsupported: "unsupported"
        case .cipherSuiteMismatch: "cipher-suite-mismatch"
        case .invalidLength: "invalid-length"
        }
    }
}

// MARK: - Encoding

/// The TLS presentation language as RFC 9420 §2.1 uses it: big-endian
/// integers and vectors prefixed with the RFC's variable-length size.
struct MLSWriter {
    private(set) var bytes = Data()

    mutating func uint8(_ value: UInt8) { bytes.append(value) }

    mutating func uint16(_ value: UInt16) {
        bytes.append(contentsOf: withUnsafeBytes(of: value.bigEndian) { Array($0) })
    }

    mutating func uint32(_ value: UInt32) {
        bytes.append(contentsOf: withUnsafeBytes(of: value.bigEndian) { Array($0) })
    }

    mutating func uint64(_ value: UInt64) {
        bytes.append(contentsOf: withUnsafeBytes(of: value.bigEndian) { Array($0) })
    }

    /// RFC 9420 §2.1.2: one, two or four bytes, the top two bits giving which.
    mutating func length(_ count: Int) {
        precondition(count < 1 << 30, "MLS vectors are limited to 2^30 bytes")
        if count < 1 << 6 {
            uint8(UInt8(count))
        } else if count < 1 << 14 {
            uint16(UInt16(count) | 0x4000)
        } else {
            uint32(UInt32(count) | 0x8000_0000)
        }
    }

    mutating func vector(_ data: Data) {
        length(data.count)
        bytes.append(data)
    }

    mutating func raw(_ data: Data) { bytes.append(data) }
}

struct MLSReader {
    private let data: Data
    private var offset: Data.Index

    init(_ data: Data) {
        self.data = data
        offset = data.startIndex
    }

    var isAtEnd: Bool { offset == data.endIndex }

    private mutating func take(_ count: Int) throws(MLSError) -> Data {
        guard count >= 0, data.endIndex - offset >= count else { throw MLSError.malformed }
        let slice = data[offset ..< offset + count]
        offset += count
        return Data(slice)
    }

    mutating func uint8() throws(MLSError) -> UInt8 {
        try take(1).first!
    }

    mutating func uint16() throws(MLSError) -> UInt16 {
        try take(2).reduce(0) { ($0 << 8) | UInt16($1) }
    }

    mutating func uint32() throws(MLSError) -> UInt32 {
        try take(4).reduce(0) { ($0 << 8) | UInt32($1) }
    }

    mutating func uint64() throws(MLSError) -> UInt64 {
        try take(8).reduce(0) { ($0 << 8) | UInt64($1) }
    }

    mutating func length() throws(MLSError) -> Int {
        let first = try uint8()
        switch first >> 6 {
        case 0:
            return Int(first)
        case 1:
            let second = try uint8()
            let value = (Int(first & 0x3F) << 8) | Int(second)
            // Minimum-length encoding is required by the RFC.
            guard value >= 1 << 6 else { throw MLSError.malformed }
            return value
        case 2:
            let rest = try take(3)
            let value = rest.reduce(Int(first & 0x3F)) { ($0 << 8) | Int($1) }
            guard value >= 1 << 14 else { throw MLSError.malformed }
            return value
        default:
            throw MLSError.malformed
        }
    }

    mutating func vector() throws(MLSError) -> Data {
        try take(try length())
    }

    mutating func finish() throws(MLSError) {
        guard isAtEnd else { throw MLSError.malformed }
    }

    /// The suite a structure names, refusing one not implemented.
    mutating func cipherSuite() throws(MLSError) -> MLSCipherSuite {
        guard try uint16() == MLSCipherSuite.version,
              let suite = MLSCipherSuite(identifier: try uint16())
        else { throw MLSError.unsupported }
        return suite
    }
}
