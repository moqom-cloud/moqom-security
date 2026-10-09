// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

// Sealed tokens: a signed token encrypted for its verifiers, so its claims are
// opaque bytes to everyone else, the holder included.
//
//     base64url( version | key ID | nonce | AES-256-GCM(segments) )
//
// The version and the key ID are the additional data. The segments are the
// JWS's header, claims and signature as raw bytes, each of the first two after
// a two-byte big-endian length. Sealing adds confidentiality and nothing else:
// what a token grants is still decided by its signature, checked after it is
// opened.

import CryptoKit
import Foundation

/// An AES-256 key tokens are sealed with, held by the issuer and by every
/// verifier, and by nobody else.
///
/// GCM with a random nonce: rotate the key well before it has sealed 2³²
/// tokens, the limit NIST SP 800-38D sets for random nonces.
public struct SealKey: Sendable, CustomStringConvertible {
    /// The first byte of every sealed token.
    public static let version: UInt8 = 0x01
    /// The length of a key's ID. Random rather than chosen, so the one thing a
    /// sealed token shows in the clear says nothing about whose it is.
    public static let idLength = 8

    static let secretLength = 32
    static let nonceLength = 12
    static let tagLength = 16

    /// The ID, as sealed tokens carry it.
    public let id: Data
    private let key: SymmetricKey

    /// A key from its eight-byte ID and 32-byte secret.
    public init(id: Data, secret: Data) throws(PublicKey.SetError) {
        guard id.count == Self.idLength, secret.count == Self.secretLength else {
            throw .invalid(kid: id.base64URL, reason: "a seal key is an 8-byte ID and a 32-byte secret")
        }
        self.id = id
        key = SymmetricKey(data: secret)
    }

    /// A new random key with a random ID.
    public static func generate() -> SealKey {
        let id = SymmetricKey(size: .bits128).withUnsafeBytes { Data($0.prefix(idLength)) }
        let secret = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
        // Lengths are right by construction.
        return try! SealKey(id: id, secret: secret)
    }

    /// The ID as a JWK `kid`: unpadded base64url.
    public var keyID: String { id.base64URL }

    /// The 32-byte AES key, for storing it.
    public var secret: Data { key.withUnsafeBytes { Data($0) } }

    /// The ID only: a seal key's description never includes its secret.
    public var description: String { "SealKey(\(keyID))" }

    /// The key as an RFC 7517 `oct` JWK, secret included: for the issuer's
    /// secret store and a verifier's configuration, never for publishing.
    public var jwk: String {
        #"{"kty":"oct","alg":"A256GCM","kid":"\#(keyID)","k":"\#(secret.base64URL)"}"#
    }

    /// Encrypt a signed token for the verifiers holding this key.
    public func seal(_ token: String) throws(TokenError) -> String {
        try seal(token, nonce: AES.GCM.Nonce())
    }

    /// ``seal(_:)`` with the nonce given, for reproducing the shared vectors.
    func seal(_ token: String, nonce: AES.GCM.Nonce) throws(TokenError) -> String {
        let parts = token.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3 else { throw .malformed("expected three segments") }
        var segments = Data()
        for (index, part) in parts.enumerated() {
            guard let raw = Data(base64URL: part) else { throw .malformed("a segment is not base64url") }
            if index < 2 {
                guard raw.count <= 0xFFFF else { throw .malformed("a segment is too long") }
                segments.append(UInt8(raw.count >> 8))
                segments.append(UInt8(raw.count & 0xFF))
            }
            segments.append(raw)
        }
        let prefix = Data([Self.version]) + id
        guard let box = try? AES.GCM.seal(segments, using: key, nonce: nonce, authenticating: prefix) else {
            throw .malformed("cannot seal")
        }
        return (prefix + Data(nonce) + box.ciphertext + box.tag).base64URL
    }

    /// Whether `token` is in the sealed form rather than a JWS. It says nothing
    /// about whether it opens.
    public static func isSealed(_ token: Data) -> Bool {
        !token.isEmpty && !token.contains(UInt8(ascii: "."))
    }

    /// Decrypt a sealed token with whichever of `keys` sealed it, and return
    /// the signed token inside, still to be verified.
    ///
    /// Refused: a token that is not the sealed form or is cut short
    /// (``TokenError/malformed(_:)``), another version
    /// (``TokenError/unsupported``), a key ID none of `keys` has
    /// (``TokenError/unknownKey``), and anything that does not authenticate
    /// under the key it names (``TokenError/badSignature``).
    public static func open(_ token: Data, keys: [SealKey]) throws(TokenError) -> String {
        guard !token.isEmpty, token.count <= TokenLimits.maximumTokenBytes else {
            throw .malformed("token length is out of range")
        }
        guard let text = String(data: token, encoding: .ascii), let sealed = Data(base64URL: text) else {
            throw .malformed("sealed token is not base64url")
        }
        let bytes = [UInt8](sealed)
        let prefixLength = 1 + idLength
        guard bytes.count >= prefixLength + nonceLength + tagLength else {
            throw .malformed("sealed token is too short")
        }
        guard bytes[0] == version else { throw .unsupported }
        let id = Data(bytes[1 ..< prefixLength])
        guard let key = keys.first(where: { $0.id == id }) else { throw .unknownKey }
        let tagStart = bytes.count - tagLength
        guard
            let nonce = try? AES.GCM.Nonce(data: Data(bytes[prefixLength ..< prefixLength + nonceLength])),
            let box = try? AES.GCM.SealedBox(
                nonce: nonce,
                ciphertext: Data(bytes[(prefixLength + nonceLength) ..< tagStart]),
                tag: Data(bytes[tagStart...])
            ),
            let opened = try? AES.GCM.open(box, using: key.key, authenticating: Data(bytes[..<prefixLength]))
        else { throw .badSignature }

        var rest = [UInt8](opened)[...]
        var parts: [String] = []
        for _ in 0 ..< 2 {
            guard rest.count >= 2 else { throw .malformed("sealed segments are cut short") }
            let length = Int(rest[rest.startIndex]) << 8 | Int(rest[rest.startIndex + 1])
            rest = rest.dropFirst(2)
            guard rest.count >= length else { throw .malformed("sealed segments are cut short") }
            parts.append(Data(rest.prefix(length)).base64URL)
            rest = rest.dropFirst(length)
        }
        parts.append(Data(rest).base64URL)
        return parts.joined(separator: ".")
    }

    /// Read seal keys from a JWK set, as a bare array or `{"keys": [...]}`: each
    /// `kty` `oct`, `alg` `A256GCM`, an eight-byte `kid` and a 32-byte `k`, both
    /// unpadded base64url.
    public static func parseSet(_ document: Data) throws(PublicKey.SetError) -> [SealKey] {
        guard StrictJSON.isValid(document),
              let parsed = try? JSONSerialization.jsonObject(with: document)
        else { throw .malformed("not strict JSON, or a member named twice") }
        let members: [Any]
        if let wrapped = parsed as? [String: Any] {
            guard let keys = wrapped["keys"] as? [Any] else { throw .malformed("no keys array") }
            members = keys
        } else if let bare = parsed as? [Any] {
            members = bare
        } else {
            throw .malformed("not an array of JWKs or {\"keys\": [...]}")
        }
        var keys: [SealKey] = []
        var seen = Set<String>()
        for member in members {
            guard let jwk = member as? [String: Any], let kid = jwk["kid"] as? String else {
                throw .malformed("a key that is not an object with a kid")
            }
            guard jwk["kty"] as? String == "oct", jwk["alg"] as? String == "A256GCM" else {
                throw .unsupported(kid: kid)
            }
            let reason = "a seal key is an 8-byte kid and a 32-byte k, in base64url"
            guard let id = Data(base64URL: kid), let k = jwk["k"] as? String, let secret = Data(base64URL: k) else {
                throw .invalid(kid: kid, reason: reason)
            }
            guard let key = try? SealKey(id: id, secret: secret) else { throw .invalid(kid: kid, reason: reason) }
            guard seen.insert(kid).inserted else { throw .duplicateKeyID(kid) }
            keys.append(key)
        }
        return keys
    }
}
