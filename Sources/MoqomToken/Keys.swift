// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

import CryptoKit
import Foundation

/// What a key verifies with, as its JOSE `alg`.
///
/// A property of the key rather than of the token, which is the defence against
/// algorithm confusion: a verifier that dispatches on the token's own `alg` can
/// be told to use `none`, or an HMAC keyed with the public key.
public enum Algorithm: String, Hashable, Sendable {
    /// ML-DSA-65, which every token is signed with.
    case mlDSA65 = "ML-DSA-65"
    /// Ed25519, read only to verify tokens signed before ML-DSA.
    case ed25519 = "EdDSA"

    /// The length of a raw public key.
    public var publicKeyBytes: Int {
        switch self {
        case .mlDSA65: 1952
        case .ed25519: 32
        }
    }
}

/// A key tokens may be verified with.
public struct PublicKey: Hashable, Sendable {
    /// The `kid` naming it.
    public let id: String
    /// What it verifies with.
    public let algorithm: Algorithm
    /// The raw public key.
    public let rawRepresentation: Data

    /// A key named `id`, or by ``derivedID(for:)`` when `id` is nil.
    ///
    /// Throws ``SetError/invalid(kid:reason:)`` for a key that is not the
    /// algorithm's ``Algorithm/publicKeyBytes`` long.
    public init(id: String? = nil, algorithm: Algorithm, rawRepresentation: Data) throws(SetError) {
        let id = id ?? Self.derivedID(for: rawRepresentation)
        guard rawRepresentation.count == algorithm.publicKeyBytes else {
            throw .invalid(kid: id, reason: "a \(algorithm.rawValue) public key is \(algorithm.publicKeyBytes) bytes")
        }
        self.init(checkedID: id, algorithm: algorithm, rawRepresentation: rawRepresentation)
    }

    fileprivate init(checkedID id: String, algorithm: Algorithm, rawRepresentation: Data) {
        self.id = id
        self.algorithm = algorithm
        self.rawRepresentation = rawRepresentation
    }

    /// The identifier a key gets when nobody names it: the first eight bytes of
    /// the SHA-256 of the raw public key, base64url.
    public static func derivedID(for rawRepresentation: Data) -> String {
        Data(SHA256.hash(data: rawRepresentation).prefix(8)).base64URL
    }

    /// Whether `signature` is this key's over `message`, by its own algorithm.
    public func isValidSignature(_ signature: Data, for message: Data) -> Bool {
        switch algorithm {
        case .mlDSA65:
            guard let key = try? MLDSA65.PublicKey(rawRepresentation: rawRepresentation) else { return false }
            return key.isValidSignature(signature, for: message)
        case .ed25519:
            guard let key = try? Curve25519.Signing.PublicKey(rawRepresentation: rawRepresentation) else { return false }
            return key.isValidSignature(signature, for: message)
        }
    }

    /// The key as a JWK: AKP for ML-DSA-65, per the JOSE ML-DSA draft, or OKP
    /// for Ed25519.
    public var jwk: String {
        let encoded = rawRepresentation.base64URL
        return switch algorithm {
        case .mlDSA65:
            JSON.object([("kty", JSON.string("AKP")), ("alg", JSON.string("ML-DSA-65")),
                         ("kid", JSON.string(id)), ("pub", JSON.string(encoded))])
        case .ed25519:
            JSON.object([("kty", JSON.string("OKP")), ("crv", JSON.string("Ed25519")),
                         ("kid", JSON.string(id)), ("x", JSON.string(encoded))])
        }
    }

    /// Why a JWK set or a raw key was refused. Each is one of the error
    /// classes the key set vectors name; see ``vectorClass``.
    public enum SetError: Error, Hashable, Sendable, CustomStringConvertible {
        /// Not a JWK set: not JSON, not an array or `{"keys": [...]}`, a key
        /// that is not an object, a member that is null, of the wrong type or
        /// named twice, or a key with no `kty` or no `kid`.
        case malformed(String)
        /// A key that is not AKP/ML-DSA-65 or OKP/Ed25519.
        case unsupported(kid: String)
        /// Key material that is not canonical base64url or not the algorithm's
        /// length, in a set or given raw.
        case invalid(kid: String, reason: String)
        /// A set naming one `kid` twice. Which of the two a token's `kid` would
        /// select is the kind of question a verifier must not answer by
        /// accident.
        case duplicateKeyID(String)

        public var vectorClass: String {
            switch self {
            case .malformed: "set_malformed"
            case .unsupported: "key_unsupported"
            case .invalid: "key_invalid"
            case .duplicateKeyID: "duplicate_kid"
            }
        }

        public var description: String {
            switch self {
            case let .malformed(why): "not a JWK set: \(why)"
            case let .unsupported(kid): "key \(kid): only AKP/ML-DSA-65 and OKP/Ed25519 are supported"
            case let .invalid(kid, reason): "key \(kid): \(reason)"
            case let .duplicateKeyID(kid): "key ID \(kid) appears twice in the set"
            }
        }
    }

    /// Read a JWK set, as a bare array or wrapped in `{"keys": [...]}`.
    ///
    /// The whole document is read first (``SetError/malformed(_:)``), then each
    /// key in order: it must be AKP/ML-DSA-65 or OKP/Ed25519
    /// (``SetError/unsupported(kid:)``), its public key must be canonical
    /// base64url of the right length (``SetError/invalid(kid:reason:)``), and
    /// its `kid` must not repeat one before it (``SetError/duplicateKeyID(_:)``).
    /// A key that fails is refused rather than skipped, because a set that
    /// silently lost a key verifies fewer tokens than its author thinks.
    /// Members a key does not need (`use`, `key_ops`) are ignored.
    public static func parseSet(_ document: Data) throws(SetError) -> [PublicKey] {
        guard UniqueMembers.check(document) else { throw .malformed("not JSON, or a member named twice") }
        let jwks: [JWK]
        do {
            if document.first(where: { !" \t\r\n".utf8.contains($0) }) == UInt8(ascii: "{") {
                jwks = try JSONDecoder().decode(Wrapped.self, from: document).keys
            } else {
                jwks = try JSONDecoder().decode([JWK].self, from: document)
            }
        } catch {
            throw .malformed("not an array of JWKs or {\"keys\": [...]}, or a JWK with a missing, null or mistyped member")
        }
        var keys: [PublicKey] = []
        var seen: Set<String> = []
        for jwk in jwks {
            let algorithm: Algorithm
            let field: String
            let name: String
            if jwk.kty == "AKP", jwk.alg == "ML-DSA-65" {
                (algorithm, field, name) = (.mlDSA65, jwk.pub, "pub")
            } else if jwk.kty == "OKP", jwk.crv == "Ed25519" {
                (algorithm, field, name) = (.ed25519, jwk.x, "x")
            } else {
                throw .unsupported(kid: jwk.kid)
            }
            guard let raw = Data(base64URL: field) else {
                throw .invalid(kid: jwk.kid, reason: "\(name) is not base64url")
            }
            let key = try PublicKey(id: jwk.kid, algorithm: algorithm, rawRepresentation: raw)
            guard seen.insert(jwk.kid).inserted else { throw .duplicateKeyID(jwk.kid) }
            keys.append(key)
        }
        return keys
    }

    /// One key of a set, with exact member names, a null refused, and `kty`
    /// and a non-empty `kid` required.
    private struct JWK: Decodable {
        let kty, crv, alg, kid, x, `pub`: String

        init(from decoder: any Decoder) throws {
            let c = try decoder.container(keyedBy: Member.self)
            guard c.contains(Member("kty")) else {
                throw DecodingError.keyNotFound(Member("kty"), .init(codingPath: c.codingPath, debugDescription: "no kty"))
            }
            kty = try c.value("kty", or: "")
            crv = try c.value("crv", or: "")
            alg = try c.value("alg", or: "")
            kid = try c.value("kid", or: "")
            x = try c.value("x", or: "")
            self.pub = try c.value("pub", or: "")
            if kid.isEmpty {
                throw DecodingError.dataCorrupted(.init(codingPath: c.codingPath, debugDescription: "no kid"))
            }
        }
    }

    private struct Wrapped: Decodable {
        let keys: [JWK]

        init(from decoder: any Decoder) throws {
            let c = try decoder.container(keyedBy: Member.self)
            guard c.contains(Member("keys")) else {
                throw DecodingError.keyNotFound(Member("keys"), .init(codingPath: c.codingPath, debugDescription: "no keys"))
            }
            keys = try c.value("keys", or: [])
        }
    }
}

/// Mints tokens with an ML-DSA-65 key.
public struct Signer: Sendable {
    private let privateKey: MLDSA65.PrivateKey
    /// The `kid` tokens from this signer carry.
    public let keyID: String

    /// A signer for `privateKey`, named `keyID` or by
    /// ``PublicKey/derivedID(for:)`` when nil.
    public init(privateKey: MLDSA65.PrivateKey, keyID: String? = nil) {
        self.privateKey = privateKey
        self.keyID = keyID ?? PublicKey.derivedID(for: privateKey.publicKey.rawRepresentation)
    }

    /// A signer from a 32-byte FIPS 204 seed.
    public init(seed: Data, keyID: String? = nil) throws {
        self.init(privateKey: try MLDSA65.PrivateKey(seedRepresentation: seed, publicKey: nil), keyID: keyID)
    }

    /// The 32-byte FIPS 204 seed, for storing the key.
    public var seed: Data { privateKey.seedRepresentation }

    /// The half a verifier needs.
    public var publicKey: PublicKey {
        PublicKey(checkedID: keyID, algorithm: .mlDSA65, rawRepresentation: privateKey.publicKey.rawRepresentation)
    }

    /// Mint a token carrying `claims`, exactly as given.
    ///
    /// Refused rather than repaired: ``TokenError/incomplete`` for claims with
    /// no subject, tenant or thumbprint, ``TokenError/thumbprint`` for a
    /// thumbprint that is not RFC 7638 SHA-256, and ``TokenError/lifetime`` for
    /// `iat` and `exp` unset, out of order, or more than fifteen minutes apart.
    /// CryptoKit's own failures are rethrown as they are.
    public func sign(_ claims: Claims) throws -> String {
        let input = try claims.signingInput(algorithm: .mlDSA65, keyID: keyID)
        return input + "." + (try signature(for: Data(input.utf8))).base64URL
    }

    /// Sign `message` with the token key, for a protocol that shares it.
    ///
    /// The caller owns the domain separation: `message` must never be a valid
    /// JWS signing input, or the signature could be spliced into a token.
    public func signature(for message: Data) throws -> Data {
        try privateKey.signature(for: message)
    }
}
