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
    public init(id: String? = nil, algorithm: Algorithm, rawRepresentation: Data) {
        self.id = id ?? Self.derivedID(for: rawRepresentation)
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

    /// Why a JWK set was refused.
    public struct SetError: Error, Hashable, Sendable, CustomStringConvertible {
        public let description: String
    }

    /// Read a JWK set, as a bare array or wrapped in `{"keys": [...]}`.
    ///
    /// Every key must be AKP/ML-DSA-65 or OKP/Ed25519 of the right length;
    /// anything else is refused rather than skipped, because a set that silently
    /// lost a key verifies fewer tokens than its author thinks.
    public static func parseSet(_ document: Data) throws(SetError) -> [PublicKey] {
        struct JWK: Decodable {
            let kty: String
            let crv: String?
            let alg: String?
            let kid: String
            let x: String?
            let `pub`: String?
        }
        struct Wrapped: Decodable { let keys: [JWK] }
        let decoder = JSONDecoder()
        let jwks: [JWK]
        if let wrapped = try? decoder.decode(Wrapped.self, from: document) {
            jwks = wrapped.keys
        } else if let bare = try? decoder.decode([JWK].self, from: document) {
            jwks = bare
        } else {
            throw SetError(description: "not a JWK set")
        }
        var keys: [PublicKey] = []
        for jwk in jwks {
            let algorithm: Algorithm
            let field: String?
            if jwk.kty == "AKP", jwk.alg == "ML-DSA-65" {
                (algorithm, field) = (.mlDSA65, jwk.pub)
            } else if jwk.kty == "OKP", jwk.crv == "Ed25519" {
                (algorithm, field) = (.ed25519, jwk.x)
            } else {
                throw SetError(description: "key \(jwk.kid): only AKP/ML-DSA-65 and OKP/Ed25519 are supported")
            }
            guard let raw = field.flatMap({ Data(base64URL: $0) }), raw.count == algorithm.publicKeyBytes else {
                throw SetError(description: "key \(jwk.kid): not a \(algorithm.publicKeyBytes)-byte base64url key")
            }
            keys.append(PublicKey(id: jwk.kid, algorithm: algorithm, rawRepresentation: raw))
        }
        return keys
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

    /// The half a verifier needs.
    public var publicKey: PublicKey {
        PublicKey(id: keyID, algorithm: .mlDSA65, rawRepresentation: privateKey.publicKey.rawRepresentation)
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
