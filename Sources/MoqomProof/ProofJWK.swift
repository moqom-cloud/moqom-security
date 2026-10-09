// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

import CryptoKit
import Foundation

/// A proof's JOSE `alg`.
public enum ProofAlgorithm: String, Hashable, Sendable, CaseIterable {
    /// ML-DSA-87 (FIPS 204), signing the message directly with an empty
    /// context, as draft-ietf-cose-dilithium specifies for JOSE. The only
    /// algorithm, so every proof is post-quantum: ES256, ML-DSA-65 and every
    /// other algorithm are refused as ``ProofError/unsupported``.
    case mlDSA87 = "ML-DSA-87"

    /// The algorithm named `name` byte for byte, where `init(rawValue:)`
    /// would accept any canonically equivalent spelling.
    init?(exactly name: String) {
        guard let algorithm = Self.allCases.first(where: { $0.rawValue.utf8.elementsEqual(name.utf8) }) else {
            return nil
        }
        self = algorithm
    }
}

/// A device's public key as a JSON Web Key: `kty` `AKP` with `alg`
/// `ML-DSA-87` and `pub`.
///
/// Only the members a thumbprint is computed over are modelled.
public struct ProofJWK: Hashable, Sendable, Codable {
    public var kty: String
    public var alg: String?
    public var pub: String?

    /// Members that carry a private key: `d` (EC, OKP, RSA), RSA's other
    /// primes, `oct`'s `k`, and AKP's `priv` and `seed`. A proof carrying one
    /// has leaked its device key and is refused.
    static let privateMembers = ["d", "dp", "dq", "k", "oth", "p", "priv", "q", "qi", "seed"]

    static let mlDSA87PublicKeyBytes = 2592

    public init(kty: String, alg: String? = nil, pub: String? = nil) {
        self.kty = kty
        self.alg = alg
        self.pub = pub
    }

    private enum CodingKeys: String, CodingKey { case kty, alg, pub }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            kty: container.decodeIfPresent(String.self, forKey: .kty) ?? "",
            alg: container.decodeIfPresent(String.self, forKey: .alg),
            pub: container.decodeIfPresent(String.self, forKey: .pub)
        )
    }

    /// An `AKP` ML-DSA-87 key.
    public init(_ key: MLDSA87.PublicKey) {
        self.init(kty: "AKP", alg: ProofAlgorithm.mlDSA87.rawValue, pub: key.rawRepresentation.base64URL)
    }

    /// The members as a dictionary, absent ones omitted: what `/join` sends.
    public var members: [String: String] {
        var members = ["kty": kty]
        for (name, value) in [("alg", alg), ("pub", pub)] {
            if let value { members[name] = value }
        }
        return members
    }

    /// The proof algorithm this key signs with.
    /// Members are compared byte for byte, as Go and Rust compare them:
    /// Swift's `==` would take `A\u{212A}P`, with a Kelvin sign, for `AKP`.
    public func algorithm() throws(ProofError) -> ProofAlgorithm {
        func exactly(_ value: String?, _ expected: String) -> Bool {
            value.map { $0.utf8.elementsEqual(expected.utf8) } ?? false
        }
        if exactly(kty, "AKP"), exactly(alg, ProofAlgorithm.mlDSA87.rawValue) { return .mlDSA87 }
        throw .unsupported
    }

    /// The raw ML-DSA-87 public key.
    func decoded() throws(ProofError) -> Data {
        _ = try algorithm()
        return try Self.exact(pub, Self.mlDSA87PublicKeyBytes, "pub is not a base64url ML-DSA-87 key")
    }

    /// The required members in lexicographic order with no whitespace, rebuilt
    /// from the decoded key so a key has one form however it was spelled.
    public func canonical() throws(ProofError) -> String {
        #"{"alg":"ML-DSA-87","kty":"AKP","pub":"\#(try decoded().base64URL)"}"#
    }

    /// The JWK thumbprint, base64url SHA-256 of ``canonical()``, the form
    /// draft-ietf-cose-dilithium gives `AKP` keys, as RFC 7638 computes it.
    public func thumbprint() throws(ProofError) -> String {
        Data(SHA256.hash(data: Data(try canonical().utf8))).base64URL
    }

    private static func exact(_ value: String?, _ size: Int, _ why: String) throws(ProofError) -> Data {
        guard let value, let bytes = Data(strictBase64URL: value), bytes.count == size else {
            throw .malformed(why)
        }
        return bytes
    }
}

extension DataProtocol {
    /// base64url without padding, RFC 4648 §5.
    var base64URL: String {
        Data(self).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

extension Data {
    /// Strict base64url: no padding, nothing outside the alphabet, and the
    /// unused bits of the last character zero, so one value has one spelling.
    init?(strictBase64URL text: String) {
        guard text.utf8.allSatisfy({ byte in
            (byte >= UInt8(ascii: "A") && byte <= UInt8(ascii: "Z"))
                || (byte >= UInt8(ascii: "a") && byte <= UInt8(ascii: "z"))
                || (byte >= UInt8(ascii: "0") && byte <= UInt8(ascii: "9"))
                || byte == UInt8(ascii: "-") || byte == UInt8(ascii: "_")
        }), text.utf8.count % 4 != 1 else { return nil }
        var standard = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        standard += String(repeating: "=", count: (4 - standard.utf8.count % 4) % 4)
        guard let decoded = Data(base64Encoded: standard), decoded.base64URL == text else { return nil }
        self = decoded
    }
}
