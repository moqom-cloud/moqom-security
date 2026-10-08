// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

import CryptoKit
import Foundation

/// A proof's JOSE `alg`.
public enum ProofAlgorithm: String, Hashable, Sendable, CaseIterable {
    /// ML-DSA-65 (FIPS 204), signing the message directly with an empty
    /// context, as draft-ietf-cose-dilithium specifies for JOSE. The default.
    case mlDSA65 = "ML-DSA-65"
    /// ECDSA on P-256 with SHA-256, the signature as fixed-width `r || s`.
    /// Accepted while devices holding older keys roll over.
    case es256 = "ES256"

    /// The algorithm named `name` byte for byte, where `init(rawValue:)`
    /// would accept any canonically equivalent spelling.
    init?(exactly name: String) {
        guard let algorithm = Self.allCases.first(where: { $0.rawValue.utf8.elementsEqual(name.utf8) }) else {
            return nil
        }
        self = algorithm
    }
}

/// A device's public key as a JSON Web Key: `kty` `AKP` with `alg` and `pub`
/// for ML-DSA-65, `kty` `EC` with `crv`, `x` and `y` for P-256.
///
/// Only the members a thumbprint is computed over are modelled.
public struct ProofJWK: Hashable, Sendable, Codable {
    public var kty: String
    public var alg: String?
    public var pub: String?
    public var crv: String?
    public var x: String?
    public var y: String?

    /// Members that carry a private key: `d` (EC, OKP, RSA), RSA's other
    /// primes, `oct`'s `k`, and AKP's `priv` and `seed`. A proof carrying one
    /// has leaked its device key and is refused.
    static let privateMembers = ["d", "dp", "dq", "k", "oth", "p", "priv", "q", "qi", "seed"]

    static let mlDSA65PublicKeyBytes = 1952
    static let p256CoordinateBytes = 32

    public init(
        kty: String, alg: String? = nil, pub: String? = nil,
        crv: String? = nil, x: String? = nil, y: String? = nil
    ) {
        self.kty = kty
        self.alg = alg
        self.pub = pub
        self.crv = crv
        self.x = x
        self.y = y
    }

    private enum CodingKeys: String, CodingKey { case kty, alg, pub, crv, x, y }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            kty: container.decodeIfPresent(String.self, forKey: .kty) ?? "",
            alg: container.decodeIfPresent(String.self, forKey: .alg),
            pub: container.decodeIfPresent(String.self, forKey: .pub),
            crv: container.decodeIfPresent(String.self, forKey: .crv),
            x: container.decodeIfPresent(String.self, forKey: .x),
            y: container.decodeIfPresent(String.self, forKey: .y)
        )
    }

    /// An `AKP` ML-DSA-65 key.
    public init(_ key: MLDSA65.PublicKey) {
        self.init(kty: "AKP", alg: ProofAlgorithm.mlDSA65.rawValue, pub: key.rawRepresentation.base64URL)
    }

    /// An `EC` P-256 key.
    public init(_ key: P256.Signing.PublicKey) {
        let raw = key.rawRepresentation
        self.init(
            kty: "EC", crv: "P-256",
            x: raw.prefix(Self.p256CoordinateBytes).base64URL,
            y: raw.suffix(Self.p256CoordinateBytes).base64URL
        )
    }

    /// The members as a dictionary, absent ones omitted: what `/join` sends.
    public var members: [String: String] {
        var members = ["kty": kty]
        for (name, value) in [("alg", alg), ("pub", pub), ("crv", crv), ("x", x), ("y", y)] {
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
        if exactly(kty, "AKP"), exactly(alg, ProofAlgorithm.mlDSA65.rawValue) { return .mlDSA65 }
        if exactly(kty, "EC"), exactly(crv, "P-256") { return .es256 }
        throw .unsupported
    }

    enum Decoded {
        case mlDSA65(Data)
        /// `x || y`, as CryptoKit's raw representation is.
        case es256(Data)
    }

    func decoded() throws(ProofError) -> Decoded {
        switch try algorithm() {
        case .mlDSA65:
            return .mlDSA65(try Self.exact(pub, Self.mlDSA65PublicKeyBytes, "pub is not a base64url ML-DSA-65 key"))
        case .es256:
            let x = try Self.exact(x, Self.p256CoordinateBytes, "x is not a base64url 32-byte coordinate")
            let y = try Self.exact(y, Self.p256CoordinateBytes, "y is not a base64url 32-byte coordinate")
            return .es256(x + y)
        }
    }

    /// The required members in lexicographic order with no whitespace, rebuilt
    /// from the decoded key so a key has one form however it was spelled.
    public func canonical() throws(ProofError) -> String {
        switch try decoded() {
        case let .mlDSA65(raw):
            return #"{"alg":"ML-DSA-65","kty":"AKP","pub":"\#(raw.base64URL)"}"#
        case let .es256(raw):
            let x = raw.prefix(Self.p256CoordinateBytes).base64URL
            let y = raw.suffix(Self.p256CoordinateBytes).base64URL
            return #"{"crv":"P-256","kty":"EC","x":"\#(x)","y":"\#(y)"}"#
        }
    }

    /// The JWK thumbprint, base64url SHA-256 of ``canonical()``: RFC 7638 for
    /// `EC`, draft-ietf-cose-dilithium for `AKP`.
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
