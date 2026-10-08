// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

import CryptoKit
import Foundation

/// Checks proofs and spends their nonces.
public struct Checker: Sendable {
    /// A proof may not be larger than this, checked before any parsing. An
    /// ML-DSA-65 proof, key included, is about 8 KB.
    public static let maximumProofBytes = 16 * 1024

    /// How far a proof's `iat` may be from the checker's clock, either way.
    public static let defaultWindow: TimeInterval = 300

    public let store: any NonceStore
    public var algorithms: Set<ProofAlgorithm>
    public var window: TimeInterval
    /// Refuse every proof when ``check(_:token:certificateHash:thumbprint:now:until:)``
    /// is given no certificate, rather than accepting only proofs that name none.
    public var requireCertificate: Bool

    public init(
        store: any NonceStore,
        algorithms: Set<ProofAlgorithm> = Set(ProofAlgorithm.allCases),
        window: TimeInterval = Checker.defaultWindow,
        requireCertificate: Bool = false
    ) {
        self.store = store
        self.algorithms = algorithms
        self.window = window
        self.requireCertificate = requireCertificate
    }

    private struct Header: Decodable {
        var alg = ""
        var typ = ""
        var jwk: ProofJWK?
        var privateMember: String?

        private enum Keys: String, CodingKey { case alg, typ, jwk }
        private struct Member: CodingKey {
            var stringValue: String
            var intValue: Int? { nil }
            init(stringValue: String) { self.stringValue = stringValue }
            init?(intValue: Int) { nil }
        }

        init(from decoder: any Decoder) throws {
            let container = try decoder.container(keyedBy: Keys.self)
            alg = try container.decodeIfPresent(String.self, forKey: .alg) ?? ""
            typ = try container.decodeIfPresent(String.self, forKey: .typ) ?? ""
            jwk = try container.decodeIfPresent(ProofJWK.self, forKey: .jwk)
            if jwk != nil {
                privateMember = try container.nestedContainer(keyedBy: Member.self, forKey: .jwk).allKeys
                    .map(\.stringValue).first(where: ProofJWK.privateMembers.contains)
            }
        }
    }

    private struct Claims: Decodable {
        var ath = ""
        var iat: Int64?
        var jti = ""
        var rel = ""

        private enum Keys: String, CodingKey { case ath, iat, jti, rel }
        init(from decoder: any Decoder) throws {
            let container = try decoder.container(keyedBy: Keys.self)
            ath = try container.decodeIfPresent(String.self, forKey: .ath) ?? ""
            iat = try container.decodeIfPresent(Int64.self, forKey: .iat)
            jti = try container.decodeIfPresent(String.self, forKey: .jti) ?? ""
            rel = try container.decodeIfPresent(String.self, forKey: .rel) ?? ""
        }
    }

    /// Check that `proof` was signed by the key whose thumbprint is
    /// `thumbprint` (the token's `cnf.jkt`), over `token`, for the certificate
    /// whose SHA-256 is `certificateHash`, at a time within the window of
    /// `now`, and spend its nonce until `until` (normally the token's expiry).
    ///
    /// `certificateHash` is `nil` (or empty) only where the checker has no
    /// certificate of its own. The proof must then name no certificate either,
    /// since one it names cannot be checked, and a checker with
    /// ``requireCertificate`` refuses it.
    ///
    /// The signature is verified before any claim is read, and the nonce is
    /// spent only once every other check has passed, so a corrupted proof
    /// cannot burn a genuine one's nonce.
    public func check(
        _ proof: Data,
        token: Data,
        certificateHash: Data?,
        thumbprint: String,
        now: Date,
        until: Date
    ) throws(ProofError) {
        guard !proof.isEmpty, proof.count <= Self.maximumProofBytes else {
            throw .malformed("proof length is out of range")
        }
        let (headerSegment, claimsSegment, signed, signature) = try Self.split(proof)

        guard let header = Self.decode(Header.self, headerSegment) else {
            throw .malformed("header is not JSON")
        }
        guard let alg = ProofAlgorithm(rawValue: header.alg), algorithms.contains(alg),
              header.typ == proofType
        else { throw .unsupported }
        guard let jwk = header.jwk else { throw .malformed("header carries no key") }
        if let member = header.privateMember { throw .malformed("the key carries private member \(member)") }
        guard try jwk.algorithm() == alg else { throw .unsupported }

        let verified: Bool
        switch try jwk.decoded() {
        case let .mlDSA65(raw):
            guard let key = try? MLDSA65.PublicKey(rawRepresentation: raw) else {
                throw .malformed("the key is not a valid public key")
            }
            verified = key.isValidSignature(signature, for: signed)
        case let .es256(raw):
            guard let key = try? P256.Signing.PublicKey(x963Representation: Data([0x04]) + raw) else {
                throw .malformed("the key is not a valid public key")
            }
            verified = (try? P256.Signing.ECDSASignature(rawRepresentation: signature))
                .map { key.isValidSignature($0, for: signed) } ?? false
        }
        guard verified else { throw .badSignature }

        // Without this, anybody could sign with a key of their own beside a
        // stolen token.
        guard Self.constantTimeEqual(try jwk.thumbprint(), thumbprint) else { throw .wrongKey }

        guard let claims = Self.decode(Claims.self, claimsSegment) else {
            throw .malformed("claims are not JSON")
        }
        guard Self.constantTimeEqual(claims.ath, Data(SHA256.hash(data: token)).base64URL) else {
            throw .wrongToken
        }
        let certificate = certificateHash.flatMap { $0.isEmpty ? nil : $0 }
        if certificate == nil, requireCertificate { throw .wrongCertificate }
        guard Self.constantTimeEqual(claims.rel, certificate?.base64URL ?? "") else {
            throw .wrongCertificate
        }
        guard let iat = claims.iat else { throw .malformed("no iat") }
        let issued = Date(timeIntervalSince1970: TimeInterval(iat))
        if issued < now.addingTimeInterval(-window) { throw .expired }
        if issued > now.addingTimeInterval(window) { throw .notYetValid }
        guard !claims.jti.isEmpty else { throw .malformed("no jti to spend") }
        try store.spend(claims.jti, until: until, now: now)
    }

    /// A compact JWS's segments, with the signed bytes taken verbatim from the
    /// input: the signature is over bytes, and a round trip need not keep them.
    private static func split(_ jws: Data) throws(ProofError) -> (Data, Data, Data, Data) {
        let segments = jws.split(separator: UInt8(ascii: "."), omittingEmptySubsequences: false)
        guard segments.count == 3 else { throw .malformed("expected three segments") }
        guard let signature = Data(strictBase64URL: String(decoding: segments[2], as: UTF8.self)) else {
            throw .malformed("signature is not base64url")
        }
        return (
            Data(segments[0]),
            Data(segments[1]),
            Data(jws.prefix(segments[0].count + 1 + segments[1].count)),
            signature
        )
    }

    private static func decode<T: Decodable>(_ type: T.Type, _ segment: Data) -> T? {
        guard let raw = Data(strictBase64URL: String(decoding: segment, as: UTF8.self)) else { return nil }
        return try? JSONDecoder().decode(type, from: raw)
    }

    /// Compare without leaking where two values first differ.
    private static func constantTimeEqual(_ left: String, _ right: String) -> Bool {
        let left = Array(left.utf8), right = Array(right.utf8)
        guard left.count == right.count else { return false }
        return zip(left, right).reduce(UInt8(0)) { $0 | ($1.0 ^ $1.1) } == 0
    }
}
