// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

import CryptoKit
import Foundation

/// Checks proofs and spends their nonces.
public struct Checker: Sendable {
    /// A proof may not be larger than this, checked before any parsing. An
    /// ML-DSA-87 proof, key included, is about 11 KB.
    public static let maximumProofBytes = 16 * 1024

    /// How far a proof's `iat` may be from the checker's clock, either way,
    /// unless the checker is made with another `window`.
    public static let defaultWindow: TimeInterval = 300

    public let store: any NonceStore
    public let algorithms: Set<ProofAlgorithm>
    public let window: TimeInterval
    /// Refuse every proof when ``check(_:token:certificateHash:thumbprint:now:until:)``
    /// is given no certificate, rather than accepting only proofs that name none.
    public let requireCertificate: Bool

    /// A checker accepting every ``ProofAlgorithm`` within ``defaultWindow``,
    /// spending nonces in `store`.
    public init(store: any NonceStore) {
        self.store = store
        algorithms = Set(ProofAlgorithm.allCases)
        window = Self.defaultWindow
        requireCertificate = false
    }

    /// A checker with settings other than the defaults.
    ///
    /// - Throws: ``ProofError/configuration(_:)`` if `algorithms` is empty or
    ///   `window` is not a positive number of seconds.
    public init(
        store: any NonceStore,
        algorithms: Set<ProofAlgorithm> = Set(ProofAlgorithm.allCases),
        window: TimeInterval = Checker.defaultWindow,
        requireCertificate: Bool = false
    ) throws(ProofError) {
        guard !algorithms.isEmpty else { throw .configuration("a checker must accept at least one algorithm") }
        guard window.isFinite, window > 0 else { throw .configuration("window \(window) is not positive") }
        self.store = store
        self.algorithms = algorithms
        self.window = window
        self.requireCertificate = requireCertificate
    }

    private struct Header {
        var alg = ""
        var typ = ""
        var jwk: ProofJWK?
        var privateMember: String?

        /// `nil` unless `json` is one object whose known members have their
        /// types; the key's members are typed here too, whatever the `alg`.
        init?(_ json: Data) {
            guard let object = StrictJSON(json) else { return nil }
            do {
                alg = try object.string("alg") ?? ""
                typ = try object.string("typ") ?? ""
                if let key = try object.object("jwk") {
                    jwk = try ProofJWK(
                        kty: key.string("kty") ?? "", alg: key.string("alg"), pub: key.string("pub")
                    )
                    privateMember = ProofJWK.privateMembers.first(where: key.has)
                }
            } catch {
                return nil
            }
        }
    }

    private struct Claims {
        var ath = ""
        var iat: Int64?
        var jti = ""
        var rel = ""

        init?(_ json: Data) {
            guard let object = StrictJSON(json) else { return nil }
            do {
                ath = try object.string("ath") ?? ""
                iat = try object.integer("iat")
                jti = try object.string("jti") ?? ""
                rel = try object.string("rel") ?? ""
            } catch {
                return nil
            }
        }
    }

    /// Check that `proof` was signed by the key whose thumbprint is
    /// `thumbprint` (the token's `cnf.jkt`), over `token`, for the certificate
    /// whose SHA-256 is `certificateHash`, at a time within the window of
    /// `now`, and spend its nonce until `until` (normally the token's expiry),
    /// or until one second past the end of the proof's window if that is later.
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

        guard let header = Self.decode(headerSegment).flatMap(Header.init) else {
            throw .malformed("header is not JSON")
        }
        guard let alg = ProofAlgorithm(exactly: header.alg), algorithms.contains(alg),
              header.typ.utf8.elementsEqual(proofType.utf8)
        else { throw .unsupported }
        guard let jwk = header.jwk else { throw .malformed("header carries no key") }
        if let member = header.privateMember { throw .malformed("the key carries private member \(member)") }
        guard try jwk.algorithm() == alg else { throw .unsupported }

        guard let key = try? MLDSA87.PublicKey(rawRepresentation: try jwk.decoded()) else {
            throw .malformed("the key is not a valid public key")
        }
        guard key.isValidSignature(signature, for: signed) else { throw .badSignature }

        // Without this, anybody could sign with a key of their own beside a
        // stolen token.
        guard Self.constantTimeEqual(try jwk.thumbprint(), thumbprint) else { throw .wrongKey }

        guard let claims = Self.decode(claimsSegment).flatMap(Claims.init) else {
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
        // The proof is accepted until issued + window, inclusive, and a store
        // keeps a nonce while its until is after now. A shorter until would
        // let the same proof in again once the store forgot it.
        try store.spend(claims.jti, until: max(until, issued.addingTimeInterval(window + 1)), now: now)
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

    private static func decode(_ segment: Data) -> Data? {
        Data(strictBase64URL: String(decoding: segment, as: UTF8.self))
    }

    /// Compare without leaking where two values first differ.
    private static func constantTimeEqual(_ left: String, _ right: String) -> Bool {
        let left = Array(left.utf8), right = Array(right.utf8)
        guard left.count == right.count else { return false }
        return zip(left, right).reduce(UInt8(0)) { $0 | ($1.0 ^ $1.1) } == 0
    }
}
