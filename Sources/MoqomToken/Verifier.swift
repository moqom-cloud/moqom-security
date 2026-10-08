// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

import Foundation

/// Checks tokens against a set of keys.
///
/// A set rather than one key, because rotation needs an overlap: the new key is
/// published, signing moves to it, and the old one stays verifiable until the
/// last token it signed has expired.
public struct Verifier: Sendable {
    /// By the UTF-8 of each `kid`: Go and Rust match IDs byte for byte, where
    /// Swift's `String` would match canonically equivalent ones.
    private let keys: [[UInt8]: PublicKey]
    /// The only `iss` accepted; empty accepts any.
    public let issuer: String
    /// The only tenant accepted; empty accepts any.
    public let tenant: String

    public init(issuer: String = "", tenant: String = "", keys: [PublicKey]) {
        var byID: [[UInt8]: PublicKey] = [:]
        for key in keys { byID[Array(key.id.utf8)] = key }
        self.keys = byID
        self.issuer = issuer
        self.tenant = tenant
    }

    /// Whether the verifier holds no key, and so verifies nothing.
    public var isEmpty: Bool { keys.isEmpty }

    /// The key named `id`, if the set has one.
    public func key(_ id: String) -> PublicKey? { keys[Array(id.utf8)] }

    /// Check `token` at `now` and return its claims.
    ///
    /// The signature is checked before any claim is read: acting on a claim
    /// from an unverified token, even to word an error, is how a parser becomes
    /// an attack surface. Then the claims, in this order: issuer, expiry,
    /// not-before, lifetime, completeness, thumbprint, tenant.
    public func verify(_ token: Data, now: Date) throws(TokenError) -> Claims {
        guard !token.isEmpty, token.count <= TokenLimits.maximumTokenBytes else {
            throw .malformed("token length is out of range")
        }
        let segments = token.split(separator: UInt8(ascii: "."), omittingEmptySubsequences: false)
        guard segments.count == 3 else { throw .malformed("expected three segments") }
        let (headerSegment, claimsSegment, signatureSegment) = (segments[0], segments[1], segments[2])

        guard let headerBytes = Self.decode(headerSegment) else { throw .malformed("header is not base64url") }
        guard let header = Header(headerBytes) else { throw .malformed("header is not JSON") }
        guard header.typ == TokenLimits.type else { throw .unsupported }
        guard let key = keys[Array(header.kid.utf8)] else { throw .unknownKey }
        guard header.alg == key.algorithm.rawValue else { throw .unsupported }

        guard let signature = Self.decode(signatureSegment) else { throw .malformed("signature is not base64url") }
        // The signed message is the first two segments verbatim: a round trip
        // through a parser would not reproduce them, and the signature is over
        // bytes.
        let signed = Data(token.prefix(headerSegment.count + 1 + claimsSegment.count))
        guard key.isValidSignature(signature, for: signed) else { throw .badSignature }

        guard let claimsBytes = Self.decode(claimsSegment) else { throw .malformed("claims are not base64url") }
        let claims = try Claims(json: claimsBytes)
        try check(claims, now: now)
        return claims
    }

    /// The same, for a token held as text.
    public func verify(_ token: String, now: Date) throws(TokenError) -> Claims {
        try verify(Data(token.utf8), now: now)
    }

    private func check(_ claims: Claims, now: Date) throws(TokenError) {
        if !issuer.isEmpty, !claims.issuer.utf8.elementsEqual(issuer.utf8) { throw .wrongIssuer }
        if claims.expires == 0 { throw .malformed("no expiry") }
        // Whole seconds, as the claims are, so every implementation draws the
        // boundaries at the same instant.
        let seconds = Int64(now.timeIntervalSince1970.rounded(.down))
        let skew = TokenLimits.clockSkew, limit = TokenLimits.maximumLifetime
        if seconds - skew > claims.expires { throw .expired }
        if claims.issuedAt != 0, seconds + skew < claims.issuedAt { throw .notYetValid }
        // Without `iat` the lifetime is measured from now, with the skew
        // allowed, so leaving it out cannot buy a longer token.
        let tooLong = claims.issuedAt == 0
            ? claims.expires - seconds > limit + skew
            : claims.expires - claims.issuedAt > limit
        if tooLong { throw .lifetime }
        if claims.subject.isEmpty || claims.tenant.isEmpty || claims.thumbprint.isEmpty { throw .incomplete }
        if !Claims.isValidThumbprint(claims.thumbprint) { throw .thumbprint }
        if !tenant.isEmpty, !claims.tenant.utf8.elementsEqual(tenant.utf8) { throw .wrongTenant }
    }

    private static func decode(_ segment: Data.SubSequence) -> Data? {
        guard let text = String(bytes: segment, encoding: .ascii) else { return nil }
        return Data(base64URL: text)
    }

    /// Exactly alg, typ and kid. Any other parameter is refused, since one this
    /// build does not know (`crit`, `jku`, `x5u`) may change what the signature
    /// means.
    private struct Header {
        let alg: String
        let typ: String
        let kid: String
        init?(_ json: Data) {
            do throws(StrictJSON.Invalid) {
                guard let header = StrictJSON(json) else { return nil }
                try header.only(["alg", "typ", "kid"])
                alg = try header.string("alg") ?? ""
                typ = try header.string("typ") ?? ""
                kid = try header.string("kid") ?? ""
            } catch {
                return nil
            }
        }
    }
}
