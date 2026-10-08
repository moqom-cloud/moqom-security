// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

// moqom-token: mint and verify the credential a MOQOM client joins a relay with.
//
// A token is a compact JWS (RFC 7515) over JSON claims, typed `MOQT`, signed
// with ML-DSA-65 (FIPS 204, JOSE `ML-DSA-65`, JWK `kty` `AKP`). Ed25519
// (`EdDSA`) keys verify and never sign, so tokens issued before the move to
// ML-DSA stay good until they expire. The key a token names by `kid` decides the
// algorithm it is verified with; the header's `alg` must agree and is never
// trusted on its own.
//
// `Signer.sign(_:)` and `Verifier.verify(_:now:)` are the whole API, the same as
// the Go and Rust libraries, and all three pass the vectors in `vectors/token`.

import Foundation

/// Limits every implementation shares.
public enum TokenLimits {
    /// The JWS `typ` every token carries, so a JWS minted for anything else in a
    /// deployment cannot be replayed at a relay.
    public static let type = "MOQT"
    /// The longest a token is good for, from `iat` to `exp`, in seconds,
    /// enforced when signing and when verifying.
    public static let maximumLifetime: Int64 = 15 * 60
    /// How much disagreement between the minting and verifying clocks is
    /// tolerated, in seconds.
    public static let clockSkew: Int64 = 30
    /// A token may not be larger than this, checked before anything is decoded.
    public static let maximumTokenBytes = 8192
}

/// Why a token was refused, to sign or to verify.
///
/// Each is one of the error classes the shared vectors name; see
/// ``errorClass``. The descriptions are the relay's wording.
public enum TokenError: Error, Hashable, Sendable, CustomStringConvertible {
    /// Not a well-formed token, or claims that cannot be encoded.
    case malformed(String)
    /// Not a MOQT token, or naming an algorithm other than its key's.
    case unsupported
    /// Signed by a key the verifier does not hold.
    case unknownKey
    /// The signature does not verify.
    case badSignature
    /// Past its expiry by more than the skew.
    case expired
    /// Issued in the future by more than the skew.
    case notYetValid
    /// `iat` and `exp` unset, out of order, or further apart than the maximum.
    case lifetime
    /// Issued by another deployment.
    case wrongIssuer
    /// For a tenant the verifier is not pinned to.
    case wrongTenant
    /// Does not name a subject, a tenant and a device.
    case incomplete
    /// `cnf.jkt` is not an RFC 7638 SHA-256 thumbprint.
    case thumbprint

    public var errorClass: String {
        switch self {
        case .malformed: "malformed"
        case .unsupported: "unsupported"
        case .unknownKey: "unknown_key"
        case .badSignature: "bad_signature"
        case .expired: "expired"
        case .notYetValid: "not_yet_valid"
        case .lifetime: "lifetime"
        case .wrongIssuer: "wrong_issuer"
        case .wrongTenant: "wrong_tenant"
        case .incomplete: "incomplete"
        case .thumbprint: "thumbprint"
        }
    }

    public var description: String {
        switch self {
        case let .malformed(why): "token is malformed: \(why)"
        case .unsupported: "token algorithm or type is not supported"
        case .unknownKey: "token was signed by an unknown key"
        case .badSignature: "token signature does not verify"
        case .expired: "token has expired"
        case .notYetValid: "token is not valid yet"
        case .lifetime: "token lifetime is out of range"
        case .wrongIssuer: "token was issued by another deployment"
        case .wrongTenant: "token is for another tenant"
        case .incomplete: "token does not name a complete identity"
        case .thumbprint: "token is not bound to an RFC 7638 SHA-256 thumbprint"
        }
    }
}

extension Data {
    /// base64url without padding.
    var base64URL: String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Strict base64url without padding: padding, a character outside the
    /// alphabet, or non-zero trailing bits (a second spelling of the same
    /// bytes) are refused.
    init?(base64URL text: some StringProtocol) {
        let alphabet = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        guard text.allSatisfy(alphabet.contains), text.count % 4 != 1 else { return nil }
        var standard = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        standard += String(repeating: "=", count: (4 - standard.count % 4) % 4)
        guard let decoded = Data(base64Encoded: standard), decoded.base64URL == text else { return nil }
        self = decoded
    }
}
