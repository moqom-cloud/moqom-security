// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

/// Why a proof or a key was refused, or a proof could not be made.
public enum ProofError: Error, Hashable, Sendable, CustomStringConvertible {
    /// Not a well-formed proof or key.
    case malformed(String)
    /// An algorithm, type or key kind this checker does not accept.
    case unsupported
    /// The signature does not verify under the key the proof carries.
    case badSignature
    /// It verified, under a key the token was not issued to.
    case wrongKey
    /// It verified, and commits to a different token.
    case wrongToken
    /// It verified, and was made for another peer certificate.
    case wrongCertificate
    /// Its `iat` is further in the past than the window.
    case expired
    /// Its `iat` is further in the future than the window.
    case notYetValid
    /// Its nonce has been spent.
    case replayed
    /// The nonce store cannot remember another. Fails closed.
    case overloaded
    /// The key refused to sign.
    case notSigned
    /// A checker or store built with settings that cannot work: no
    /// algorithms, or a window or capacity that is not positive.
    case configuration(String)

    /// The error class the shared vectors name.
    public var errorClass: String {
        switch self {
        case .malformed: "malformed"
        case .unsupported: "unsupported"
        case .badSignature: "bad_signature"
        case .wrongKey: "wrong_key"
        case .wrongToken: "wrong_token"
        case .wrongCertificate: "wrong_certificate"
        case .expired: "expired"
        case .notYetValid: "not_yet_valid"
        case .replayed: "replayed"
        case .overloaded: "overloaded"
        case .notSigned: "signing"
        case .configuration: "configuration"
        }
    }

    public var description: String {
        switch self {
        case let .malformed(why): "proof is malformed: \(why)"
        case .unsupported: "proof algorithm, type or key is not supported"
        case .badSignature: "proof signature does not verify"
        case .wrongKey: "proof is signed by a key the token was not issued to"
        case .wrongToken: "proof was made for a different token"
        case .wrongCertificate: "proof was made for another peer certificate"
        case .expired: "proof was issued too long ago"
        case .notYetValid: "proof is issued in the future"
        case .replayed: "proof nonce has already been spent"
        case .overloaded: "nonce store is full"
        case .notSigned: "signing the proof failed"
        case let .configuration(why): "proof checker or nonce store is misconfigured: \(why)"
        }
    }
}
