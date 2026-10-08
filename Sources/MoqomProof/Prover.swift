// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

import CryptoKit
import Foundation

/// The JWS `typ` of a proof, so that a JWS made for anything else, including a
/// token from the same deployment, is not one.
public let proofType = "MOQT-POP"

/// A device key, and the proofs it signs.
public struct Prover: Sendable {
    /// Where the private key is held. The enclave keys cannot be exported.
    public enum Key: Sendable {
        case mlDSA65(MLDSA65.PrivateKey)
        case secureEnclaveMLDSA65(SecureEnclave.MLDSA65.PrivateKey)
        case es256(P256.Signing.PrivateKey)
        case secureEnclaveES256(SecureEnclave.P256.Signing.PrivateKey)
    }

    public let key: Key

    /// The public key, as a proof carries it and `/join` receives it.
    public let jwk: ProofJWK

    /// The JWK thumbprint, what a token's `cnf.jkt` must equal.
    public let thumbprint: String

    private let header: String

    public init(_ key: Key) {
        self.key = key
        let jwk = switch key {
        case let .mlDSA65(key): ProofJWK(key.publicKey)
        case let .secureEnclaveMLDSA65(key): ProofJWK(key.publicKey)
        case let .es256(key): ProofJWK(key.publicKey)
        case let .secureEnclaveES256(key): ProofJWK(key.publicKey)
        }
        self.jwk = jwk
        // A key CryptoKit produced always has a canonical form.
        let canonical = (try? jwk.canonical()) ?? ""
        thumbprint = Data(SHA256.hash(data: Data(canonical.utf8))).base64URL
        header = #"{"alg":"\#(Self.algorithm(of: key).rawValue)","typ":"\#(proofType)","jwk":\#(canonical)}"#
    }

    /// The algorithm this key signs with.
    public var algorithm: ProofAlgorithm { Self.algorithm(of: key) }

    private static func algorithm(of key: Key) -> ProofAlgorithm {
        switch key {
        case .mlDSA65, .secureEnclaveMLDSA65: .mlDSA65
        case .es256, .secureEnclaveES256: .es256
        }
    }

    /// Sign a proof that this key holds `token`, for the peer whose leaf
    /// certificate has SHA-256 `certificateHash`, using `nonce` as its
    /// single-use `jti` and `issuedAt` as its `iat`.
    ///
    /// `nonce` must be fresh for every proof; ``nonce()`` makes one. An empty
    /// `certificateHash` binds the proof to no certificate, which a checker
    /// that knows its own refuses.
    public func prove(
        token: Data,
        certificateHash: Data,
        nonce: String,
        issuedAt: Date = Date()
    ) throws(ProofError) -> Data {
        guard !nonce.isEmpty else { throw .malformed("a proof needs a nonce") }
        guard let quoted = try? JSONSerialization.data(withJSONObject: nonce, options: .fragmentsAllowed) else {
            throw .malformed("nonce")
        }
        let iat = Int64(issuedAt.timeIntervalSince1970.rounded(.down))
        let ath = Data(SHA256.hash(data: token)).base64URL
        let claims = #"{"ath":"\#(ath)","iat":\#(iat),"jti":\#(String(decoding: quoted, as: UTF8.self)),"rel":"\#(certificateHash.base64URL)"}"#
        let signed = "\(Data(header.utf8).base64URL).\(Data(claims.utf8).base64URL)"
        let signature: Data
        do {
            signature = try sign(Data(signed.utf8))
        } catch {
            throw .notSigned
        }
        return Data("\(signed).\(signature.base64URL)".utf8)
    }

    /// `rawRepresentation` for ECDSA: fixed-width `r || s`, as JWS requires.
    private func sign(_ message: Data) throws -> Data {
        switch key {
        case let .mlDSA65(key): try key.signature(for: message)
        case let .secureEnclaveMLDSA65(key): try key.signature(for: message)
        case let .es256(key): try key.signature(for: message).rawRepresentation
        case let .secureEnclaveES256(key): try key.signature(for: message).rawRepresentation
        }
    }

    /// A fresh 128-bit nonce, base64url.
    public static func nonce() -> String {
        SymmetricKey(size: .bits128).withUnsafeBytes { Data($0) }.base64URL
    }
}
