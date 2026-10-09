// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

// The device-bound sign-in example on moqom.dev, against the public API only.

import CryptoKit
import Foundation
import MoqomProof
import MoqomToken
import Testing

/// Your backend, reduced to the two calls that matter.
private final class Backend: Sendable {
    let issuer: Signer
    let verifier: Verifier
    let checker: Checker
    /// SHA-256 of this server's TLS leaf certificate, in DER.
    let certificateHash: Data

    init(certificateHash: Data) throws {
        // Generate the issuer key once and keep `issuer.seed` in your secret manager.
        issuer = Signer(privateKey: try MLDSA65.PrivateKey(), keyID: "2026-10")
        verifier = Verifier(issuer: "https://api.example.com", tenant: "acme", keys: [issuer.publicKey])
        checker = try Checker(store: MemoryNonceStore(), algorithms: [.mlDSA65], requireCertificate: true)
        self.certificateHash = certificateHash
    }

    /// `POST /enrol`, after your existing sign-in: the device sends its public key.
    func enrol(user: String, key body: Data) throws -> String {
        let key = try JSONDecoder().decode(ProofJWK.self, from: body)
        let now = Int64(Date().timeIntervalSince1970)
        return try issuer.sign(Claims(
            issuer: "https://api.example.com",
            subject: user,
            tenant: "acme",
            id: Prover.nonce(),
            issuedAt: now,
            expires: now + 15 * 60,
            thumbprint: try key.thumbprint() // derived here, never taken from the device
        ))
    }

    /// Any other request: verify the token, then the proof.
    func me(token: String, proof: Data) -> String {
        let now = Date()
        do {
            let claims = try verifier.verify(token, now: now)
            try checker.check(proof, token: Data(token.utf8), certificateHash: certificateHash,
                              thumbprint: claims.thumbprint, now: now, until: claims.expiresDate)
            return "200 hello \(claims.subject)"
        } catch let error as TokenError {
            return "401 \(error.errorClass)"
        } catch let error as ProofError {
            return "401 \(error.errorClass)"
        } catch {
            return "500"
        }
    }
}

/// Sends requests with the device-bound token, each with a fresh proof.
private struct SignedClient {
    let device: Prover
    let certificateHash: Data
    let session: URLSession

    init(device: Prover, certificateHash: Data) {
        self.device = device
        self.certificateHash = certificateHash
        session = URLSession(configuration: .ephemeral,
                             delegate: PinnedServer(certificateHash: certificateHash),
                             delegateQueue: nil)
    }

    func data(for request: URLRequest, token: String) async throws -> (Data, URLResponse) {
        var request = request
        let proof = try device.prove(token: Data(token.utf8), certificateHash: certificateHash, nonce: Prover.nonce())
        request.setValue("MOQT \(token)", forHTTPHeaderField: "Authorization")
        request.setValue(String(decoding: proof, as: UTF8.self), forHTTPHeaderField: "MOQT-Proof")
        return try await session.data(for: request)
    }
}

/// Refuses any server whose leaf certificate is not the one the proofs name.
private final class PinnedServer: NSObject, URLSessionDelegate {
    let certificateHash: Data

    init(certificateHash: Data) { self.certificateHash = certificateHash }

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge
    ) async -> (URLSession.AuthChallengeDisposition, URLCredential?) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust,
              SecTrustEvaluateWithError(trust, nil),
              let leaf = (SecTrustCopyCertificateChain(trust) as? [SecCertificate])?.first,
              Data(SHA256.hash(data: SecCertificateCopyData(leaf) as Data)) == certificateHash
        else { return (.cancelAuthenticationChallenge, nil) }
        return (.useCredential, URLCredential(trust: trust))
    }
}

/// The app's enrolment, compiled but not run: `swift test` may have no Secure Enclave.
private func enrolmentInAnApp() throws -> Data {
    // Once per device: a key in the Secure Enclave. Keep key.dataRepresentation in the keychain
    // and load it again with SecureEnclave.MLDSA65.PrivateKey(dataRepresentation:).
    let key = try SecureEnclave.MLDSA65.PrivateKey()
    let device = Prover(.secureEnclaveMLDSA65(key))
    return try JSONEncoder().encode(device.jwk) // POST this after your sign-in
}

@Suite struct SignInExampleTests {
    @Test func deviceBoundSignIn() throws {
        let serverCertificate = Data(SHA256.hash(data: Data("your server's leaf certificate, DER".utf8)))
        let backend = try Backend(certificateHash: serverCertificate)

        // On the device. In an app: Prover(.secureEnclaveMLDSA65(try SecureEnclave.MLDSA65.PrivateKey())).
        let device = Prover(.mlDSA65(try MLDSA65.PrivateKey()))
        let token = try backend.enrol(user: "ada", key: try JSONEncoder().encode(device.jwk))

        // Each request: the token, and a fresh proof for the server's certificate.
        let proof = try device.prove(token: Data(token.utf8), certificateHash: serverCertificate, nonce: Prover.nonce())
        #expect(backend.me(token: token, proof: proof) == "200 hello ada")

        // The same request sent again.
        #expect(backend.me(token: token, proof: proof) == "401 replayed")

        // A stolen token, proved with the thief's own key.
        let thief = Prover(.mlDSA65(try MLDSA65.PrivateKey()))
        let stolen = try thief.prove(token: Data(token.utf8), certificateHash: serverCertificate, nonce: Prover.nonce())
        #expect(backend.me(token: token, proof: stolen) == "401 wrong_key")

        // A proof the device made for a machine in the middle, forwarded on.
        let middle = Data(SHA256.hash(data: Data("the interceptor's certificate".utf8)))
        let intercepted = try device.prove(token: Data(token.utf8), certificateHash: middle, nonce: Prover.nonce())
        #expect(backend.me(token: token, proof: intercepted) == "401 wrong_certificate")

        // The token alone, as a bearer token.
        #expect(backend.me(token: token, proof: Data()) == "401 malformed")
    }
}
