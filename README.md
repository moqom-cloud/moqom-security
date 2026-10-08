# moqom-security

MOQOM's post-quantum security, as four libraries in Swift, Go and Rust:

| Library | Does | Standards |
| --- | --- | --- |
| [`moqom-token`](docs/moqom-token.md) | Mints and verifies join tokens: tenant, room, grants, expiry, device binding (`cnf.jkt`), key rotation by key ID | Compact JWS; ML-DSA-65 (FIPS 204), Ed25519 verify-only |
| [`moqom-proof`](docs/moqom-proof.md) | A device's single-use proof that it holds the key its token names, bound to the token and to the peer's certificate | RFC 9449 shape, RFC 7638 thumbprints; ML-DSA-65, ES256 accepted |
| [`moqom-sframe`](docs/moqom-sframe.md) | Seals and opens MoQ objects with their full track name and metadata bound into the tag | RFC 9605; binds the fields draft-ietf-moq-secure-objects authenticates |
| [`moqom-mls`](docs/moqom-mls.md) | Room key agreement that produces SFrame keys, and sealing an epoch's key to broadcast viewers | RFC 9420, `MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65` (draft-ietf-mls-pq-ciphersuites) |

These are the libraries MOQOM's apps, relays and control plane run. Every
language passes the same JSON test vectors in [`vectors/`](vectors/README.md),
including published RFC vectors where they exist.

No library implements a primitive. Each composes its platform's audited
implementation: CryptoKit (including the Secure Enclave) on Apple platforms, the
Go standard library, and AWS-LC through `aws-lc-rs` in Rust.

## Using it

Swift (iOS, macOS, visionOS and tvOS 26):

```swift
.package(url: "https://github.com/moqom-cloud/moqom-security", from: "0.1.0"),
// products: MoqomToken, MoqomProof, MoqomSFrame, MoqomMLS
```

Go 1.27:

```sh
go get github.com/moqom-cloud/moqom-security/go@v0.1.0
# packages: .../go/token, .../go/proof, .../go/sframe, .../go/mls
```

Rust 1.97:

```sh
cargo add moqom-token moqom-proof moqom-sframe moqom-mls
```

Reference documentation, with examples in all three languages, is at
[moqom.dev/security/libraries](https://moqom.dev/security/libraries/). Releases are listed in
[CHANGELOG.md](CHANGELOG.md).

## Layout

```
Package.swift, Sources/, Tests/   Swift package
go/                               Go module github.com/moqom-cloud/moqom-security/go
rust/                             Cargo workspace
vectors/                          shared test vectors
docs/                             one document per library
```

## Licence

Apache-2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE). "MOQOM" is a trademark
of Elliott Wave LLC. Report vulnerabilities as described in
[SECURITY.md](SECURITY.md).
