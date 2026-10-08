<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Elliott Wave LLC -->

# moqom-proof

Device proof of possession for MOQOM sessions. A join token names a device key
by its JWK thumbprint (`cnf.jkt`, see [moqom-token](moqom-token.md)). A token on
its own is a bearer credential: whoever copies it can use it. A proof turns it
into a sender-constrained one. At connect, and again with every in-session
token renewal, the device signs a fresh single-use proof. The proof commits to
the token, to the TLS certificate of the peer it is talking to, and to the time.
The peer checks that the proof was signed by the key the token names.

Proofs follow the shape of RFC 9449 (DPoP), adapted to a MoQ session instead of
an HTTP request. There is no `htm`/`htu`; the peer's certificate takes their
place.

The library is the same in Swift (`MoqomProof`), Go
(`github.com/moqom-cloud/moqom-security/go/proof`) and Rust (`moqom-proof`).
All three pass every case in [`vectors/proof`](../vectors/proof).

## What it does

- **Binds a proof to one token.** `ath` is the SHA-256 of the token bytes. A
  proof made for one token is `wrong_token` for every other, including the
  token a renewal replaces it with.
- **Binds a proof to one peer.** `rel` is the SHA-256 of the receiving peer's
  TLS leaf certificate (DER). A proof captured by, or presented to, one relay
  is `wrong_certificate` at any other. A checker that has no certificate of its
  own (an in-process harness) passes none, or an empty hash. A proof must then
  name no certificate either (`rel` empty or absent): one it names cannot be
  checked, so it is `wrong_certificate`. A checker configured to require a
  certificate (Go `RequireCertificate`, Rust `with_certificate_required`,
  Swift `requireCertificate:`) refuses every proof when it has none.
- **Single use.** `jti` is a fresh 128-bit nonce. The checker spends it in a
  caller-supplied `NonceStore` until the token expires. A second proof over
  the same token with a new nonce is a new session, not a replay.
- **Fresh.** `iat` must be within a window (default five minutes) of the
  checker's clock, either way.
- **Two algorithms.** ML-DSA-65 (FIPS 204) is the default and the only
  algorithm new devices generate. ES256 (P-256) is still accepted while
  devices holding older keys roll over. A checker can be limited to a subset.
- **The algorithm belongs to the key.** The header's `alg` must match the
  embedded JWK's key type. Anything else is `unsupported`.
- **Signature first.** No claim is read before the signature has verified
  against the embedded key and that key's thumbprint has matched the token's
  `cnf.jkt`. The nonce is spent only after every other check passes, so a
  corrupted proof cannot burn a genuine proof's nonce.

## Device keys

| Platform | ML-DSA-65 key | ES256 key (rollover only) |
| --- | --- | --- |
| Swift, device with a Secure Enclave | `SecureEnclave.MLDSA65.PrivateKey` | `SecureEnclave.P256.Signing.PrivateKey` |
| Swift, no enclave (macOS without one, tests) | `MLDSA65.PrivateKey` | `P256.Signing.PrivateKey` |
| Go | `*mldsa.PrivateKey` (`crypto/mldsa`), or any `crypto.Signer` holding one | `*ecdsa.PrivateKey` |
| Rust | aws-lc-rs ML-DSA-65 from a 32-byte seed or PKCS#8 | aws-lc-rs P-256 from PKCS#8 |

Swift's `MoqomKit.DeviceKey` chooses: an enclave key when
`SecureEnclave.isAvailable` and creation succeeds, otherwise a software key.

ML-DSA-65 signing is deterministic in Go and Rust, so the vectors reproduce
those proofs byte for byte. CryptoKit signs with hedged randomness, and ES256
is randomised everywhere. For those, the vectors give proofs to verify, not
proofs to reproduce.

## Wire format

A proof is a compact JWS: `base64url(header) "." base64url(claims) "."
base64url(signature)`. Base64url has no padding and is strict: the unused bits
of the last character must be zero.

Header:

```json
{"alg":"ML-DSA-65","typ":"MOQT-POP","jwk":{"alg":"ML-DSA-65","kty":"AKP","pub":"…"}}
{"alg":"ES256","typ":"MOQT-POP","jwk":{"crv":"P-256","kty":"EC","x":"…","y":"…"}}
```

- `typ` is always `MOQT-POP`.
- `jwk` is the device's public key. For ML-DSA-65 this is `kty` `AKP`, `alg`
  `ML-DSA-65` and `pub`, the 1,952-byte raw public key in base64url
  (draft-ietf-cose-dilithium). For ES256 it is an RFC 7517 EC key with 32-byte
  coordinates in canonical base64url. Any other length or spelling is
  `malformed`. So is a `jwk` with a private member (`d`, `p`, `q`, `dp`, `dq`,
  `qi`, `oth`, `k`, `priv` or `seed`), whatever its value, even `null`: the
  device has published its key.

Claims:

```json
{"ath":"<b64url sha256(token)>","iat":1700000000,"jti":"<nonce>","rel":"<b64url sha256(peer leaf cert)>"}
```

The signature is over the ASCII bytes `header "." claims`, exactly as they
arrived. For ML-DSA-65 it is the 3,309-byte FIPS 204 signature with an empty
context. For ES256 it is the 64-byte `r || s`.

### Thumbprints

The token's `cnf.jkt` is the base64url SHA-256 of the key's canonical JSON:
members in lexicographic order, no whitespace.

- EC P-256 (RFC 7638): `{"crv":"P-256","kty":"EC","x":"…","y":"…"}`
- AKP ML-DSA-65 (draft-ietf-cose-dilithium): `{"alg":"ML-DSA-65","kty":"AKP","pub":"…"}`

A key that is the wrong size, non-canonically spelled, or of a different curve
or algorithm has no thumbprint. That is `malformed` or `unsupported`, as
the [thumbprint vectors](../vectors/proof/thumbprints.json) list.

### Where it travels

- **MOQT.** The proof goes in the `AUTHORIZATION_PROOF` parameter (0x4D51,
  length-prefixed) of CLIENT_SETUP. The relay checks it against its own leaf
  certificate. Each in-session renewal carries a new proof for the new token.
  Direct-path peers exchange proofs the same way in their SETUP messages.
- **/join.** The device sends its public JWK (`key`) so the control plane
  derives `cnf.jkt` itself rather than trusting a thumbprint it is given.

### Sizes

| | ML-DSA-65 | ES256 |
| --- | --- | --- |
| Public JWK | about 2.65 KB | about 120 B |
| Proof | about 8.2 KB (8,194 B in the interop fixture) | about 0.5 KB |

Every checker refuses a proof longer than 16 KiB before parsing it. A MOQT
parameter value and a control message body may each be up to 65,535 bytes, so
a SETUP carrying an ML-DSA token (at most 8 KiB) and an ML-DSA proof fits with
room to spare. The control plane's /join and relay-link request bodies are
capped at 16 KiB, which fits an AKP key and three names of the maximum length.

## Check order

1. Length is 1 to 16 KiB (`malformed`).
2. Three segments, base64url, a JSON header (`malformed`).
3. `typ` is `MOQT-POP` and `alg` is an accepted algorithm (`unsupported`).
4. The header has a `jwk` with no private member (`malformed`), whose key type
   matches `alg` (`unsupported`) and is well formed (`malformed`).
5. The signature verifies under that key (`bad_signature`).
6. The key's thumbprint equals the token's `cnf.jkt` (`wrong_key`).
7. The claims are JSON (`malformed`).
8. `ath` matches the token (`wrong_token`).
9. The checker has a certificate if it requires one, and `rel` matches its
   certificate hash, or is empty when it has none (`wrong_certificate`).
10. `iat` is present (`malformed`) and within the window: too old is
    `expired`, too far ahead is `not_yet_valid`.
11. `jti` is present (`malformed`) and is spent in the store until the token
    expires (`replayed`, `overloaded`).

## API

### Go

```go
import "github.com/moqom-cloud/moqom-security/go/proof"

device, err := proof.GenerateProver(proof.MLDSA65) // or proof.NewProver(signer)
device.JWK()        // proof.JWK, sent to /join
device.Thumbprint() // the token's cnf.jkt
p, err := device.Prove(token, certHash[:], proof.NewNonce(), time.Now())

checker := &proof.Checker{
    Store: proof.NewMemoryNonceStore(proof.DefaultCapacity),
    // Algorithms: []proof.Algorithm{proof.MLDSA65}, // default: both
    // Window: proof.DefaultWindow,
    // RequireCertificate: true, // refuse everything when certHash is empty
}
err = checker.Check(p, token, certHash[:], jkt, time.Now(), tokenExpiry)
proof.Class(err) // "wrong_certificate", as in the vectors
```

`JWK` has `Algorithm()` and `Thumbprint()`. `Prover.Deterministic()` returns a
prover that signs ML-DSA-65 deterministically (vector generation). Go passes
the certificate hash as a slice. An empty slice binds to no certificate and
only matches a proof that also named none, as `None` does in Rust and `nil` in
Swift. `NonceStore` is one method:
`Spend(nonce string, until, now time.Time) error`.

### Rust

```rust
use moqom_proof::{Algorithm, Checker, MemoryNonceStore, Prover, nonce, DEFAULT_CAPACITY};

let device = Prover::generate(Algorithm::MlDsa65)?; // or ml_dsa_65_from_seed, from_pkcs8
device.jwk_json();   // sent to /join
device.thumbprint(); // the token's cnf.jkt
let proof = device.prove(token, &cert_hash, &nonce()?, SystemTime::now())?;

let checker = Checker::new(MemoryNonceStore::new(DEFAULT_CAPACITY))
    .with_algorithms(&Algorithm::ALL)
    .with_window(moqom_proof::DEFAULT_WINDOW)
    .with_certificate_required(true);
checker.check(&proof, token, Some(&cert_hash), &jkt, SystemTime::now(), expiry)?;
// Err(moqom_proof::Error::WrongCertificate); error.class() == "wrong_certificate"
```

`Jwk` has `ml_dsa_65(pub)`, `p256(x, y)`, `algorithm()`, `canonical()` and
`thumbprint()`. `Prover` also has `to_pkcs8`, `algorithm`, `jwk` and
`public_key`. `NonceStore` is a `Send + Sync` trait with
`spend(&self, nonce, until, now)`, implemented for `Arc<S>`. The constants are
`PROOF_TYPE`, `MAX_PROOF_BYTES`, `DEFAULT_WINDOW` and `DEFAULT_CAPACITY`.

### Swift

```swift
import MoqomProof

let device = Prover(.secureEnclaveMLDSA65(try SecureEnclave.MLDSA65.PrivateKey()))
// or .mlDSA65(MLDSA65.PrivateKey()), .es256(…), .secureEnclaveES256(…)
device.jwk         // ProofJWK, sent to /join
device.thumbprint  // the token's cnf.jkt
let proof = try device.prove(token: token, certificateHash: certHash, nonce: Prover.nonce())

let checker = Checker(store: MemoryNonceStore())  // algorithms:, window:, requireCertificate: optional
try checker.check(proof, token: token, certificateHash: certHash,
                  thumbprint: jkt, now: Date(), until: expiry)
// throws(ProofError): .wrongCertificate; error.errorClass == "wrong_certificate"
```

`ProofJWK` is `Codable` and has `algorithm()`, `canonical()` and
`thumbprint()`. `NonceStore` is a `Sendable` protocol with
`spend(_:until:now:) throws(ProofError)`. The constants are `proofType`,
`Checker.maximumProofBytes`, `Checker.defaultWindow` and
`MemoryNonceStore.defaultCapacity`.

### Nonce stores

`MemoryNonceStore` remembers nonces in memory until each one's `until`, up to a
capacity (default 100,000). When full it refuses with `overloaded` rather than
evicting, because evicting would choose which proof becomes replayable. It
forgets everything on restart, so a proof captured and never delivered could
be replayed after a restart, within its window and its token's lifetime. A
deployment that needs to close that gap supplies a shared store.

## Errors

| Class | Go | Rust | Swift | Meaning |
| --- | --- | --- | --- | --- |
| `malformed` | `ErrMalformed` | `Malformed(why)` | `.malformed(why)` | Not a well-formed proof or key, or a claim is missing |
| `unsupported` | `ErrUnsupported` | `Unsupported` | `.unsupported` | Wrong `typ`, an algorithm not accepted, or `alg` not the key's |
| `bad_signature` | `ErrBadSignature` | `BadSignature` | `.badSignature` | The signature does not verify under the embedded key |
| `wrong_key` | `ErrWrongKey` | `WrongKey` | `.wrongKey` | The embedded key is not the one `cnf.jkt` names |
| `wrong_token` | `ErrWrongToken` | `WrongToken` | `.wrongToken` | `ath` is for another token |
| `wrong_certificate` | `ErrWrongCertificate` | `WrongCertificate` | `.wrongCertificate` | `rel` is for another peer |
| `expired` | `ErrExpired` | `Expired` | `.expired` | `iat` is older than the window |
| `not_yet_valid` | `ErrNotYetValid` | `NotYetValid` | `.notYetValid` | `iat` is further ahead than the window |
| `replayed` | `ErrReplayed` | `Replayed` | `.replayed` | The nonce was already spent |
| `overloaded` | `ErrOverloaded` | `Overloaded` | `.overloaded` | The nonce store cannot remember another |
| `signing` | the signer's own error | `Signing` | `.notSigned` | Proving only: the key refused to sign |

`Class` in Go returns `""` for an error that is not one of the above, which
includes a signer's own error.

## Vectors

[`vectors/proof`](../vectors/proof) follows the [common format](../vectors/README.md);
times are Unix seconds in `now`.

- `keys.json` (4 cases): ML-DSA-65 keys from seeds and P-256 keys from
  scalars, with the public JWK and thumbprint each must produce.
- `thumbprints.json` (13 cases): RFC 7638 and AKP thumbprints, and 9 keys that
  have none (`malformed` 4, `unsupported` 5).
- `proofs.json` (66 cases): proofs to check against `token`,
  `certificate_hash_hex`, `thumbprint` and `now`, with nonces in `spent`
  already spent, until `until`, at a checker that requires a certificate if
  `require_certificate` is set. An empty `certificate_hash_hex` is a checker
  with none. 57 must be refused: `malformed` 23 (6 of them keys carrying a
  private member), `unsupported` 7, `bad_signature` 6, `wrong_key` 4,
  `wrong_token` 3, `wrong_certificate` 8 (4 of them at a checker with no
  certificate), `expired` 2, `not_yet_valid` 2, `replayed` 2.

They are generated by `go/proof/generate_test.go`. The products also share an
interop fixture, `moqom-relay/tests/testdata/possession.json` in the engine.
The Swift client writes it (`MOQOM_WRITE_FIXTURES=1`), and the relay, the Go
control plane and the Swift client all read it.

## Known gaps

- `MemoryNonceStore` does not survive a restart and is not shared between
  relays. `rel` limits a captured proof to the relay it was made for, but a
  restart of that relay reopens the window.
- The window is symmetric and fixed per checker. There is no server-supplied
  nonce (RFC 9449 `DPoP-Nonce`), so freshness depends on the device clock
  being within the window.
