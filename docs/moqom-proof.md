<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Elliott Wave LLC -->

# moqom-proof

Device proof of possession for MOQOM sessions. A join token names a device key
by its [JWK](https://www.rfc-editor.org/rfc/rfc7517) thumbprint (`cnf.jkt`, see [moqom-token](moqom-token.md)). A token on
its own is a bearer credential: whoever copies it can use it. A proof turns it
into a sender-constrained one. At connect, and again with every in-session
token renewal, the device signs a fresh single-use proof. The proof commits to
the token, to the TLS certificate of the peer it is talking to, and to the time.
The peer checks that the proof was signed by the key the token names.

Proofs follow the shape of [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449) (DPoP), adapted to a MoQ session instead of
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
  caller-supplied `NonceStore` until the token expires, and never for less
  than the proof's window: until the later of the caller's `until` and one
  second past `iat` plus the window. A second proof over the same token with a
  new nonce is a new session, not a replay.
- **Fresh.** `iat` must be within a window (default five minutes) of the
  checker's clock, either way.
- **One algorithm.** ML-DSA-87 ([FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)) is the only algorithm a device signs
  with and a checker accepts, so every proof is post-quantum. ES256, EdDSA,
  ML-DSA-44, ML-DSA-65 and anything else are `unsupported`, however well
  signed.
- **The algorithm belongs to the key.** The header's `alg` must match the
  embedded [JWK](https://www.rfc-editor.org/rfc/rfc7517)'s key type. Anything else is `unsupported`.
- **Signature first.** No claim is read before the signature has verified
  against the embedded key and that key's thumbprint has matched the token's
  `cnf.jkt`. The nonce is spent only after every other check passes, so a
  corrupted proof cannot burn a genuine proof's nonce.

## Device keys

| Platform | [ML-DSA-87](https://csrc.nist.gov/pubs/fips/204/final) key |
| --- | --- |
| Swift, device with a Secure Enclave | `SecureEnclave.MLDSA87.PrivateKey` |
| Swift, no enclave (macOS without one, tests) | `MLDSA87.PrivateKey` |
| Go | `*mldsa.PrivateKey` (`crypto/mldsa`, `mldsa.MLDSA87()`), or any `crypto.Signer` holding one |
| Rust | aws-lc-rs `ML_DSA_87_SIGNING` from a 32-byte seed or PKCS#8 |

Swift's `MoqomKit.DeviceKey` chooses: an enclave key when
`SecureEnclave.isAvailable` and creation succeeds, otherwise a software key.

Every prover signs with fresh randomness: hedged ML-DSA-87 (FIPS 204's
default) in CryptoKit, Go's `crypto/mldsa` and aws-lc-rs. Go's
`Prover.Deterministic()` returns a copy that signs with ML-DSA's deterministic
variant instead, and it is how `go/proof/generate_test.go` makes the vectors
reproducible. Swift and Rust have no deterministic mode, so for them the
vectors are proofs to verify, not proofs to reproduce.

## Wire format

A proof is a compact [JWS](https://www.rfc-editor.org/rfc/rfc7515): `base64url(header) "." base64url(claims) "."
base64url(signature)`. Base64url has no padding and is strict: the unused bits
of the last character must be zero.

The header, the key inside it and the claims are each one JSON object, read the
same way in every language, so that no two parsers can disagree about what a
proof says:

- The bytes are UTF-8, and a `\u` escape of a surrogate is half of a pair.
- No object, at any depth, names a member twice. Names are compared after
  unescaping and byte for byte, so `jti` and `j\u0074i` are the same name and
  `jti` and `JTI` are not. Go's `encoding/json` keeps the last of a duplicate
  and matches struct fields regardless of case; neither is allowed to decide.
- A known member (`alg`, `typ`, `jwk`; `kty`, `alg`, `pub`;
  `ath`, `iat`, `jti`, `rel`) has its type or is absent. `null` is refused, not
  read as absent.
- `iat` is an integer literal that fits in 64 bits: no fraction, no exponent,
  and not `-0`, which `serde_json` reads as a float. So `1.7e9`,
  `1700000000.0` and `-0` are refused, as moqom-token refuses them.
- No number is too large for a double (`1e400`), and arrays and objects nest
  at most 127 deep, the outermost object included: `serde_json`'s limits, kept
  by all three.
- Other members are ignored.

Anything else is `malformed`.

Every string the checker compares (`alg`, `typ`, `kty`, member names,
the thumbprint, `ath`, `rel`, and the nonce as a store key) is compared byte for
byte after unescaping. Swift's `==` treats canonically equivalent Unicode as
equal, so there `kty` `A\u212AP` (with a Kelvin sign) would pass for `AKP`, and
`nonce-\u00E9` would be refused as a replay of `nonce-e\u0301`; Go and Rust tell
them apart, and so does Swift's checker. A proof has no `htm`, `htu` or `kid`.

Header:

```json
{"alg":"ML-DSA-87","typ":"MOQT-POP","jwk":{"alg":"ML-DSA-87","kty":"AKP","pub":"…"}}
```

- `typ` is always `MOQT-POP`.
- `jwk` is the device's public key: `kty` `AKP`, `alg` `ML-DSA-87` and `pub`,
  the 2,592-byte raw [ML-DSA-87](https://csrc.nist.gov/pubs/fips/204/final) public key in base64url
  ([draft-ietf-cose-dilithium](https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/)). Any other key type or `alg` is `unsupported`;
  any other length or spelling is `malformed`. So is a `jwk` with a private member (`d`, `p`, `q`, `dp`, `dq`,
  `qi`, `oth`, `k`, `priv` or `seed`), whatever its value, even `null`: the
  device has published its key.

Claims:

```json
{"ath":"<b64url sha256(token)>","iat":1700000000,"jti":"<nonce>","rel":"<b64url sha256(peer leaf cert)>"}
```

The signature is over the ASCII bytes `header "." claims`, exactly as they
arrived: the 4,627-byte FIPS 204 ML-DSA-87 signature with an empty context.

### Thumbprints

The token's `cnf.jkt` is the base64url SHA-256 of the key's canonical JSON,
members in lexicographic order with no whitespace, as [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638) computes it
over the members [draft-ietf-cose-dilithium](https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/) gives AKP keys:
`{"alg":"ML-DSA-87","kty":"AKP","pub":"…"}`.

A key that is the wrong size, non-canonically spelled, or of another key type
or algorithm (EC, OKP, ML-DSA-44, ML-DSA-65) has no thumbprint. That is
`malformed` or `unsupported`, as the [thumbprint vectors](../vectors/proof/thumbprints.json) list.

### Where it travels

- **MOQT.** The proof goes in the `AUTHORIZATION_PROOF` parameter (0x4D51,
  length-prefixed) of CLIENT_SETUP. The relay checks it against its own leaf
  certificate. Each in-session renewal carries a new proof for the new token.
  Direct-path peers exchange proofs the same way in their SETUP messages.
- **/join.** The device sends its public [JWK](https://www.rfc-editor.org/rfc/rfc7517) (`key`) so the control plane
  derives `cnf.jkt` itself rather than trusting a thumbprint it is given.

### Sizes

| | [ML-DSA-87](https://csrc.nist.gov/pubs/fips/204/final) |
| --- | --- |
| Public [JWK](https://www.rfc-editor.org/rfc/rfc7517) | about 3.5 KB |
| Proof | about 11 KB |

Every checker refuses a proof longer than 16 KiB before parsing it. A MOQT
parameter value and a control message body may each be up to 65,535 bytes, so
a SETUP carrying an ML-DSA-87 token (at most 8 KiB) and an ML-DSA-87 proof
fits with room to spare. The control plane's /join and relay-link request bodies are
capped at 16 KiB, which fits an AKP key and three names of the maximum length.

## Check order

1. Length is 1 to 16 KiB (`malformed`).
2. Three segments, base64url, and a header that is JSON as above, its key's
   members included (`malformed`).
3. `typ` is `MOQT-POP` and `alg` is an accepted algorithm (`unsupported`).
4. The header has a `jwk` with no private member (`malformed`), whose key type
   matches `alg` (`unsupported`) and is well formed (`malformed`).
5. The signature verifies under that key (`bad_signature`).
6. The key's thumbprint equals the token's `cnf.jkt` (`wrong_key`).
7. The claims are JSON as above (`malformed`).
8. `ath` matches the token (`wrong_token`).
9. The checker has a certificate if it requires one, and `rel` matches its
   certificate hash, or is empty when it has none (`wrong_certificate`).
10. `iat` is present (`malformed`) and within the window: too old is
    `expired`, too far ahead is `not_yet_valid`.
11. `jti` is present (`malformed`) and is spent in the store until the later
    of `until` (the token's expiry) and one second past `iat` plus the window
    (`replayed`, `overloaded`).

## API

### Go

```go
import "github.com/moqom-cloud/moqom-security/go/proof"

device, err := proof.GenerateProver(proof.MLDSA87) // or proof.NewProver(signer)
device.JWK()        // proof.JWK, sent to /join
device.Thumbprint() // the token's cnf.jkt
p, err := device.Prove(token, certHash[:], proof.NewNonce(), time.Now())

checker, err := proof.NewChecker(proof.NewDefaultMemoryNonceStore(),
    // proof.WithAlgorithms(proof.MLDSA87), // the default and only one
    // proof.WithWindow(proof.DefaultWindow),
    // proof.WithCertificateRequired(true), // refuse everything when certHash is empty
)
err = checker.Check(p, token, certHash[:], jkt, time.Now(), tokenExpiry)
proof.Class(err) // "wrong_certificate", as in the vectors
```

`NewChecker` refuses a nil store, and the options refuse no algorithms, an
unknown algorithm, and a window that is not positive, all with
`ErrConfiguration`. Leaving an option out gives its default. A zero `Checker`
or `MemoryNonceStore` (not made by its constructor) refuses everything with
`ErrConfiguration`. `Checker` has `Store()`, `Algorithms()`, `Window()` and
`CertificateRequired()`.

`JWK` has `Algorithm()` and `Thumbprint()`. `Prover.Deterministic()` returns a
prover that signs deterministically (vector generation). Go passes
the certificate hash as a slice. An empty slice binds to no certificate and
only matches a proof that also named none, as `None` does in Rust and `nil` in
Swift. `NonceStore` is one method:
`Spend(nonce string, until, now time.Time) error`.

### Rust

```rust
use moqom_proof::{Algorithm, Checker, MemoryNonceStore, Prover, nonce, DEFAULT_CAPACITY};

let device = Prover::generate(Algorithm::MlDsa87)?; // or ml_dsa_87_from_seed, from_pkcs8
device.jwk_json();   // sent to /join
device.thumbprint(); // the token's cnf.jkt
let proof = device.prove(token, &cert_hash, &nonce()?, SystemTime::now())?;

let checker = Checker::new(MemoryNonceStore::default()) // or MemoryNonceStore::new(capacity)?
    .with_algorithms(&Algorithm::ALL)?
    .with_window(moqom_proof::DEFAULT_WINDOW)?
    .with_certificate_required(true);
checker.check(&proof, token, Some(&cert_hash), &jkt, SystemTime::now(), expiry)?;
// Err(moqom_proof::Error::WrongCertificate); error.class() == "wrong_certificate"
```

`Jwk` has `ml_dsa_87(pub)`, `algorithm()`, `canonical()` and
`thumbprint()`. `Prover` also has `to_pkcs8`, `algorithm`, `jwk` and
`public_key`. `MemoryNonceStore::new` refuses a capacity of zero,
`with_algorithms` an empty slice and `with_window` a zero window, with
`Error::Configuration`. `Checker` has `store`, `algorithms`, `window` and
`certificate_required`. `NonceStore` is a `Send + Sync` trait with
`spend(&self, nonce, until, now)`, implemented for `Arc<S>`. The constants are
`PROOF_TYPE`, `MAX_PROOF_BYTES`, `DEFAULT_WINDOW` and `DEFAULT_CAPACITY`.

### Swift

```swift
import MoqomProof

let device = Prover(.secureEnclaveMLDSA87(try SecureEnclave.MLDSA87.PrivateKey()))
// or .mlDSA87(MLDSA87.PrivateKey())
device.jwk         // ProofJWK, sent to /join
device.thumbprint  // the token's cnf.jkt
let proof = try device.prove(token: token, certificateHash: certHash, nonce: Prover.nonce())

let checker = Checker(store: MemoryNonceStore())  // the defaults; cannot fail
// try Checker(store:algorithms:window:requireCertificate:), try MemoryNonceStore(capacity:)
try checker.check(proof, token: token, certificateHash: certHash,
                  thumbprint: jkt, now: Date(), until: expiry)
// throws(ProofError): .wrongCertificate; error.errorClass == "wrong_certificate"
```

The throwing initialisers refuse no algorithms, a window that is not a
positive number of seconds, and a capacity that is not positive, with
`ProofError.configuration`. `ProofJWK` is `Codable` and has `algorithm()`,
`canonical()` and `thumbprint()`. `NonceStore` is a `Sendable` protocol with
`spend(_:until:now:) throws(ProofError)`. The constants are `proofType`,
`Checker.maximumProofBytes`, `Checker.defaultWindow` and
`MemoryNonceStore.defaultCapacity`.

### Nonce stores

`MemoryNonceStore` remembers nonces in memory until each one's `until`, up to a
capacity (default 100,000, and it must be positive). When full it refuses with
`overloaded` rather than evicting, because evicting would choose which proof
becomes replayable. It
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
| `signing` | `ErrSigning` | `Signing` | `.notSigned` | Proving only: the key refused to sign |
| `configuration` | `ErrConfiguration` | `Configuration(why)` | `.configuration(why)` | Making a checker or store: no store, no algorithms, or a window or capacity that is not positive |

Go's `ErrSigning` wraps the signer's own error, so `errors.Is` finds both.
`Class` in Go returns `""` for an error that is not one of the above.

## Vectors

[`vectors/proof`](../vectors/proof) follows the [common format](../vectors/README.md);
times are Unix seconds in `now`.

- `keys.json` (2 cases): [ML-DSA-87](https://csrc.nist.gov/pubs/fips/204/final) keys from seeds, with the public [JWK](https://www.rfc-editor.org/rfc/rfc7517)
  and thumbprint each must produce.
- `thumbprints.json` (11 cases): one AKP ML-DSA-87 thumbprint, and 10 keys
  that have none (`malformed` 2, `unsupported` 8: EC, OKP, ML-DSA-44,
  ML-DSA-65, and each `alg` on the other's key).
- `proofs.json` (93 cases): proofs to check against `token`,
  `certificate_hash_hex`, `thumbprint` and `now`, with nonces in `spent`
  already spent, until `until`, at a checker that requires a certificate if
  `require_certificate` is set. An empty `certificate_hash_hex` is a checker
  with none. 13 are valid, and 80 must be refused: `malformed` 49 (3 of them
  keys carrying a private member, most of the rest headers or claims that
  JSON parsers could read differently, all signed), `unsupported` 14
  (correctly signed ES256 and ML-DSA-65 proofs among them), `bad_signature`
  4, `wrong_key` 2, `wrong_token` 2, `wrong_certificate` 6 (3 of them at a
  checker with no certificate), `expired` 1, `not_yet_valid` 1, `replayed` 1.

They are generated by `go/proof/generate_test.go`. The products also share an
interop fixture, `moqom-relay/tests/testdata/possession.json` in the engine.
The Swift client writes it (`MOQOM_WRITE_FIXTURES=1`), and the relay, the Go
control plane and the Swift client all read it.

## Known gaps

- `MemoryNonceStore` does not survive a restart and is not shared between
  relays. `rel` limits a captured proof to the relay it was made for, but a
  restart of that relay reopens the window.
- Checkers that share a store but not a clock can disagree about when a nonce
  may be forgotten: a store swept by a checker whose clock runs ahead can let
  a checker whose clock runs behind accept the proof again, for as long as the
  clocks differ.
- `ProofJWK`, `JWK` and `Jwk` are decoded with each language's own JSON
  decoder when a caller reads one (from `/join`, say), and those differ: Go
  matches member names regardless of case and reads `null` as absent, Swift
  reads `null` as absent, Rust refuses it, and none refuses a duplicate. The
  thumbprint is rebuilt from the decoded key, so the same key always gets the
  same thumbprint, but an oddly spelled key can be accepted in one language and
  refused in another. The checker does not use these decoders.
- The window is symmetric and fixed per checker. There is no server-supplied
  nonce ([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449) `DPoP-Nonce`), so freshness depends on the device clock
  being within the window.
