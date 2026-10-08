<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Elliott Wave LLC -->

# moqom-token

The MOQOM access token: a compact JWS that the control plane signs and that
relays and direct-path peers verify. A token says who someone is (tenant, user
and the device key they hold), which room they may join and what they may do
there, and for how long. It is signed with ML-DSA-65 (FIPS 204). Ed25519 keys
can still verify, but nothing signs with them, so tokens minted before the
move to ML-DSA keep working until they expire.

The library is the same in Swift (`MoqomToken`), Go
(`github.com/moqom-cloud/moqom-security/go/token`) and Rust (`moqom-token`).
All three pass every case in [`vectors/token`](../vectors/token).

## What it does

- **Signs and verifies, nothing else.** A `Signer` holds one ML-DSA-65 key and
  its key ID (`kid`). A `Verifier` holds a set of public keys, an issuer, and
  optionally a tenant. `verify(token, now)` returns the claims only if every
  check passes. No API returns claims from a token that has not been
  verified, and none reads a claim before the signature has been checked.
- **Rotation by key ID.** The `kid` in the header selects the key. A verifier
  holding the old key and the new one accepts tokens from both. An unknown
  `kid` is `unknown_key`, never a fallback to some other key.
- **The algorithm belongs to the key.** Each public key carries its algorithm,
  and the header's `alg` must match it exactly. If it doesn't, the token is
  `unsupported`. That rules out the usual JOSE confusions: `none`, HMAC keyed
  with the public key, and an Ed25519 signature checked against an ML-DSA key
  ID.
- **Fifteen minutes at most.** A signer refuses to mint a token that lasts
  longer than 900 seconds, or whose expiry is not after its issue time. A
  verifier refuses one that would last longer: `exp − iat > 900` when it has an
  issue time, or `exp − now > 930` when it has none.
- **Bound to a device.** `cnf.jkt` is the RFC 7638 SHA-256 thumbprint of the
  device key the token was issued to. A signer refuses one that is not 32
  bytes of base64url. The proof that a session holds that key is
  `moqom-proof`'s job, not this library's.
- **Key sets.** JWK sets are read either as a bare array or wrapped in
  `{"keys": [...]}`. Each key must be `AKP` / `ML-DSA-65` or `OKP` /
  `Ed25519`, with a public key of the right length. A key that doesn't fit is
  refused rather than skipped. A derived key ID is
  `base64url(SHA-256(raw public key)[:8])`.
- **Raw signatures for protocols that share the key.** `SignMessage` (Go),
  `sign_message` (Rust) and `signature(for:)` (Swift) sign arbitrary bytes with
  the token key; the room control log uses this. The caller owns domain
  separation, and the message must never be a valid JWS signing input.

What stays in the products, because it is a rule about the product rather than
about a token:

- Which capability bits exist.
- That E2EE must be `required`.
- The provenance rules for `via`.
- What a relay link may carry.
- Device IDs being the first 16 characters of the thumbprint.
- The room log.
- Relay direct tickets (`typ` `moqom-direct-ticket`).

## Wire format

`base64url(header) "." base64url(claims) "." base64url(signature)`.

The base64url is unpadded and canonical: padding, characters outside the
alphabet, and non-zero trailing bits are all refused. The signature covers the
first two segments exactly as received, and the token is at most 8,192 bytes.

The header has exactly these members, and any other parameter is malformed:

```json
{"alg":"ML-DSA-65","typ":"MOQT","kid":"…"}
```

The claims, in the order the signer writes them:

| Member | Type | Meaning |
| --- | --- | --- |
| `iss` | string | Issuer, compared when the verifier pins one |
| `sub` | string | User. Required. |
| `aud` | string | Tenant. Required. Compared when the verifier pins one. |
| `jti` | string | Token ID |
| `iat` | integer | Issued at, in Unix seconds. 0 or absent means unknown. |
| `exp` | integer | Expires, in Unix seconds. Required. |
| `cnf` | `{"jkt": string}` | Device key thumbprint. Required. |
| `moqt` | object | The grant (see below) |
| `via` | string | Who brought this person in. Omitted when empty. |
| `e2ee` | string | Room encryption policy. Omitted when empty. |

The grant, `moqt`:

| Member | Type | Meaning |
| --- | --- | --- |
| `room` | string | Room. Omitted when empty, meaning any. |
| `pub` | integer 0–255 | Media kinds the holder may publish. 0 means a viewer. |
| `cap` | integer, 32 bits | Capability bits |
| `own` | bool | Room owner. Omitted when false. |
| `bs` | bool | Backstage. Omitted when false. |
| `age` | bool | Age verified. Omitted when false. |
| `rly` | bool | Relay link. Omitted when false. |

Parsing rules:

- Both segments must be JSON objects.
- Member names are case-sensitive, and a `null` member is refused rather than
  read as absent.
- No object in the header or the claims, at any depth, may name a member twice
  (`header is not JSON`, `claims are not JSON`). Parsers disagree about which
  of a duplicate wins, so a token with one would mean different things to
  different verifiers. Names are compared after unescaping (`s\u0075b` is
  `sub`) and byte for byte, without Unicode normalization.
- Unknown top-level claims are ignored, so the issuer can add one without first
  upgrading every verifier.
- An unknown member of `moqt` is malformed. A grant field added later is as
  likely to narrow a grant as to widen it, and a verifier that skipped it would
  grant more than was issued.

The signer's JSON encoding is canonical and identical in all three languages,
and the sign vectors pin it byte for byte:

- No whitespace, and no HTML escaping.
- `\b \f \n \r \t` are written as short escapes, other control characters as
  lowercase `\u00xx`.
- U+2028 and U+2029 are escaped, and DEL is left raw.

Go signs deterministically only in the vector generator. Production signing in
all three languages is hedged or randomized, so Rust and Swift check the
signing input byte for byte and that their own tokens verify.

## Verification order

The checks run in this order, and each one stops at the first failure:

1. Length (`malformed`).
2. Three segments (`malformed`).
3. The header decodes (`malformed`).
4. `typ` is `MOQT` (`unsupported`).
5. `kid` is in the key set (`unknown_key`).
6. `alg` matches that key's algorithm (`unsupported`).
7. The signature segment decodes (`malformed`).
8. The signature verifies (`bad_signature`).
9. The claims decode (`malformed`).
10. The issuer matches, if pinned (`wrong_issuer`).
11. `exp` is present (`malformed`).
12. Not expired: `now − 30 > exp` fails (`expired`).
13. Already valid: when `iat ≠ 0`, `now + 30 < iat` fails (`not_yet_valid`).
14. Lifetime (`lifetime`).
15. `sub`, `aud` and `jkt` are all present (`incomplete`).
16. The tenant matches, if pinned (`wrong_tenant`).

Times are compared in whole Unix seconds, with 30 seconds of clock skew allowed
either way.

## API

### Go

```go
import "github.com/moqom-cloud/moqom-security/go/token"

signer, err := token.NewSigner(seed)              // or token.GenerateSigner()
signer = signer.WithID("2026-10")                 // optional; default is derived
jws, err := signer.Sign(token.Claims{
    Issuer: iss, Subject: "ada", Tenant: "acme",
    IssuedAt: now.Unix(), Expires: now.Add(10 * time.Minute).Unix(),
    Confirmation: token.Confirmation{Thumbprint: jkt},
    Grant: token.Grant{Room: "room-42", Publish: 3},
})

keys, err := token.ParseJWKSet(document)          // []token.PublicKey
v := token.NewVerifier(iss, keys...).ForTenant("acme")
claims, err := v.Verify(jws, time.Now())
switch {
case errors.Is(err, token.ErrExpired): …
}
token.Class(err)                                   // "expired", as in the vectors
```

`PublicKey` has `NewPublicKey(alg, id, raw)`, `ID`, `Algorithm`, `Bytes`,
`Verify(msg, sig)` and `JWK`. `Signer` has `ID`, `PublicKey`, `Seed` and
`SignMessage`.

### Rust

```rust
use moqom_token::{Claims, Confirmation, Grant, PublicKey, Signer, Verifier};

let signer = Signer::from_seed(&seed)?.with_id("2026-10");
let jws = signer.sign(&Claims {
    iss: iss.into(), sub: "ada".into(), tenant: "acme".into(),
    iat, exp: iat + 600,
    cnf: Confirmation { jkt },
    grant: Grant { room: "room-42".into(), publish: 3, ..Grant::default() },
    ..Claims::default()
})?;

let keys = PublicKey::parse_set(&document)?;
let verifier = Verifier::new(iss, keys).for_tenant("acme");
let claims = verifier.verify(jws.as_bytes(), SystemTime::now())?;
// Err(moqom_token::Error::Expired), …; error.class() == "expired"
```

`PublicKey` has `ml_dsa_65(id, bytes)`, `ed25519(id, bytes)`,
`verifies(msg, sig)` and `jwk()`. `key_id(raw)` derives a key ID. The
constants are `TOKEN_TYPE`, `MAX_LIFETIME`, `CLOCK_SKEW` and
`MAX_TOKEN_BYTES`.

### Swift

```swift
import MoqomToken

let signer = try Signer(seed: seed, keyID: "2026-10")   // or Signer(privateKey:keyID:)
let jws = try signer.sign(Claims(
    issuer: iss, subject: "ada", tenant: "acme",
    issuedAt: now, expires: now + 600, thumbprint: jkt,
    grant: Grant(room: "room-42", publish: 3)
))

let keys = try PublicKey.parseSet(document)
let verifier = Verifier(issuer: iss, tenant: "acme", keys: keys)
let claims = try verifier.verify(jws, now: Date())        // throws(TokenError)
// TokenError.expired, …; error.vectorClass == "expired"
```

`PublicKey(id:algorithm:rawRepresentation:)` has `derivedID(for:)`,
`isValidSignature(_:for:)` and `jwk`. `TokenLimits` holds the type, the
maximum lifetime, the clock skew and the maximum length.

## Errors

| Class | Go | Rust | Swift | Meaning |
| --- | --- | --- | --- | --- |
| `malformed` | `ErrMalformed` | `Malformed(why)` | `.malformed(why)` | Not a well-formed token |
| `unsupported` | `ErrUnsupported` | `Unsupported` | `.unsupported` | Wrong `typ`, or `alg` not the key's |
| `unknown_key` | `ErrUnknownKey` | `UnknownKey` | `.unknownKey` | `kid` not in the set |
| `bad_signature` | `ErrBadSignature` | `BadSignature` | `.badSignature` | The signature does not verify |
| `expired` | `ErrExpired` | `Expired` | `.expired` | Past `exp` plus the skew |
| `not_yet_valid` | `ErrNotYetValid` | `NotYetValid` | `.notYetValid` | `iat` beyond now plus the skew |
| `lifetime` | `ErrLifetime` | `Lifetime` | `.lifetime` | Longer than fifteen minutes, or minted with no lifetime |
| `wrong_issuer` | `ErrWrongIssuer` | `WrongIssuer` | `.wrongIssuer` | `iss` is not the pinned issuer |
| `wrong_tenant` | `ErrWrongTenant` | `WrongTenant` | `.wrongTenant` | `aud` is not the pinned tenant |
| `incomplete` | `ErrIncomplete` | `Incomplete` | `.incomplete` | Missing `sub`, `aud` or `jkt` |
| `thumbprint` | `ErrThumbprint` | `Thumbprint` | `.thumbprint` | Signing only: `jkt` is not a SHA-256 thumbprint |

The `malformed` reasons are the same strings in all three languages, and the
relay closes a session with them:

- `token length is out of range`
- `expected three segments`
- `header is not base64url`
- `header is not JSON`
- `signature is not base64url`
- `claims are not base64url`
- `claims are not JSON`
- `no expiry`

## Vectors

`vectors/token` is generated by the Go tests:

```sh
cd go && MOQOM_WRITE_VECTORS=1 go test ./token -run TestVectors
```

Without the variable, the test checks that the committed files are what this
build would write. The generator uses fixed seeds and
`now = 1800000000`. The top-level `keys` array lists each key's ID, algorithm,
seed and public key.

- `verify.json` has 62 cases. Each gives a token, a time, an issuer, a tenant
  and a key set, together with either the claims it yields or the error class.
  They cover:
  - valid ML-DSA-65 tokens and the legacy Ed25519 ones;
  - rotation;
  - expiry and not-yet-valid, each at the skew boundary;
  - wrong `kid`;
  - tampered claims and tampered signatures;
  - algorithm confusion (`none`, `HS256`, `EdDSA` against an ML-DSA key and the
    reverse);
  - lifetimes over the cap;
  - issuer and tenant pins;
  - incomplete identities;
  - grant strictness;
  - duplicate member names in the header, the claims, `cnf`, the grant, an
    unknown claim and an array, including one spelled with an escape;
  - every malformed reason, including non-canonical base64url and non-object
    JSON.
- `sign.json` has 13 cases: five valid claim sets with their exact signing
  input and a deterministic token, and eight that a signer must refuse.

The runners:

- Go: `go test ./token`
- Rust: `cargo test -p moqom-token`
- Swift: `swift test --filter MoqomTokenTests`

## Known gaps

- Duplicate JSON member names are not vectored. Go's and Rust's decoders keep
  the last occurrence, and Foundation's behaviour is unspecified. A signer
  never writes one, and the signature covers the exact bytes, so only an issuer
  could produce one.
- The library does not track token IDs (`jti`), so it does not detect replay.
  A token is a bearer of rights for at most fifteen minutes, and the
  proof-of-possession check is what binds it to a session.
