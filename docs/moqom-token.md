<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Elliott Wave LLC -->

# moqom-token

The MOQOM access token: a compact [JWS](https://www.rfc-editor.org/rfc/rfc7515) that the control plane signs and that
relays and direct-path peers verify. A token says who someone is (tenant, user
and the device key they hold), which room they may join and what they may do
there, and for how long. It is signed with ML-DSA-65 ([FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)). Ed25519 keys
can still verify, but nothing signs with them, so tokens minted before the
move to ML-DSA keep working until they expire.

The library is the same in Swift (`MoqomToken`), Go
(`github.com/moqom-cloud/moqom-security/go/token`) and Rust (`moqom-token`).
All three pass every case in [`vectors/token`](../vectors/token).

## What it does

- **Signs and verifies, nothing else.** A `Signer` holds one [ML-DSA-65](https://csrc.nist.gov/pubs/fips/204/final) key and
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
- **Bound to a device.** `cnf.jkt` is the [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638) SHA-256 thumbprint of the
  device key the token was issued to: 43 characters of canonical unpadded
  base64url, decoding to 32 bytes. A signer refuses to mint, and a verifier
  refuses to accept, a token whose `jkt` is anything else (`thumbprint`),
  because no proof of possession could match it. The proof that a session
  holds that key is `moqom-proof`'s job, not this library's.
- **Key sets.** [JWK](https://www.rfc-editor.org/rfc/rfc7517) sets are read either as a bare array or wrapped in
  `{"keys": [...]}`. The whole document is read first, as strict JSON under
  the same rules as a token's segments (see Parsing rules): member names are
  exact, a `null` or repeated member is refused, each key is an object, and
  every key needs a `kty` and a non-empty `kid` (`set_malformed`). Then each key in order: it must be `AKP` /
  `ML-DSA-65` or `OKP` / `Ed25519` (`key_unsupported`), its public key must be
  canonical base64url of the right length (`key_invalid`), and its `kid` must
  not repeat an earlier one, byte for byte (`duplicate_kid`). A key that doesn't fit makes the
  set an error rather than being skipped, and two keys under one `kid` would
  leave which one a token selects to the parser. Members a key doesn't need
  (`use`, `key_ops`) are ignored. A derived key ID is
  `base64url(SHA-256(raw public key)[:8])`.
- **Raw signatures for protocols that share the key.** `SignMessage` (Go),
  `sign_message` (Rust) and `signature(for:)` (Swift) sign arbitrary bytes with
  the token key; the room control log uses this. The caller owns domain
  separation, and the message must never be a valid [JWS](https://www.rfc-editor.org/rfc/rfc7515) signing input.

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
alphabet (line breaks included, which Go's decoder would otherwise skip), and
non-zero trailing bits are all refused. The signature covers the
first two segments exactly as received, and the token is at most 8,192 bytes.

The header has exactly these members, and any other parameter is malformed:

```json
{"alg":"ML-DSA-65","typ":"MOQT","kid":"…"}
```

The claims, in the order the signer writes them:

| Member | Type | Meaning |
| --- | --- | --- |
| `iss` | string | Issuer, compared byte for byte when the verifier pins one |
| `sub` | string | User. Required. |
| `aud` | string | Tenant. Required. Compared byte for byte when the verifier pins one. |
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
| `room` | string | Room. Omitted when empty, meaning none. |
| `pub` | integer 0–255 | Media kinds the holder may publish. 0 means a viewer. |
| `cap` | integer, 32 bits | Capability bits |
| `own` | bool | Room owner. Omitted when false. |
| `bs` | bool | Backstage. Omitted when false. |
| `age` | bool | Age verified. Omitted when false. |
| `rly` | bool | Relay link. Omitted when false. |

Parsing rules. The header and the claims are each one JSON object, read the
same way in every language, so that no two parsers can disagree about what a
token says. Anything else is malformed (`header is not JSON`, `claims are not
JSON`), even when the signature is good:

- Each segment is one JSON object ([RFC 8259](https://www.rfc-editor.org/rfc/rfc8259)), with only whitespace around it:
  not an array, a string or `null`, and no byte order mark.
- The bytes are UTF-8 (no overlong forms or encoded surrogates), a `\u`
  escape of a surrogate is half of a pair, and a string holds no raw control
  character.
- No object in the header or the claims, at any depth, may name a member
  twice. Parsers disagree about which of a duplicate wins, so a token with one
  would mean different things to different verifiers. Names are compared after
  unescaping (`s\u0075b` is `sub`) and byte for byte, so `sub` and `Sub` are
  different names.
- A known member has its type or is absent: a string, an integer, a bool or an
  object, as in the tables. `null` is refused rather than read as absent, and
  `cnf` and `moqt` given as arrays are refused.
- `iat`, `exp`, `pub` and `cap` are integer literals in range: no fraction, no
  exponent and not `-0`, so `1.8e9`, `1800000000.0` and `3e0` are refused, as
  are a negative `pub`, a `cap` over 32 bits and an `exp` over 64. A bool is
  `true` or `false`, not `1` or `"true"`.
- No number anywhere is too large for a double (`1e400`; `1e-400` is fine),
  and arrays and objects nest at most 127 deep, the outermost object included:
  `serde_json`'s limits, kept by all three.
- Unknown top-level claims are ignored, whatever their value (`null`, a
  fraction), so the issuer can add one without first upgrading every verifier.
- An unknown member of `moqt` is malformed. A grant field added later is as
  likely to narrow a grant as to widen it, and a verifier that skipped it would
  grant more than was issued.

The library carries `room`, `pub` and `cap` without interpreting them. In
MOQOM, a token with no room admits its holder to no room. The relay lets it
publish only on the holder's own personal channel and read personal channels
in its tenant, refuses every room and backstage name, and refuses a relay link
(`rly`) that names no room. The control plane refuses to deliver room keys to a
token with no room, and refuses to mint one that has `via` but no room, or an
agent token with no room.

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
16. `jkt` is a SHA-256 thumbprint (`thumbprint`).
17. The tenant matches, if pinned (`wrong_tenant`).

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

keys, err := token.ParseJWKSet(document)          // []token.PublicKey; errors.Is(err, token.ErrDuplicateKeyID), …
v := token.NewVerifier(iss, keys...).ForTenant("acme")
claims, err := v.Verify(jws, time.Now())
switch {
case errors.Is(err, token.ErrExpired): …
}
token.Class(err)                                   // "expired", as in the vectors
```

`PublicKey` has `NewPublicKey(alg, id, raw)`, `ID`, `Algorithm`, `Bytes`,
`Verify(msg, sig)` and `JWK`. `Signer` has `ID`, `PublicKey`, `Seed` and
`SignMessage`. `Verifier` has `IsEmpty` and `Key(id)`. Loading a key, a set or
a seed fails with `ErrKeySetMalformed`, `ErrKeyUnsupported`, `ErrKeyInvalid`
or `ErrDuplicateKeyID`, which `Class` also names.

### Rust

```rust
use moqom_token::{Claims, Confirmation, Grant, PublicKey, Signer, Verifier};

let signer = Signer::from_seed(&seed)?.with_id("2026-10");  // or Signer::generate()
let jws = signer.sign(&Claims {
    iss: iss.into(), sub: "ada".into(), tenant: "acme".into(),
    iat, exp: iat + 600,
    cnf: Confirmation { jkt },
    grant: Grant { room: "room-42".into(), publish: 3, ..Grant::default() },
    ..Claims::default()
})?;

let keys = PublicKey::parse_set(&document)?;        // Err(KeyError::DuplicateKeyId(kid)), …
let verifier = Verifier::new(iss, keys).for_tenant("acme");
let claims = verifier.verify(jws.as_bytes(), SystemTime::now())?;
// Err(moqom_token::Error::Expired), …; error.class() == "expired"
```

`PublicKey` has `ml_dsa_65(id, bytes)` and `ed25519(id, bytes)`, which refuse
the wrong length with `KeyError::Invalid`, `verifies(msg, sig)` and `jwk()`;
its fields are public to read, and it cannot be built field by field outside
the crate. `key_id(raw)` derives a key ID. `Signer` has
`generate()`, `seed()`, `id()`, `public_key()` and `sign_message(msg)`.
`Verifier` has `is_empty()`, `key(id)`, `keys()`, `issuer()` and `tenant()`.
Loading a key, a set or a seed fails with `KeyError` (`Malformed`,
`Unsupported`, `Invalid`, `DuplicateKeyId`, `Seed`, `Random`), whose `class()`
names it. The constants are `TOKEN_TYPE`, `MAX_LIFETIME`, `CLOCK_SKEW` and
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

let keys = try PublicKey.parseSet(document)              // throws(PublicKey.SetError)
let verifier = Verifier(issuer: iss, tenant: "acme", keys: keys)
let claims = try verifier.verify(jws, now: Date())        // throws(TokenError)
// TokenError.expired, …; error.errorClass == "expired"
```

`PublicKey(id:algorithm:rawRepresentation:)`, which throws
`.invalid(kid:reason:)` for the wrong length, has `derivedID(for:)`,
`isValidSignature(_:for:)` and `jwk`. `Signer` has `keyID`, `seed`,
`publicKey` and `signature(for:)`. `Verifier` has `isEmpty` and `key(_:)`.
`PublicKey.SetError` is `.malformed(why)`, `.unsupported(kid:)`,
`.invalid(kid:reason:)` or `.duplicateKeyID(kid)`, and its `errorClass` names
it. `TokenLimits` holds the type, the maximum lifetime, the clock skew and the
maximum length.

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
| `thumbprint` | `ErrThumbprint` | `Thumbprint` | `.thumbprint` | `jkt` is not a SHA-256 thumbprint |

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

Loading a key set, or a raw key (the `key_invalid` row):

| Class | Go | Rust (`KeyError`) | Swift (`PublicKey.SetError`) | Meaning |
| --- | --- | --- | --- | --- |
| `set_malformed` | `ErrKeySetMalformed` | `Malformed(why)` | `.malformed(why)` | Not a [JWK](https://www.rfc-editor.org/rfc/rfc7517) set, a `null`, mistyped or repeated member, or a key with no `kty` or `kid` |
| `key_unsupported` | `ErrKeyUnsupported` | `Unsupported { kid }` | `.unsupported(kid:)` | Not `AKP` / `ML-DSA-65` or `OKP` / `Ed25519` |
| `key_invalid` | `ErrKeyInvalid` | `Invalid { kid, reason }`, `Seed` | `.invalid(kid:reason:)` | Public key not canonical base64url or the wrong length; a bad seed |
| `duplicate_kid` | `ErrDuplicateKeyID` | `DuplicateKeyId(kid)` | `.duplicateKeyID(kid)` | Two keys in the set share a `kid` |

Rust's `KeyError::Random` (class `random`) is `Signer::generate` failing to
read the system random number generator; no vector names it.

## Vectors

`vectors/token` is generated by the Go tests:

```sh
cd go && MOQOM_WRITE_VECTORS=1 go test ./token -run TestVectors
```

Without the variable, the test checks that the committed files are what this
build would write. The generator uses fixed seeds and
`now = 1800000000`. The top-level `keys` array lists each key's ID, algorithm,
seed and public key.

- `verify.json` has 120 cases. Each gives a token, a time, an issuer, a tenant
  and a key set, together with either the claims it yields or the error class.
  They cover:
  - valid [ML-DSA-65](https://csrc.nist.gov/pubs/fips/204/final) tokens and the legacy Ed25519 ones;
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
  - every malformed reason, including non-canonical base64url, line breaks
    inside a segment, and non-object JSON;
  - correctly signed segments that break a parsing rule: `null` and non-object
    segments, `null` and mistyped members, `iat`, `exp`, `pub` and `cap` with
    exponents, fractions, `-0` or out of range, unpaired surrogate escapes,
    invalid UTF-8, a raw control character, a byte order mark, trailing data,
    `1e400`, a leading zero, and nesting one deeper than allowed; and the edge
    cases that must pass: nesting exactly 127 deep, `1e-400`, a `null` or
    fractional unknown claim, a surrogate pair, escaped names and
    whitespace, and `pub` and `cap` at their limits;
  - issuer and tenant compared byte for byte, without Unicode normalization;
  - `cnf.jkt` values that are not a SHA-256 thumbprint: too short, too long,
    padded, outside the alphabet, non-canonical trailing bits, a line break,
    and a 16-character device ID.
- `sign.json` has 18 cases: five valid claim sets with their exact signing
  input and a deterministic token, and thirteen that a signer must refuse.
- `keysets.json` has 49 cases. Each gives a [JWK](https://www.rfc-editor.org/rfc/rfc7517) set document and either the
  key IDs it yields, in order, or the error class. They cover both shapes, the
  empty set, ignored members, duplicate key IDs (byte for byte), every
  `set_malformed` cause, the parsing rules where a key set can break them
  (surrogates, depth, number range, a byte order mark, trailing data, keys
  written as arrays), unsupported key types, and bad key material.

The runners:

- Go: `go test ./token`
- Rust: `cargo test -p moqom-token`
- Swift: `swift test --filter MoqomTokenTests`

## Known gaps

- The library does not track token IDs (`jti`), so it does not detect replay.
  A token is a bearer of rights for at most fifteen minutes, and the
  proof-of-possession check is what binds it to a session.
