<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Elliott Wave LLC -->

# moqom-sframe

End-to-end encryption for MoQ objects with SFrame ([RFC 9605]). Each object's
payload is sealed with AES-GCM under a key that only the room's members hold.
The fields a relay needs to schedule (group, object, priority and object
properties) stay in the clear and are bound into the authentication tag. A
relay can read, forward, drop and reorder objects. It cannot read a payload,
and it cannot change a field without the object failing to open.

The library is the same in Swift (`MoqomSFrame`), Go
(`github.com/moqom-cloud/moqom-security/go/sframe`) and Rust (`moqom-sframe`).
All three pass every case in [`vectors/sframe`](../vectors/sframe).

[RFC 9605]: https://www.rfc-editor.org/rfc/rfc9605

## What it does

- **Suites.** AES-128-GCM-SHA256 (`0x0004`) and AES-256-GCM-SHA512 (`0x0005`,
  the default). The AES-CTR + HMAC suites (`0x0001`–`0x0003`) are not
  implemented. Every platform we target has hardware AES-GCM, and the CTR
  suites would mean composing CTR-then-HMAC ourselves to save a few tag bytes.
- **Keys.** Each key is derived from a base key and a KID, as RFC 9605 §4.4.2
  specifies:
  - `secret = HKDF-Extract("", base_key)`
  - `key = HKDF-Expand(secret, "SFrame 1.0 Secret key " || KID(8) || suite(2), Nk)`
  - `salt = HKDF-Expand(secret, "SFrame 1.0 Secret salt " || KID(8) || suite(2), 12)`
  
  Because the KID and suite are part of both labels, a ciphertext made under
  one KID or suite never opens under another.
- **Counters.** The sender owns the counter. It starts at 0 for each key and
  goes up by one per object. No API lets a caller choose a counter. The nonce
  is `salt XOR counter`, with the counter big-endian in the low eight bytes.
  The counter value 2^64 − 1 is never issued: rather than wrap, the sender
  refuses with `counter_exhausted`.
- **Metadata binding.** The AAD is the encoded SFrame header followed by the
  object's canonical metadata (below). This follows the shape of
  `draft-ietf-moq-secure-objects`.
- **Replay window.** For each KID, the receiver tracks the highest counter it
  has seen plus a bitmap of the window of counters at and below it:
  - A counter above the highest is accepted, however far ahead.
  - A counter below the highest is accepted only if it is less than the window
    behind and has not been seen. With the default window of 1024, the highest
    minus 1023 is accepted and the highest minus 1024 is refused.
  - The bitmap is a ring of 64-bit words, one more than the window needs (17
    words, 136 bytes, for 1024). Windows above 65536 behave as 65536, which is
    8 KiB per KID.
  - A counter is recorded only after the object authenticates, so a forged
    object cannot use up the counter of the real one behind it.
  - Adding a key resets that key's window.
- **MLS KIDs** (RFC 9605 §5.2, context 0, E = 4): `KID = (leaf << 4) | (epoch
  mod 16)`. The base key for an epoch is `MLS-Exporter("SFrame 1.0 Base Key",
  "", Nk)`. The MLS group itself is in `moqom-mls`.

## Wire format

An SFrame object is `header || ciphertext || tag`, with a 16-byte tag.

The header is RFC 9605 §4.3 unchanged. It starts with a config byte laid out as
`X KKK Y CCC`:

- If `X` is 0, `KKK` is the KID itself (0–7).
- If `X` is 1, `KKK + 1` is the number of big-endian KID bytes that follow.
- `Y` and `CCC` do the same for the counter. Any KID bytes come before any
  counter bytes.

The encoder always uses the fewest bytes. The decoder also accepts non-minimal
forms: the tag covers the header bytes exactly as received, so nobody without
the key can produce one.

Metadata is encoded canonically, as the MOQT wire encoding of the same fields.
Integers are QUIC varints (RFC 9000 §16, minimal length, at most 2^62 − 1):

```
varint(group) || varint(object) || priority(1 byte)
  || varint(property count)
  || for each property, sorted by type (stable, so equal types keep their order):
       varint(type − previous type)
       || even type: varint(value)
       || odd type:  varint(length) || bytes   (length ≤ 65535)
```

Metadata with no encoding is `invalid_metadata`. That covers an even type with
bytes, an odd type with an integer, a value at or above 2^62, and bytes over
65535. MOQOM's property types are listed in the SDK's `MoqomObjectProperty`:
capture time `0x78`, decoder configuration `0x79`, temporal layer `0x7A`,
silence `0x7C`, catalog disclosure `0x7D`, authority signature `0x7F`.

## API

`Context(suite, keyID, baseKey)`, `seal(payload, metadata) -> object` and
`open(object, metadata) -> payload` hold one key for both directions. A room
uses a `Sender` per outgoing stream and one `Receiver` that holds every other
member's key. The raw-`Data` forms of `protect` and `unprotect` take arbitrary
AAD and exist for RFC 9605 interop. MoQ objects go through the metadata forms.

### Swift (`import MoqomSFrame`)

```swift
let context = SFrameContext(suite: .aes256GcmSha512, keyID: 1, baseKey: base)
let metadata = SFrameMetadata(group: 5, object: 2, priority: 64,
                              properties: [.integer(0x78, 1_000_000)])
let object = try context.seal(payload, metadata: metadata)
let payload = try context.open(object, metadata: metadata)

let key = SFrameKey(keyID: SFrameKeyID.mls(leaf: 3, epoch: 14), baseKey: base)
let sender = SFrameSender(key: key)        // or SFrameSender() until a key arrives
try sender.protect(payload, metadata: metadata)
sender.rekey(next); sender.clearKey()

let receiver = SFrameReceiver(replayWindow: 1024)
receiver.add(key); receiver.remove(keyID: key.keyID)
receiver.setResolver { kid in /* derive or return nil */ nil }
try receiver.unprotect(object, metadata: metadata)
```

Errors are thrown as `SFrameError`. `SFrameHeader` encodes and reads headers.
The MoqomKit SDK re-exports this module and adds `SFrameMetadata(TrackObject)`.

### Go

```go
ctx, err := sframe.NewContext(sframe.AES256GCMSHA512, 1, base) // NewContextWindow for a window
md := sframe.Metadata{Group: 5, Object: 2, Priority: 64,
    Properties: []sframe.Property{sframe.IntegerProperty(0x78, 1_000_000)}}
object, err := ctx.Seal(payload, md)
payload, err := ctx.Open(object, md)

key, err := sframe.NewKey(sframe.MLSKeyID(3, 14), base, sframe.AES256GCMSHA512)
s := sframe.NewSender(key) // NewSender(nil) refuses until Rekey
object, err = s.ProtectObject(payload, md)
r := sframe.NewReceiver(sframe.DefaultReplayWindow)
r.Add(key); r.SetResolver(func(kid uint64) *sframe.Key { return nil })
payload, err = r.UnprotectObject(object, md)
```

`sframe.Class(err)` returns the vector class. `*UnknownKeyError` and
`*ReplayError` carry the KID and the counter, and match `ErrUnknownKey` and
`ErrReplay` with `errors.Is`.

### Rust

```rust
use moqom_sframe::{CipherSuite, Context, Key, Metadata, Property, Receiver, Sender, mls_key_id};

let context = Context::new(CipherSuite::Aes256GcmSha512, 1, &base); // with_replay_window
let metadata = Metadata { group: 5, object: 2, priority: 64,
                          properties: vec![Property::integer(0x78, 1_000_000)] };
let object = context.seal(&payload, &metadata)?;
let payload = context.open(&object, &metadata)?;

let sender = Sender::new(Key::new(mls_key_id(3, 14), &base, CipherSuite::default())); // Sender::empty()
let object = sender.protect_object(&payload, &metadata)?;
let receiver = Receiver::default();
receiver.add(Key::new(mls_key_id(3, 14), &base, CipherSuite::default()));
receiver.set_resolver(Some(|kid| None));
let payload = receiver.unprotect_object(&object, &metadata)?;
```

`moqom_sframe::Error::class()` returns the vector class. A property's type is
named `code` in Rust, because `type` is a keyword.

## Error classes

| Class | Meaning |
| --- | --- |
| `malformed_header` | Empty input, or a header that says it has more KID or CTR bytes than there are |
| `unknown_key` | No key held, and the resolver returned none, for the header's KID. Recoverable: the key may still be on its way |
| `authentication_failure` | The tag does not verify, or the input is shorter than a tag. Do not report it onward in any more detail |
| `replay` | The counter has already been seen, or is older than the window |
| `counter_exhausted` | The sender has used every counter under its key, and must rekey |
| `no_key` | The sender has no key, so it refuses rather than send in the clear |
| `invalid_metadata` | The metadata has no canonical encoding |
| `unsupported_suite` | A cipher suite number other than 4 or 5 (Go and Rust; Swift's suite type cannot hold one) |

A receiver checks in this order: metadata encoding (for the metadata forms),
then header, then key, then replay window, then tag.

## Vectors

| File | Cases | What |
| --- | --- | --- |
| `rfc9605.json` | 297 | RFC 9605 Appendix C as published. C.1: 289 headers. C.2: 3 AES-CTR + HMAC AEAD cases. C.3: 5 SFrame cases. The 6 cases marked `skip` are suites 1–3, which are not implemented. All three languages run the other 291: every header, plus C.3 for suites 4 and 5 down to the label, secret, key, salt, nonce, AAD and ciphertext |
| `metadata.json` | 18 | Canonical encodings at each varint size boundary: sorting, repeated types, empty and two-byte-length bytes, large type deltas. 6 have no encoding |
| `kid.json` | 14 | MLS KIDs, epoch tags, and the header each produces at counter 0 |
| `nonce.json` | 40 | Key, salt, nonce and header for both suites and two KIDs, at counters from 0 to 2^64 − 1 |
| `seal-open.json` | 10 (32 objects) | Context seal must reproduce each object byte for byte, and open must return each payload. Covers empty payloads, the maximum KID, and a counter crossing into the extended form |
| `open.json` | 50 | Per suite: every metadata field changed (group, object, priority, each property, a property added, removed or retyped) gives `authentication_failure`. Also covers ciphertext, tag and counter changes, a changed KID (`unknown_key`), truncation and malformed headers, objects sealed under the other suite or another base key, invalid metadata, a non-minimal header (which opens), and reordered properties (which open) |
| `replay.json` | 22 (100 steps) | Duplicates, reordering, the edges of windows of 1024, 64 and 8, duplicates across a 1024 window, jumps far ahead, the cap at 65536, a forward jump, a forgery that does not use up its counter, and the top of the counter space |

`rfc9605.json` comes from `extract-rfc9605.py`, which reads the RFC text. Its
output matches the working group's `test-vectors.json` for every RFC case. The
other files come from the Swift implementation:

```
MOQOM_WRITE_VECTORS=1 swift test --filter SFrameVectorGeneration
```

Without the variable, the same test regenerates the vectors in memory and fails
if the result differs from the checked-in files.

Not covered by vectors: `counter_exhausted` (reaching it takes 2^64 seals),
`no_key` (a `Context` always has a key; unit tests in each language cover it),
and a byte property over 65535 bytes (left out because it would make the file
large).

## Tests

```
swift test --filter MoqomSFrameTests                     # moqom-security root
cd go && go test -race ./sframe
cd rust && cargo test -p moqom-sframe
```
