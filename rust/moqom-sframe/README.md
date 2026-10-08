# moqom-sframe

SFrame ([RFC 9605]) for MoQ objects. Each object's payload is sealed with
AES-GCM under a key derived from a base key and a KID. The object's full track
name, group, object ID, priority and properties, the fields
`draft-ietf-moq-secure-objects` authenticates, stay in the clear for relays and
are bound into the authentication tag as AAD after the RFC 9605 header. The
sender owns the counter, and the receiver keeps a replay window per KID.

```rust
use moqom_sframe::{CipherSuite, Context, Metadata, Property, Track};

let base_key = [0x2a; 32]; // in a room, exported from the MLS group
let context = Context::new(CipherSuite::Aes256GcmSha512, 1, &base_key)?;
let metadata = Metadata { track: Track::new(["moqom", "demo", "alice"], "video"),
                          group: 5, object: 2, priority: 64,
                          properties: vec![Property::integer(0x78, 1_000_000)] };
let object = context.seal(b"frame", &metadata)?;
let payload = context.open(&object, &metadata)?;
```

Suites `0x0004` (AES-128-GCM-SHA256) and `0x0005` (AES-256-GCM-SHA512, the
default) are implemented; the AES-CTR + HMAC suites are not. Cryptography is
from AWS-LC through `aws-lc-rs`.

The same library is available in Swift (`MoqomSFrame`) and Go
(`github.com/moqom-cloud/moqom-security/go/sframe`), and all three pass the
shared vectors, including RFC 9605 Appendix C.

- Reference: <https://moqom.dev/security/libraries/sframe/>
- Design: <https://github.com/moqom-cloud/moqom-security/blob/main/docs/moqom-sframe.md>
- Source and vectors: <https://github.com/moqom-cloud/moqom-security>

Licensed under Apache-2.0.

[RFC 9605]: https://www.rfc-editor.org/rfc/rfc9605
