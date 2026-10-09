<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Elliott Wave LLC -->

# moqom-mls

Group key agreement for MOQOM rooms: the subset of MLS ([[RFC 9420](https://www.rfc-editor.org/rfc/rfc9420)]) the
devices in a room use to agree a secret each epoch, and the [SFrame](https://www.rfc-editor.org/rfc/rfc9605) base key
([RFC 9605] §5.2) every member encrypts media under. New groups are founded in
`MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65` (`0xF0AA`): [ML-KEM-768](https://csrc.nist.gov/pubs/fips/203/final) key
encapsulation and [ML-DSA-65](https://csrc.nist.gov/pubs/fips/204/final) signatures. Groups founded in X-Wing (`0xF0A1`)
or `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (`0x0001`) still work.

```rust
use moqom_mls::{CipherSuite, Group, KeyPackageBundle, SFRAME_EXPORTER_LABEL};

let alice = KeyPackageBundle::generate("alice/phone", CipherSuite::FOUNDING)?;
let bob = KeyPackageBundle::generate("bob/laptop", CipherSuite::FOUNDING)?;

let add = Group::create(b"acme/room-42", &alice)?.commit(&[bob.key_package.clone()], &[])?;
let bob_group = Group::join(add.welcome.as_ref().unwrap(), &bob)?;
assert_eq!(add.next.epoch_authenticator(), bob_group.epoch_authenticator());
let base_key = bob_group.exporter(SFRAME_EXPORTER_LABEL, &[], 32)?;
```

It is not a general MLS implementation: members are a flat list rather than a
ratchet tree, messages use MOQOM's own framing, and there are no PSKs, external
commits or PrivateMessage. The primitives and key schedule are RFC 9420's and
are checked against the MLS working group's vectors. Cryptography is AWS-LC's,
through `aws-lc-rs`.

`Group::exporter`, `EpochSecrets::exporter` and `CipherSuite::expand_with_label`
refuse a length past HKDF-Expand's limit of 255 times the suite's hash length
with `Error::InvalidLength { length, max }`, class `invalid-length`.

The same library is available in Swift (`MoqomMLS`) and Go
(`github.com/moqom-cloud/moqom-security/go/mls`), and all three pass the shared
vectors in
[`vectors/mls`](https://github.com/moqom-cloud/moqom-security/tree/main/vectors/mls).

- Reference: <https://moqom.dev/security/libraries/mls/>
- Design: [`docs/moqom-mls.md`](https://github.com/moqom-cloud/moqom-security/blob/main/docs/moqom-mls.md)
- API: <https://docs.rs/moqom-mls>

Licensed under Apache-2.0.

[RFC 9420]: https://www.rfc-editor.org/rfc/rfc9420
[RFC 9605]: https://www.rfc-editor.org/rfc/rfc9605
