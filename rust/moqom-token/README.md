<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Elliott Wave LLC -->

# moqom-token

Mint and verify the token a MOQOM client joins a relay with. A token is a
compact [JWS](https://www.rfc-editor.org/rfc/rfc7515), typed `MOQT`, signed with ML-DSA-65 ([FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)). It names a
tenant, a user, the device key it is bound to (`cnf.jkt`), a room and what
the holder may do there, and it lasts at most fifteen minutes. Ed25519 keys
still verify, so tokens signed before the move to ML-DSA keep working until
they expire; nothing signs with Ed25519.

```rust
use moqom_token::{Signer, Verifier};

let signer = Signer::from_seed(&seed)?.with_id("2026-10");
let jws = signer.sign(&claims)?;

let verifier = Verifier::new("https://api.example.com", [signer.public_key()]).for_tenant("acme");
let claims = verifier.verify(jws.as_bytes(), std::time::SystemTime::now())?;
```

The same library exists in Go (`github.com/moqom-cloud/moqom-security/go/token`)
and Swift (`MoqomToken`), and all three pass the shared vectors in
[`vectors/token`](https://github.com/moqom-cloud/moqom-security/tree/main/vectors/token).

- Reference: <https://moqom.dev/security/libraries/token/>
- Design: [`docs/moqom-token.md`](https://github.com/moqom-cloud/moqom-security/blob/main/docs/moqom-token.md)
- API: <https://docs.rs/moqom-token>

Licensed under Apache-2.0.
