# moqom-proof

Device proof of possession for MOQOM sessions. A join token names a device key
by its [JWK](https://www.rfc-editor.org/rfc/rfc7517) thumbprint (`cnf.jkt`). At connect, and with every in-session token
renewal, the device signs a fresh single-use proof that commits to the token,
to the TLS leaf certificate of the peer it is talking to, and to the time. The
peer checks that the proof was signed by the key the token names, and spends
its nonce.

Proofs follow the shape of [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449) (DPoP), with the peer's certificate in
place of `htm` and `htu`. ML-DSA-65 ([FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)) is the default; ES256 is
accepted while devices holding older keys roll over. Cryptography is from
AWS-LC through `aws-lc-rs`.

```rust
use std::time::{Duration, SystemTime};

use aws_lc_rs::digest::{SHA256, digest};
use moqom_proof::{Algorithm, Checker, Error, MemoryNonceStore, Prover, nonce};

fn main() -> Result<(), Error> {
    let device = Prover::generate(Algorithm::MlDsa65)?;
    let token = b"eyJhbGciOiJNTC1EU0EtNjUi...";
    let relay_certificate = digest(&SHA256, b"the relay's leaf certificate, DER");
    let now = SystemTime::now();
    let proof = device.prove(token, relay_certificate.as_ref(), &nonce()?, now)?;

    let checker = Checker::new(MemoryNonceStore::default());
    let expiry = now + Duration::from_secs(15 * 60);
    checker.check(&proof, token, Some(relay_certificate.as_ref()), device.thumbprint(), now, expiry)?;
    Ok(())
}
```

The same library is available in Swift (`MoqomProof`) and Go
(`github.com/moqom-cloud/moqom-security/go/proof`), and all three pass the
shared vectors in `vectors/proof`.

- Reference: <https://moqom.dev/security/libraries/proof/>
- Design and wire format: [`docs/moqom-proof.md`](https://github.com/moqom-cloud/moqom-security/blob/main/docs/moqom-proof.md)
- Source: <https://github.com/moqom-cloud/moqom-security>

Licensed under Apache-2.0.
