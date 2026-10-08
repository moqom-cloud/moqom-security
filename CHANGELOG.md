# Changelog

All four libraries are released together under one version, in all three languages. Tags are
`v<version>` for the Swift package and Rust crates and `go/v<version>` for the Go module.

## 0.1.0 (October 2026)

The first release.

### moqom-token

- Mints and verifies MOQOM join tokens as compact JWS signed with ML-DSA-65 (FIPS 204), with
  tenant, room, grants, expiry, device binding (`cnf.jkt`) and key rotation by key ID.
- Verifies Ed25519 tokens signed before the move to ML-DSA-65; never signs them.
- Refuses tokens whose header or claims repeat a member name.

### moqom-proof

- A device's single-use proof of the key its token names, signed with ML-DSA-65 (Secure Enclave
  on Apple platforms) and bound to the token and to the certificate of the peer it talks to.
- Accepts ES256 proofs from older SDKs.
- Refuses proofs whose JWK carries private key members, and proofs naming a certificate when the
  checker has none to compare; `requireCertificate` makes the certificate mandatory.

### moqom-sframe

- Seals and opens MoQ objects with RFC 9605 SFrame, binding the object's position, priority and
  properties into the tag as draft-ietf-moq-secure-objects describes.
- A replay window of 1,024 counters by default, configurable up to 65,536.

### moqom-mls

- MLS (RFC 9420) key agreement for rooms with `MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65`
  (0xF0AA) for new groups, exporting SFrame keys and the epoch authenticator, and sealing an
  epoch's key to broadcast viewers.
- Opens legacy groups in X-Wing (0xF0A1) and `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`
  (0x0001) in every language.
- Rust wipes HPKE secrets, epoch secrets and private keys when they are dropped.

### Test vectors

- One JSON vector set shared by all three languages, plus the published RFC 9605, mlswg, X-Wing
  draft and HPKE working group vectors. See `NOTICE` for their licences.
