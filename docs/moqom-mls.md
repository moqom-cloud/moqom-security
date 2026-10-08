<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Elliott Wave LLC -->

# moqom-mls

Group key agreement for MOQOM rooms: the subset of MLS ([RFC 9420]) that the
devices in a room use to agree on a secret each epoch. It also produces the
SFrame base key every member encrypts media under ([RFC 9605] §5.2). Every new
group is post-quantum: key packages, commits and Welcomes use ML-KEM-768 and
ML-DSA-65.

The library is the same in Swift (`MoqomMLS`), Go
(`github.com/moqom-cloud/moqom-security/go/mls`) and Rust (`moqom-mls`). All
three pass every case in [`vectors/mls`](../vectors/mls), including the vectors
the other two generated.

[RFC 9420]: https://www.rfc-editor.org/rfc/rfc9420
[RFC 9605]: https://www.rfc-editor.org/rfc/rfc9605
[RFC 9180]: https://www.rfc-editor.org/rfc/rfc9180

## What it does

- **Key packages.** A device publishes a key package so it can be added. The
  package carries its identity (`username/device`), a signature key, and two
  KEM keys in one cipher suite: an init key, used once to receive a Welcome,
  and an encryption key, which becomes its leaf key. It is signed with
  `SignWithLabel("KeyPackageTBS")`. Verifying a package checks the key
  lengths, that both KEM keys pass FIPS 203's encapsulation-key check, that
  the init key and encryption key differ, and the signature.
- **Groups.** A member creates a group, commits to add and remove members, and
  processes other members' commits. A commit with no proposals is an Update
  that refreshes the committer's leaf key. Each member derives the same epoch
  secrets, epoch authenticator and exporter. A commit is checked in a fixed
  order (group, epoch, sender, signature, proposals, sealed secret,
  confirmation tag), so all three languages report the same failure for the
  same bytes.
- **Joining.** A new member joins from a Welcome. It opens the joiner secret
  with its init key, decrypts the GroupInfo, and verifies the GroupInfo
  signature, the member-list hash and the confirmation tag.
- **Exporter.** `MLS-Exporter(label, context, length)` as RFC 9420 §8.5
  defines it. HKDF-Expand produces at most 255 times the suite's hash length:
  8,160 bytes in `0xF0A1` and `0x0001`, 12,240 in `0xF0AA`. A longer (or, in
  Swift and Go, negative) length is refused as `invalid-length` in all three
  languages. The SFrame base key for an epoch is
  `exporter("SFrame 1.0 Base Key", "", Nk)`. Each member's KID is
  `(leaf << 4) | (epoch % 16)`, built by `MoqomSFrame`'s `SFrameKeyID` in
  Swift.
- **Audience envelopes.** A viewer in a large broadcast is not a member. It
  holds an ML-KEM-768 key pair, and the committer seals each epoch's SFrame
  base key to it:
  `EncryptWithLabel(pk, "MOQOM audience key", vector(group_id) || uint64(epoch), base_key)`
  in suite 0xF0AA, whatever suite the group is in. An envelope opens only for
  the group and epoch it was sealed for.

## Cipher suites

| Value    | Name                                              | KEM                      | KDF / AEAD               | Signature  |
| -------- | ------------------------------------------------- | ------------------------ | ------------------------ | ---------- |
| `0xF0AA` | `MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65`       | HPKE `0x0041`, ML-KEM-768 | HKDF-SHA384, AES-256-GCM | ML-DSA-65  |
| `0xF0A1` | `MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519` | HPKE `0x647a`, X-Wing     | HKDF-SHA256, AES-128-GCM | Ed25519    |
| `0x0001` | `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`    | HPKE `0x0020`, X25519     | HKDF-SHA256, AES-128-GCM | Ed25519    |

`0xF0AA` is the founding suite: every new group is created in it, and the
delivery service refuses to found a group in any other. The other two remain
so that groups already founded in them can be followed. `0xF0AA` and `0xF0A1`
are draft-ietf-mls-pq-ciphersuites' suites. They sit in RFC 9420's private-use
range until IANA assigns values, and must then change in all three languages
together.

ML-DSA-65 is pure ML-DSA with an empty context. HPKE is RFC 9180 base mode,
single-shot, with empty AAD. For KEMs `0x0041` and `0x647a` the shared secret
is the KEM's own (draft-ietf-hpke-pq). For X-Wing that is
draft-connolly-cfrg-xwing-kem's `SHA3-256(ss_M || ss_X || ct_X || pk_X ||
"\.//^\")`. The public key is ML-KEM-768's encapsulation key followed by
X25519's, and the encapsulation is ML-KEM-768's ciphertext followed by X25519's.

An X-Wing encapsulation whose X25519 half gives an all-zero shared value is
refused by Rust (AWS-LC) and Go (`crypto/ecdh`). The draft does not require
this check. An honest sender never produces such a value, so it makes no
difference to an honest exchange.

Private keys are stored as RFC 9180's `SerializePrivateKey` gives them:

- ML-KEM-768: the 64-byte seed `d || z`.
- X-Wing: the 32-byte seed.
- X25519: the raw scalar.
- Signature keys: the 32-byte seed (FIPS 204's ξ for ML-DSA-65, or the Ed25519
  seed).

Nothing here implements a primitive:

- Swift composes CryptoKit. CryptoKit has no HPKE over pure ML-KEM, so the
  RFC 9180 key schedule is written in `CipherSuite.swift`.
- Go uses `crypto/hpke`, `crypto/mlkem`, `crypto/mldsa`, `crypto/hkdf` and
  `crypto/ed25519`.
- Rust composes aws-lc-rs. RFC 9180 HPKE is written in `src/hpke.rs`, and
  ML-KEM keys load from their seed through AWS-LC's PKCS#8 seed form (see
  [Unsafe code](#unsafe-code)). aws-lc-rs has no X-Wing, so `src/xwing.rs`
  composes it from aws-lc-rs's ML-KEM-768, X25519 and SHA3-256. The 32-byte
  seed is expanded with SHAKE256, which aws-lc-rs does not expose, so that
  comes from RustCrypto's `sha3` crate (0.11, no default features). `sha3`
  forbids `unsafe`, but its `keccak` dependency uses ARMv8 SHA-3 intrinsics
  when the CPU has them. It is the only primitive not taken from AWS-LC.

The hand-written compositions, Swift's ML-KEM HPKE and Rust's HPKE and X-Wing,
are held to Go's `crypto/hpke` and CryptoKit's `XWingMLKEM768X25519` by the
vectors. Each language opens ciphertexts the other two sealed, in `0xF0AA` and
in `0xF0A1`.

## Wire formats

Everything is RFC 9420 §2.1's TLS presentation language: big-endian integers,
and `vector` meaning a §2.1.2 variable-length size followed by the bytes. A
size not in its shortest form is refused.

```
KeyPackage      = uint16 version(1) || uint16 suite || vector identity
                  || vector signature_key || vector init_key
                  || vector encryption_key || vector signature
KeyPackageRef   = RefHash("MLS 1.0 KeyPackage Reference", KeyPackage)

GroupContext    = RFC 9420 §8.1, extensions always empty;
                  tree_hash = RefHash("MOQOM 1.0 Member List", Members)
Members         = uint32 count || count × (uint8 0 | uint8 1 || Leaf)
Leaf            = vector identity || vector signature_key || vector encryption_key

CommitMessage   = FramedContent || vector signature || vector confirmation_tag
FramedContent   = vector group_id || uint64 epoch || uint32 sender || vector Commit
Commit          = uint32 n || n × Proposal || vector committer_encryption_key
                  || uint32 m || m × (uint32 leaf || HPKECiphertext)
Proposal        = uint16 1 || vector KeyPackage      (Add)
                | uint16 3 || uint32 leaf            (Remove)
HPKECiphertext  = vector kem_output || vector ciphertext

Welcome         = uint32 n || n × (vector KeyPackageRef || HPKECiphertext)
                  || vector encrypted_group_info
GroupInfo       = GroupContext || Members || vector confirmation_tag
                  || uint32 signer || vector signature
AudienceEnvelope = HPKECiphertext
```

Signatures and sealed secrets:

| What                | How                                                                                        |
| ------------------- | ------------------------------------------------------------------------------------------ |
| Key package         | `SignWithLabel(sk, "KeyPackageTBS", KeyPackage without signature)`                          |
| Commit              | `SignWithLabel(sk, "FramedContentTBS", GroupContext(epoch n) || FramedContent)`             |
| GroupInfo           | `SignWithLabel(sk, "GroupInfoTBS", GroupInfo without signature)`                            |
| Commit secret       | `EncryptWithLabel(leaf_key, "UpdatePathNode", GroupContext(epoch n+1, new tree hash, confirmed hash of epoch n), commit_secret)` |
| Joiner secret       | `EncryptWithLabel(init_key, "Welcome", encrypted_group_info, joiner_secret)`                |
| GroupInfo encryption | AEAD with `key = ExpandWithLabel(welcome_secret, "key", "", Nk)`, `nonce = ExpandWithLabel(welcome_secret, "nonce", "", 12)`, empty AAD |

The transcript is RFC 9420 §8.2's, over this framing:

- `confirmed = Hash(interim || FramedContent || vector(signature))`
- `tag = MAC(confirmation_key, confirmed)`
- `interim = Hash(confirmed || vector(tag))`

A new group's epoch 0 starts from random init and commit secrets, with an
empty confirmed hash and `tag = MAC(confirmation_key, "")`.

A commit's proposals are applied the same way on every member:

1. Every Remove.
2. Each Add, in order, into the leftmost blank leaf (or appended).
3. Trailing blank leaves are trimmed.

The committer's leaf then takes the new encryption key. Leaf indices are never
sent, and every member derives the same list.

## API

The same operations in each language. Errors are those in
[Error classes](#error-classes).

### Swift (`import MoqomMLS`)

Names keep the `MLS` prefix so they cannot collide with SwiftUI's `Group`.

```swift
let bundle = try MLSKeyPackageBundle.generate(identity: "alice/phone", cipherSuite: .mls192MLKEM768MLDSA65)
let package = try MLSKeyPackage.decode(bytes); try package.verify()

var group = try MLSGroup.create(groupID: id, bundle: bundle)
let pending = try group.commit(adding: [bob.keyPackage], removing: [])   // .message, .welcome, .next
let bobGroup = try MLSGroup.join(pending.welcome!, bundle: bob)
switch try bobGroup.process(MLSCommitMessage.decode(bytes)) {
case .advanced(let next): ...
case .removed: ...
}
try group.exporter(label: "SFrame 1.0 Base Key", length: 32)
group.epochAuthenticator; group.roster
group.sframeBaseKey(suite: .aes256GcmSha512); group.sframeKeys(suite:)   // RFC 9605 §5.2

let keys = bundle.privateKeys            // (initPrivate, encryptionPrivate, signaturePrivate)
let restored = MLSKeyPackageBundle(keyPackage: try MLSKeyPackage.decode(stored),
    initPrivate: keys.initPrivate, encryptionPrivate: keys.encryptionPrivate,
    signaturePrivate: keys.signaturePrivate)

let viewer = try MLSAudience.generateKeyPair()
let envelope = try MLSAudience.seal(base, to: viewer.publicKey, groupID: id, epoch: 7)
let base = try MLSAudience.open(envelope, privateKey: viewer.privateKey, groupID: id, epoch: 7)
```

The suite primitives are on `MLSCipherSuite`: `expandWithLabel`,
`deriveSecret`, `refHash`, `signWithLabel`, `verifyWithLabel`,
`encryptWithLabel`, `decryptWithLabel` and the key-pair generators. The key
schedule is `MLSGroupContext` and `MLSEpochSecrets.derive(...)` /
`.exporter(...)`.

### Go

```go
bundle, err := mls.GenerateKeyPackage("alice/phone", mls.FoundingSuite)
k, err := mls.ParseKeyPackage(data)        // DecodeKeyPackage + Verify

g, err := mls.CreateGroup(id, bundle)
p, err := g.Commit([]*mls.KeyPackage{bob.KeyPackage}, nil) // p.Message, p.Welcome, p.Next
w, err := mls.DecodeWelcome(data)
bobGroup, err := mls.Join(w, bob)
m, err := mls.DecodeCommitMessage(data)
next, removed, err := bobGroup.Process(m)
base, err := g.Exporter(mls.SFrameExporterLabel, nil, 32)
g.EpochAuthenticator()

initPriv, encPriv, sigPriv := bundle.PrivateKeys()
restored := mls.NewKeyPackageBundle(k, initPriv, encPriv, sigPriv)

priv, pub, err := mls.GenerateAudienceKeyPair()
env, err := mls.SealAudience(base, pub, id, 7)
base, err := mls.OpenAudience(env, priv, id, 7)
```

The suite primitives are methods on `mls.CipherSuite`: `ExpandWithLabel`,
`DeriveSecret`, `RefHash`, `SignWithLabel`, `VerifyWithLabel`,
`EncryptWithLabel` and `DecryptWithLabel`. The key schedule is
`mls.GroupContext`, `mls.DeriveEpochSecrets` and `(*EpochSecrets).Exporter`.
`(*KeyPackageBundle).PrivateKeys` and `mls.NewKeyPackageBundle` store and
restore a bundle.

### Rust

```rust
let bundle = KeyPackageBundle::generate("alice/phone", CipherSuite::FOUNDING)?;
let package = KeyPackage::parse(&bytes)?;      // decode + verify

let group = Group::create(&id, &bundle)?;
let pending = group.commit(&[bob.key_package.clone()], &[])?; // .message, .welcome, .next
let bob_group = Group::join(&Welcome::decode(&bytes)?, &bob)?;
match bob_group.process(&CommitMessage::decode(&bytes)?)? {
    Processed::Advanced(next) => ..., Processed::Removed => ...,
}
group.exporter(SFRAME_EXPORTER_LABEL, &[], 32)?;
group.epoch_authenticator();

let (init, encryption, signature) = bundle.private_keys();
let restored = KeyPackageBundle::new(package, init.to_vec(), encryption.to_vec(), signature.to_vec());

let (private, public) = audience::generate_key_pair()?;
let envelope = audience::seal(&base, &public, &id, 7)?;
let base = audience::open(&envelope, &private, &id, 7)?;
```

The suite primitives are methods on `CipherSuite`: `expand_with_label`,
`derive_secret`, `ref_hash`, `sign_with_label`, `verify_with_label`,
`encrypt_with_label`, `decrypt_with_label` and `kem_public_key`. The key
schedule is `GroupContext`, `EpochSecrets::derive` and
`EpochSecrets::exporter`.

`Group`, `PendingCommit`, `Processed` and `EpochSecrets` implement `Debug`
with every secret and private key left out.

Rust implements HPKE in all three suites, X-Wing included.

## Error classes

The vectors name a class, never a message. Each language maps its errors onto
these classes:

- **Swift:** `MLSError` cases; `MLSError.errorClass` is the class.
- **Go:** sentinels matched with `errors.Is`; `mls.Class(err)` is the class.
- **Rust:** `Error` variants; `Error::class()` is the class.

| Class                   | Meaning                                                                      |
| ----------------------- | ---------------------------------------------------------------------------- |
| `malformed`             | Does not decode: truncated, trailing bytes, a non-minimal length, a bad tag. |
| `unsupported`           | A protocol version, cipher suite or proposal type not implemented.          |
| `invalid-key-package`   | Wrong key lengths, a KEM key FIPS 203 rejects, or the init key reused as the encryption key. |
| `bad-signature`         | A key package, commit or GroupInfo signature that does not verify.          |
| `confirmation-mismatch` | A confirmation tag or member-list hash that does not match.                 |
| `decryption-failed`     | An HPKE or AEAD ciphertext that does not open, including for another group or epoch. |
| `wrong-epoch`           | A commit for an epoch other than the group's current one.                   |
| `wrong-group`           | A commit for another group.                                                  |
| `invalid-proposal`      | Removing an empty leaf or the committer, or adding an existing member.      |
| `unknown-sender`        | A commit or GroupInfo from a leaf that is empty or is this member's own.    |
| `not-addressed`         | A Welcome or commit that holds nothing for this member.                     |
| `cipher-suite-mismatch` | A key package or Welcome in a different suite from the group.               |
| `crypto-failure`        | The platform's crypto refused an operation (key generation, a bad private key). |
| `invalid-length`        | An exporter length past 255 times the suite's hash length, or negative.     |

Being removed by a commit is an outcome, not an error. Swift returns
`.removed`, Go returns `removed == true`, and Rust returns
`Processed::Removed`. Vectors write it as `"removed": true`. There is no
`removed` error class.

## Vectors

`vectors/mls` holds 13 files.

| File                         | Cases | From | What |
| ---------------------------- | ----- | ---- | ---- |
| `mlswg-crypto-basics.json`   | 2     | mlswg/mls-implementations | RefHash, ExpandWithLabel, DeriveSecret and DeriveTreeSecret for suites 1 and 7. Suite 1 also checks SignWithLabel and EncryptWithLabel. |
| `mlswg-key-schedule.json`    | 2     | mlswg/mls-implementations | Every epoch secret, the GroupContext and the exporter, for suites 1 and 7. |
| `mlswg-deserialization.json` | 14    | mlswg/mls-implementations | §2.1.2 variable-length headers, both directions. |
| `xwing-draft.json`           | 3     | draft-connolly-cfrg-xwing-kem | X-Wing's public key from its seed, and decapsulation to the shared secret. |
| `hpkewg-xwing.json`          | 1     | hpkewg/hpke-pq | HPKE KEM `0x647a`: `pkRm` from `skRm` and `shared_secret` from `enc` (its AEAD, ChaCha20-Poly1305, is no suite's). |
| `mls-crypto.json`            | 17    | Swift | Labelled primitives in `0xF0AA`, plus tampered signature and ciphertext cases. The 5 cases with `"cipher_suite": 61601` are EncryptWithLabel in `0xF0A1`: one that opens, then another context, a flipped byte in each KEM half, and a short KEM output. |
| `mls-crypto-go.json`         | 7     | Go    | ML-DSA-65 and HPKE `0x0041` from Go's standard library, plus tampered cases. 3 cases are HPKE `0x647a` in `0xF0A1`. |
| `mls-crypto-rust.json`       | 6     | Rust  | The same from aws-lc-rs, `src/hpke.rs` and `src/xwing.rs`. 2 cases are in `0xF0A1`. |
| `mls-key-schedule.json`      | 1     | Swift | Four epochs of `0xF0AA`: every secret, and the exporter (SFrame base key at 32 and 16 bytes, "MOQOM direct offer"). |
| `mls-key-packages.json`      | 14    | Swift | Valid packages in all three suites. Also a bad signature, a changed identity, relabelled and unknown suites, an unknown version, a trailing byte, truncation, and an init key that is reused, not ML-KEM, short, or an Ed25519-sized key where ML-DSA is required. |
| `mls-group.json`             | 4 (23 steps) | Swift | One member follows a group through a Welcome and add, remove and empty commits, with the epoch, leaf, members, epoch authenticator and exporters after each step. Also forged signature and confirmation tag, another group, a replay, truncation, a Welcome for another package, a tampered Welcome, and removal. |
| `mls-group-go.json`          | 1 (5 steps)  | Go    | A group Go founded and committed to, followed the same way. |
| `mls-audience.json`          | 6     | Swift | An envelope that opens, then the same envelope against another epoch, another group, tampered bytes, a trailing byte and truncation. |

Every case that follows a group carries the member's private keys, so any
implementation can replay the steps.

Regenerating:

- The Go files are fully deterministic: `testing/cryptotest.SetGlobalRandom`
  fixes all randomness, so regenerating them changes nothing.
- The Swift and Rust files are recorded transcripts, because CryptoKit and
  AWS-LC take no caller randomness. Their inputs come from fixed SHA-512 seeds,
  but signatures and ciphertexts change if regenerated.
- The published files are fetched by `published.py` at a pinned commit, and
  rerunning it is a no-op.

```
MOQOM_MLS_GENERATE=1 swift test --filter MLSVectorGenerator        # Swift files
cd go && MOQOM_MLS_GENERATE=1 go test ./mls -run TestGenerateVectors # Go files
cd rust && MOQOM_MLS_GENERATE=1 cargo test -p moqom-mls --test generate  # Rust file
python3 vectors/mls/published.py                                     # mlswg and X-Wing files
```

The published vectors that apply are crypto-basics, key-schedule and
deserialization. Suite 7's KDF fields check `0xF0AA`'s SHA-384. Suite 7's
signatures and HPKE use P-384, which is not implemented. `external_pub` is not
checked, since external commits are not implemented.

These published sets cannot apply:

- **tree-math, tree-validation, tree-operations, treekem:** there is no
  ratchet tree.
- **messages, welcome, transcript-hash:** they use RFC 9420's MLSMessage
  framing, and this library has its own.
- **secret-tree, message-protection:** there is no PrivateMessage.
- **psk_secret, passive-client-\*:** there are no PSKs, and those vectors need
  the full protocol.

No public MLS vectors exist for the post-quantum suites yet. The X-Wing KEM
under `0xF0A1` is checked against the draft's own vectors and the HPKE working
group's, in Rust from `xwing-draft.json` and `hpkewg-xwing.json`, and in Swift
from `Tests/MoqomMLSTests/HybridVectors.swift`. The draft's `eseed` cannot be
replayed, because neither CryptoKit nor AWS-LC takes caller randomness, so
X-Wing encapsulation is checked by the cross-language files instead.

## RFC 9420 subset

Implemented, bit-exact with the RFC and checked against the working group's
vectors:

- §2.1 encoding.
- §5.1 `ExpandWithLabel`, `DeriveSecret`, `SignWithLabel` and
  `EncryptWithLabel`.
- §5.2 `RefHash` and `KeyPackageRef`.
- §8 key schedule, §8.1 GroupContext, §8.5 exporter, and §8.7 epoch
  authenticator.

MOQOM's own simplifications, the same in all three languages:

- **No ratchet tree.** Members are a flat list. A commit seals its commit
  secret to every remaining member's leaf key, which is what TreeKEM reduces to
  when every parent node is blank. The GroupContext's `tree_hash` is a hash of
  the member list. A commit's cost grows linearly with the group, which is
  acceptable for a room's publishers (viewers use audience envelopes instead).
- **Own framing.** Commits travel as `CommitMessage` rather than MLSMessage or
  PublicMessage. The KeyPackage has no LeafNode, capabilities, lifetime or
  extensions. The Welcome and GroupInfo are simplified the same way.
- **Proposals.** Only Add and Remove, carried by value inside the commit. An
  empty commit is an Update. Proposals by reference, standalone proposals,
  ReInit, ExternalInit, PreSharedKey and GroupContextExtensions are not
  implemented.
- **Not implemented:** PrivateMessage, the secret tree, external commits
  (`external_secret` is derived but unused), PSKs (`psk_secret` is always
  zero), resumption, and credentials beyond a basic identity.

Ordering is the delivery service's job: it accepts the first commit for each
epoch and rejects the rest. A committer keeps `PendingCommit.next` until the
service accepts the commit.

## Unsafe code

`rust/moqom-mls/src/mlkem.rs` holds the crate's only `unsafe` code; X-Wing in
`src/xwing.rs` reaches AWS-LC only through it and safe aws-lc-rs. aws-lc-rs
(1.18.1, the latest release) builds an ML-KEM-768 decapsulation key only from
the expanded 2,400-byte key, and has no safe way in from the 64-byte seed that
every language here stores. So the seed is wrapped in a fixed 86-byte PKCS#8
PrivateKeyInfo, RFC 9935's `[0]` seed form, and passed to AWS-LC through
`aws-lc-sys`:

1. `EVP_parse_private_key` parses it from a `CBS` over the buffer. Any byte
   left unread is refused. AWS-LC checks that the seed is 64 bytes and runs
   FIPS 203's KeyGen on it.
2. `EVP_PKEY_get_raw_private_key` and `EVP_PKEY_get_raw_public_key` copy out
   the 2,400-byte decapsulation key and the 1,184-byte encapsulation key. A
   call that fails, or writes any other length, is refused.
3. The expanded key goes to aws-lc-rs's `kem::DecapsulationKey::new`, and the
   `EVP_PKEY` is freed.

Why this is sound:

- **Pointers and lengths.** The `CBS` borrows the buffer for the one call;
  AWS-LC reads at most its length and copies what it keeps. Each output call
  gets a buffer and its exact length, and AWS-LC writes at most that many
  bytes.
- **Null and errors.** A null key from the parser is an error, and every
  return value is checked before anything is used.
- **Freeing.** The `EVP_PKEY` is held by a guard that frees it on drop, so it
  is freed exactly once on every path, early returns included. Nothing else
  frees it.
- **Threads.** The key never leaves the function, so no other thread can see
  it. The AWS-LC functions used touch no shared mutable state (the error queue
  is thread-local), and `aws_lc_rs::init()` runs first.
- **Secrets.** The DER buffer, which holds the seed, and the expanded key are
  `Zeroizing` and wiped on drop. AWS-LC wipes its own copies when they are
  freed, because `OPENSSL_free` cleanses.
- **Linking.** `aws-lc-sys` must be the version aws-lc-rs links (0.45 for
  aws-lc-rs 1.18). If they drift apart, Cargo builds two separately prefixed
  copies of AWS-LC. That is still sound, since only bytes pass between them,
  but it doubles the build, so bump them together.

The unit tests in `mlkem.rs` cover seeds of the wrong length, the all-zero and
all-`0xff` seeds, distinct seeds giving distinct keys, and trailing or missing
DER bytes. The vectors check that each seed gives Swift's and Go's public key
and opens their ciphertexts.

Elsewhere in the crate, HPKE's shared secrets, extracted keys and AEAD keys are
`Zeroizing`. `EpochSecrets`, `KeyPackageBundle` and `Group` wipe their secrets
and private keys when dropped. Because of that, the fields of `EpochSecrets`
can be read or cloned but not moved out. Private keys returned by
`generate_key_pair` and `generate_signature_key_pair` are plain `Vec<u8>`, so
the caller has to wipe them.

## Tests

```
swift test --filter MoqomMLSTests
cd go && go test ./mls/...
cd rust && CARGO_TARGET_DIR=... cargo test -p moqom-mls
```
