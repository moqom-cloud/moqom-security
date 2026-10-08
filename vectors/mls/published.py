#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Elliott Wave LLC
#
# Copies the published vectors that apply to moqom-mls into this directory,
# each from a pinned commit so that running it again is a no-op: the MLS
# working group's, the X-Wing draft's, and the HPKE working group's for X-Wing.
#
# Only cipher suites 1 and 7 are kept. Suite 1 is RFC 9420's mandatory suite,
# which moqom-mls implements. Suite 7 is not implemented, but its hash, KDF and
# MAC (SHA-384) are MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65's, so its
# KDF-only fields hold that suite's key schedule to the RFC. Entries are copied
# as published, with a "name" added so every case can be told apart.

import json
import pathlib
import urllib.request

COMMIT = "2034fe72e0c805a683ba76165660c834f2a8142a"
BASE = f"https://raw.githubusercontent.com/mlswg/mls-implementations/{COMMIT}/test-vectors"
XWING_COMMIT = "984c2f7a93b8f8d8f8073ebb53f9f4ce50b5babd"
XWING = f"https://raw.githubusercontent.com/dconnolly/draft-connolly-cfrg-xwing-kem/{XWING_COMMIT}/spec/test-vectors.json"
HPKE_PQ_COMMIT = "6433c8fce0b8b749dfc86c1095081a88698ccfab"
HPKE_PQ = f"https://raw.githubusercontent.com/hpkewg/hpke-pq/{HPKE_PQ_COMMIT}/test-vectors.json"
HERE = pathlib.Path(__file__).parent


def fetch_url(url):
    with urllib.request.urlopen(url) as response:
        return json.load(response)


def fetch(name):
    return fetch_url(f"{BASE}/{name}.json")


def write(file, description, name, cases, source=None):
    document = {
        "library": "moqom-mls",
        "description": description,
        "source": source or f"{BASE}/{name}.json",
        "cases": cases,
    }
    (HERE / file).write_text(json.dumps(document, indent=2) + "\n")


def by_suite(entries):
    return [{"name": f"suite-{e['cipher_suite']}", **e} for e in entries if e["cipher_suite"] in (1, 7)]


write(
    "mlswg-crypto-basics.json",
    "RefHash, ExpandWithLabel, DeriveSecret, DeriveTreeSecret, SignWithLabel and EncryptWithLabel. "
    "Suite 1 applies in full; suite 7 only for its SHA-384 fields (ref_hash, expand_with_label, "
    "derive_secret, derive_tree_secret), since its P-384 KEM and signature are not implemented.",
    "crypto-basics",
    by_suite(fetch("crypto-basics")),
)
write(
    "mlswg-key-schedule.json",
    "Every epoch secret, the GroupContext encoding, the init-secret chain and the exporter over five epochs. "
    "external_pub is not checked: it is the suite's DHKEM DeriveKeyPair, which external commits use and "
    "moqom-mls does not implement.",
    "key-schedule",
    by_suite(fetch("key-schedule")),
)
write(
    "mlswg-deserialization.json",
    "RFC 9420 §2.1.2 variable-length vector headers, both directions.",
    "deserialization",
    [{"name": f"header-{e['vlbytes_header']}", **e} for e in fetch("deserialization")],
)
write(
    "xwing-draft.json",
    "X-Wing KEM (draft-connolly-cfrg-xwing-kem): the public key from the 32-byte seed (sk), and "
    "decapsulation of ct to ss. eseed, the encapsulation's randomness, cannot be replayed through "
    "CryptoKit or AWS-LC, so encapsulation is checked by the cross-language files instead.",
    None,
    [{"name": f"xwing-{i}", **e} for i, e in enumerate(fetch_url(XWING))],
    source=XWING,
)
write(
    "hpkewg-xwing.json",
    "HPKE KEM 0x647a (MLKEM768-X25519, X-Wing) from draft-ietf-hpke-pq, base mode, HKDF-SHA256, "
    "ChaCha20-Poly1305: the entry with kem_id 25722, kdf_id 1, aead_id 3. pkRm from skRm and "
    "shared_secret from enc are checked; ChaCha20-Poly1305 is not an MLS suite's AEAD.",
    None,
    [
        {"name": "kem-647a-kdf-1-aead-3", **e}
        for e in fetch_url(HPKE_PQ)
        if (e["kem_id"], e["kdf_id"], e["aead_id"], e["mode"]) == (0x647A, 1, 3, 0)
    ],
    source=HPKE_PQ,
)
