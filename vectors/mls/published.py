#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Elliott Wave LLC
#
# Copies the MLS working group's published vectors that apply to moqom-mls into
# this directory, from a pinned commit so that running it again is a no-op.
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
HERE = pathlib.Path(__file__).parent


def fetch(name):
    with urllib.request.urlopen(f"{BASE}/{name}.json") as response:
        return json.load(response)


def write(file, description, name, cases):
    document = {
        "library": "moqom-mls",
        "description": description,
        "source": f"{BASE}/{name}.json",
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
