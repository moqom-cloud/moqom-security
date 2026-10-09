#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Elliott Wave LLC
#
# Copies the published vectors that apply to moqom-mls into this directory,
# from a pinned commit so that running it again is a no-op: the MLS working
# group's.
#
# Only cipher suite 5 is kept. It is not implemented, but its hash, KDF and MAC
# (SHA-512) are MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87's, so its KDF-only
# fields hold that suite's key schedule to the RFC. Suite 1 is an AES-128 suite
# and is not implemented. Entries are copied as published, with a "name" added
# so every case can be told apart.

import json
import pathlib
import urllib.request

COMMIT = "2034fe72e0c805a683ba76165660c834f2a8142a"
BASE = f"https://raw.githubusercontent.com/mlswg/mls-implementations/{COMMIT}/test-vectors"
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
    return [{"name": f"suite-{e['cipher_suite']}", **e} for e in entries if e["cipher_suite"] == 5]


write(
    "mlswg-crypto-basics.json",
    "RefHash, ExpandWithLabel, DeriveSecret and DeriveTreeSecret in suite 5, for its SHA-512 fields "
    "only, since its P-521 KEM and signature are not implemented.",
    "crypto-basics",
    by_suite(fetch("crypto-basics")),
)
write(
    "mlswg-key-schedule.json",
    "Every epoch secret, the init-secret chain and the exporter over five epochs, in suite 5. "
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
