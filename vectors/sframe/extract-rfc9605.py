#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Elliott Wave LLC

"""Copy RFC 9605 Appendix C into rfc9605.json, value for value.

    curl -sSf https://www.rfc-editor.org/rfc/rfc9605.txt | ./extract-rfc9605.py > rfc9605.json
"""

import json
import re
import sys

SOURCE = "https://www.rfc-editor.org/rfc/rfc9605.txt, Appendix C"

# Only AES-256-GCM is implemented in any language; see docs/moqom-sframe.md.
IMPLEMENTED = {0x0005}
SKIP = "AES-CTR + HMAC suites are not implemented: every target platform has hardware AES-GCM"
SKIP_AES128 = "AES-128-GCM is refused: MOQOM uses AES-256-GCM only"


def sections(text):
    # The table of contents names every heading first.
    start = text.rindex("Appendix C.  Test Vectors")
    end = text.index("Acknowledgements", start)
    body = text[start:end]
    # Page breaks: the footer line, the form feed, and the running header.
    body = re.sub(r"\n[^\n]*\[Page \d+\]\n\f\n[^\n]*\n", "\n", body)
    c1 = body.index("C.1.  Header Encoding/Decoding")
    c2 = body.index("C.2.  AEAD Encryption/Decryption Using AES-CTR and HMAC")
    c3 = body.index("C.3.  SFrame Encryption/Decryption")
    return body[c1:c2], body[c2:c3], body[c3:]


def records(section, first):
    """Each record is a run of `name: value` lines starting at `first`, with
    continuation lines (more hex) appended to the previous value."""
    out = []
    current = None
    last = None
    for line in section.splitlines():
        match = re.match(r"^   ([a-z_]+): (\S+)$", line)
        if match:
            name, value = match.groups()
            if name == first:
                current = {}
                out.append(current)
            if current is not None:
                current[name] = value
                last = name
            continue
        more = re.match(r"^ {6,}([0-9a-f]+)$", line)
        if more and current is not None and last is not None:
            current[last] += more.group(1)
            continue
        last = None
    return out


def number(value):
    return int(value, 16)


def main():
    c1, c2, c3 = sections(sys.stdin.read())
    cases = []

    for record in records(c1, "kid"):
        kid, ctr = number(record["kid"]), number(record["ctr"])
        cases.append({
            "name": f"header-kid-{kid:x}-ctr-{ctr:x}",
            "kind": "header",
            "kid": kid,
            "ctr": ctr,
            "header_hex": record["header"],
        })

    for record in records(c2, "cipher_suite"):
        suite = number(record["cipher_suite"])
        cases.append({
            "name": f"aead-{suite:04x}",
            "kind": "aes_ctr_hmac",
            "cipher_suite": suite,
            "key_hex": record["key"],
            "enc_key_hex": record["enc_key"],
            "auth_key_hex": record["auth_key"],
            "nonce_hex": record["nonce"],
            "aad_hex": record["aad"],
            "pt_hex": record["pt"],
            "ct_hex": record["ct"],
            "skip": SKIP,
        })

    for record in records(c3, "cipher_suite"):
        suite = number(record["cipher_suite"])
        case = {
            "name": f"sframe-{suite:04x}",
            "kind": "sframe",
            "cipher_suite": suite,
            "kid": number(record["kid"]),
            "ctr": number(record["ctr"]),
        }
        for field in (
            "base_key", "sframe_key_label", "sframe_salt_label", "sframe_secret",
            "sframe_key", "sframe_salt", "metadata", "nonce", "aad", "pt", "ct",
        ):
            case[field + "_hex"] = record[field]
        if suite == 0x0004:
            case["skip"] = SKIP_AES128
        elif suite not in IMPLEMENTED:
            case["skip"] = SKIP
        cases.append(case)

    document = {
        "library": "moqom-sframe",
        "description": "RFC 9605 Appendix C: header encoding (C.1), AES-CTR + HMAC AEAD (C.2) and "
                       "SFrame encryption (C.3), copied as published. Cases with `skip` name a suite "
                       "no language implements.",
        "source": SOURCE,
        "cases": cases,
    }
    json.dump(document, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
