// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

// Package sframe is moqom-sframe: SFrame (RFC 9605) for MoQ objects.
//
// An object is sealed under a key derived from a base key and a KID, with a
// counter the sender owns, and with the object's metadata — group, object,
// priority and properties, the fields a relay reads to schedule — bound into
// the AEAD tag in the shape of draft-ietf-moq-secure-objects. A relay can read
// and forward them and cannot change any of them.
//
// Only AES-256-GCM (0x0005) is implemented. AES-128-GCM (0x0004) is refused so
// no peer or object can name a 128-bit key. Every platform MOQOM targets has
// hardware AES-GCM, and the AES-CTR + HMAC suites would be a composition of our
// own.
//
// Context is the simple API: Seal and Open under one key. Sender and Receiver
// are the pieces a room uses, a sender per media stream and a receiver holding
// every other member's key.
//
// The same library exists in Rust (crate moqom-sframe) and Swift (MoqomSFrame),
// and all three pass the vectors in vectors/sframe. See docs/moqom-sframe.md.
package sframe
