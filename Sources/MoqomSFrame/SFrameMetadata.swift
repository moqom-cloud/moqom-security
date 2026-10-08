// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

// What a MoQ object authenticates as: the same fields draft-ietf-moq-secure-objects
// authenticates — the full track name, the group and object IDs, the publisher
// priority and the object's properties — appended to the RFC 9605 header as AAD.
// They stay in the clear for the relay and are bound into the AEAD tag.
//
// Without that binding a relay could take an object from group 5 and re-label
// it as group 2, or move it from one participant's track onto another's, and
// the receiver would decrypt it happily. None of that requires breaking any
// cryptography — only that the position not be authenticated. So it is.
//
// Canonical because both ends must produce identical bytes from the same
// object or nothing decrypts. The encoding is the MOQT wire encoding of the same
// fields — the draft's Serialized Full Track Name, QUIC varints, and properties
// as a count followed by delta-coded key-value pairs, sorted by type — so the
// two cannot drift.

import Foundation

/// A MoQ Full Track Name: the namespace's fields and the track's name, as bytes.
public struct SFrameTrack: Hashable, Sendable {
    public var namespace: [Data]
    public var name: Data

    /// MOQT's limit on namespace fields. At least one is required.
    public static let maximumNamespaceFields = 32

    /// MOQT's limit on the namespace fields and the name together, in bytes.
    public static let maximumLength = 4096

    public init(namespace: [Data], name: Data) {
        self.namespace = namespace
        self.name = name
    }

    /// Each field and the name as their UTF-8 bytes, unnormalised.
    public init(namespace: [String], name: String) {
        self.init(namespace: namespace.map { Data($0.utf8) }, name: Data(name.utf8))
    }

    /// The Serialized Full Track Name, draft-ietf-moq-secure-objects §3.3.1:
    /// the number of namespace fields, each field with its length, then the
    /// name with its length, all lengths as varints.
    public func encoded() throws(SFrameError) -> Data {
        var out = Data()
        try encode(into: &out)
        return out
    }

    func encode(into out: inout Data) throws(SFrameError) {
        guard (1 ... Self.maximumNamespaceFields).contains(namespace.count),
              namespace.reduce(name.count, { $0 + $1.count }) <= Self.maximumLength
        else { throw SFrameError.invalidMetadata }
        try SFrameMetadata.varInt(UInt64(namespace.count), into: &out)
        for field in namespace {
            try SFrameMetadata.varInt(UInt64(field.count), into: &out)
            out.append(field)
        }
        try SFrameMetadata.varInt(UInt64(name.count), into: &out)
        out.append(name)
    }
}

/// The canonical description of one MoQ object, authenticated with its payload.
public struct SFrameMetadata: Hashable, Sendable {
    public var track: SFrameTrack
    public var group: UInt64
    public var object: UInt64
    public var priority: UInt8
    public var properties: [Property]

    /// One object property. Even types carry a varint and odd types carry
    /// bytes; the parity is the discriminator, so a mismatched pair has no
    /// encoding.
    public struct Property: Hashable, Sendable {
        public enum Value: Hashable, Sendable {
            case integer(UInt64)
            case bytes(Data)
        }

        public let type: UInt64
        public let value: Value

        public init(type: UInt64, value: Value) {
            self.type = type
            self.value = value
        }

        public static func integer(_ type: UInt64, _ value: UInt64) -> Property {
            Property(type: type, value: .integer(value))
        }

        public static func bytes(_ type: UInt64, _ value: Data) -> Property {
            Property(type: type, value: .bytes(value))
        }
    }

    public init(
        track: SFrameTrack,
        group: UInt64,
        object: UInt64,
        priority: UInt8,
        properties: [Property] = []
    ) {
        self.track = track
        self.group = group
        self.object = object
        self.priority = priority
        self.properties = properties
    }

    /// Largest value a QUIC varint carries.
    static let varIntMaximum: UInt64 = (1 << 62) - 1

    /// Longest byte-valued property MOQT allows.
    static let maximumPropertyLength = (1 << 16) - 1

    /// The bytes appended to the SFrame header as AAD.
    ///
    /// The Serialized Full Track Name, then the group, object, priority and
    /// properties. Properties are written sorted by type, keeping the given
    /// order among equal types, so the caller's order does not change what is
    /// bound.
    public func encoded() throws(SFrameError) -> Data {
        var out = Data()
        out.reserveCapacity(32)
        try track.encode(into: &out)
        try Self.varInt(group, into: &out)
        try Self.varInt(object, into: &out)
        out.append(priority)
        try Self.varInt(UInt64(properties.count), into: &out)

        let sorted = properties.enumerated()
            .sorted { lhs, rhs in
                lhs.element.type == rhs.element.type
                    ? lhs.offset < rhs.offset
                    : lhs.element.type < rhs.element.type
            }
            .map(\.element)

        var previous: UInt64 = 0
        for property in sorted {
            try Self.varInt(property.type - previous, into: &out)
            previous = property.type
            switch property.value {
            case let .integer(value):
                guard property.type.isMultiple(of: 2) else { throw SFrameError.invalidMetadata }
                try Self.varInt(value, into: &out)
            case let .bytes(value):
                guard !property.type.isMultiple(of: 2),
                      value.count <= Self.maximumPropertyLength
                else { throw SFrameError.invalidMetadata }
                try Self.varInt(UInt64(value.count), into: &out)
                out.append(value)
            }
        }
        return out
    }

    /// RFC 9000 §16, minimal length.
    static func varInt(_ value: UInt64, into out: inout Data) throws(SFrameError) {
        switch value {
        case 0 ... 63:
            out.append(UInt8(value))
        case 64 ... 16383:
            out.append(contentsOf: [UInt8(value >> 8) | 0x40, UInt8(truncatingIfNeeded: value)])
        case 16384 ... 1_073_741_823:
            let v = UInt32(value) | (0b10 << 30)
            for shift in stride(from: 24, through: 0, by: -8) {
                out.append(UInt8(truncatingIfNeeded: v >> UInt32(shift)))
            }
        case 1_073_741_824 ... varIntMaximum:
            let v = value | (0b11 << 62)
            for shift in stride(from: 56, through: 0, by: -8) {
                out.append(UInt8(truncatingIfNeeded: v >> UInt64(shift)))
            }
        default:
            throw SFrameError.invalidMetadata
        }
    }
}
