// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

// The shapes of vectors/sframe/*.json, shared by the generator and the tests
// that consume them.

import Foundation

@testable import MoqomSFrame

let vectorDirectory = URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent()
    .deletingLastPathComponent()
    .deletingLastPathComponent()
    .appending(path: "vectors/sframe")

struct VectorFile<Case: Codable & Sendable>: Codable, Sendable {
    var library = "moqom-sframe"
    var description: String
    var source: String
    var cases: [Case]
}

func loadVectors<Case: Codable & Sendable>(_ name: String, as _: Case.Type) throws -> VectorFile<Case> {
    let data = try Data(contentsOf: vectorDirectory.appending(path: name))
    return try JSONDecoder().decode(VectorFile<Case>.self, from: data)
}

func encodeVectors(_ file: some Encodable) throws -> Data {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
    return try encoder.encode(file) + Data("\n".utf8)
}

func hex(_ string: String) -> Data {
    var bytes = Data()
    var index = string.startIndex
    while index < string.endIndex {
        let next = string.index(index, offsetBy: 2)
        bytes.append(UInt8(string[index ..< next], radix: 16)!)
        index = next
    }
    return bytes
}

extension Data {
    var hexString: String { map { String(format: "%02x", $0) }.joined() }
}

struct TrackVector: Codable, Sendable {
    var namespace_hex: [String]
    var name_hex: String

    init(_ track: SFrameTrack) {
        namespace_hex = track.namespace.map(\.hexString)
        name_hex = track.name.hexString
    }

    var track: SFrameTrack {
        SFrameTrack(namespace: namespace_hex.map(hex), name: hex(name_hex))
    }
}

struct MetadataVector: Codable, Sendable {
    struct Property: Codable, Sendable {
        var type: UInt64
        var integer: UInt64?
        var bytes_hex: String?
    }

    var track: TrackVector
    var group: UInt64
    var object: UInt64
    var priority: UInt8
    var properties: [Property]

    init(_ metadata: SFrameMetadata) {
        track = TrackVector(metadata.track)
        group = metadata.group
        object = metadata.object
        priority = metadata.priority
        properties = metadata.properties.map {
            switch $0.value {
            case let .integer(value): Property(type: $0.type, integer: value)
            case let .bytes(value): Property(type: $0.type, bytes_hex: value.hexString)
            }
        }
    }

    var metadata: SFrameMetadata {
        SFrameMetadata(
            track: track.track,
            group: group,
            object: object,
            priority: priority,
            properties: properties.map {
                if let integer = $0.integer { .integer($0.type, integer) } else { .bytes($0.type, hex($0.bytes_hex ?? "")) }
            }
        )
    }
}

struct RFCCase: Codable, Sendable {
    var name: String
    var kind: String
    var skip: String?
    var kid: UInt64?
    var ctr: UInt64?
    var header_hex: String?
    var cipher_suite: UInt16?
    var base_key_hex: String?
    var sframe_key_label_hex: String?
    var sframe_salt_label_hex: String?
    var sframe_secret_hex: String?
    var sframe_key_hex: String?
    var sframe_salt_hex: String?
    var metadata_hex: String?
    var nonce_hex: String?
    var aad_hex: String?
    var pt_hex: String?
    var ct_hex: String?
}

struct MetadataCase: Codable, Sendable {
    var name: String
    var metadata: MetadataVector
    var encoded_hex: String?
    var error: String?
}

struct KeyIDCase: Codable, Sendable {
    var name: String
    var leaf: UInt32
    var epoch: UInt64
    var kid: UInt64
    var epoch_tag: UInt64
    var header_hex: String
}

struct NonceCase: Codable, Sendable {
    var name: String
    var cipher_suite: UInt16
    var kid: UInt64
    var ctr: UInt64
    var base_key_hex: String
    var sframe_key_hex: String
    var sframe_salt_hex: String
    var nonce_hex: String
    var header_hex: String
}

struct SealCase: Codable, Sendable {
    struct Seal: Codable, Sendable {
        var pt_hex: String
        var object_hex: String
    }

    var name: String
    var cipher_suite: UInt16
    var kid: UInt64
    var base_key_hex: String
    var metadata: MetadataVector
    var seals: [Seal]
}

struct OpenCase: Codable, Sendable {
    var name: String
    var cipher_suite: UInt16
    var kid: UInt64
    var base_key_hex: String
    var metadata: MetadataVector
    var object_hex: String
    var pt_hex: String?
    var error: String?
}

struct ReplayCase: Codable, Sendable {
    struct Step: Codable, Sendable {
        var object_hex: String
        var pt_hex: String?
        var error: String?
    }

    var name: String
    var cipher_suite: UInt16
    var kid: UInt64
    var base_key_hex: String
    var replay_window: UInt64
    var metadata: MetadataVector
    var steps: [Step]
}
