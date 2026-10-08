// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

import Foundation

@testable import MoqomMLS

/// The shared vectors in `vectors/mls`, which every language's tests read.
enum Vectors {
    static let directory = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .appendingPathComponent("../../vectors/mls")
        .standardizedFileURL

    /// The cases of one vector file.
    static func cases(_ file: String) throws -> [Vector] {
        let data = try Data(contentsOf: directory.appendingPathComponent(file))
        let document = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        return (document["cases"] as! [[String: Any]]).map(Vector.init)
    }

    static func write(_ file: String, description: String, source: String, cases: [[String: Any]]) throws {
        let document: [String: Any] = [
            "library": "moqom-mls",
            "description": description,
            "source": source,
            "cases": cases,
        ]
        var data = try JSONSerialization.data(
            withJSONObject: document, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        )
        data.append(0x0A)
        try data.write(to: directory.appendingPathComponent(file))
    }
}

/// One case: a JSON object, read by field.
struct Vector: @unchecked Sendable, CustomStringConvertible {
    let fields: [String: Any]

    init(_ fields: [String: Any]) { self.fields = fields }

    var name: String { string("name") }
    var description: String { name }

    func string(_ key: String) -> String { fields[key] as! String }
    func optionalString(_ key: String) -> String? { fields[key] as? String }
    func hex(_ key: String) -> Data { Data(hex: string(key)) }
    func int(_ key: String) -> Int { (fields[key] as! NSNumber).intValue }
    func uint64(_ key: String) -> UInt64 { (fields[key] as! NSNumber).uint64Value }
    func object(_ key: String) -> Vector { Vector(fields[key] as! [String: Any]) }
    func objects(_ key: String) -> [Vector] { (fields[key] as? [[String: Any]] ?? []).map(Vector.init) }
    func has(_ key: String) -> Bool { fields[key] != nil }
    /// The failure class a case expects, if it is one that must fail.
    var error: String? { fields["error"] as? String }
}

extension Data {
    init(hex string: String) {
        var data = Data(capacity: string.count / 2)
        var index = string.startIndex
        while index < string.endIndex {
            let next = string.index(index, offsetBy: 2)
            data.append(UInt8(string[index ..< next], radix: 16)!)
            index = next
        }
        self = data
    }

    var hex: String { map { String(format: "%02x", $0) }.joined() }
}
