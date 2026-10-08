// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

import Foundation

/// Whether no object in a JSON document, at any depth, names a member twice.
///
/// Parsers disagree on a duplicate (Go keeps the last, others the first), so a
/// token with one would mean different things to different verifiers. Names
/// are compared after unescaping, so `sub` and `s\u0075b` are the same, and
/// byte for byte, as Go and Rust compare them, rather than by Swift's
/// canonical-equivalence `==`. Anything the scanner cannot follow is refused.
enum UniqueMembers {
    static let maximumDepth = 128

    static func check(_ json: Data) -> Bool {
        var scanner = Scanner(bytes: [UInt8](json))
        return scanner.value(depth: 0)
    }

    private struct Scanner {
        let bytes: [UInt8]
        var at = 0

        mutating func value(depth: Int) -> Bool {
            space()
            guard at < bytes.count, depth <= UniqueMembers.maximumDepth else { return false }
            switch bytes[at] {
            case UInt8(ascii: "{"):
                at += 1
                var names = Set<[UInt8]>()
                space()
                if eat(UInt8(ascii: "}")) { return true }
                repeat {
                    space()
                    guard let name = string(), names.insert(name).inserted else { return false }
                    space()
                    guard eat(UInt8(ascii: ":")), value(depth: depth + 1) else { return false }
                    space()
                } while eat(UInt8(ascii: ","))
                return eat(UInt8(ascii: "}"))
            case UInt8(ascii: "["):
                at += 1
                space()
                if eat(UInt8(ascii: "]")) { return true }
                repeat {
                    guard value(depth: depth + 1) else { return false }
                    space()
                } while eat(UInt8(ascii: ","))
                return eat(UInt8(ascii: "]"))
            case UInt8(ascii: "\""):
                return string() != nil
            default:
                let start = at
                while at < bytes.count, !",:]}[{\" \t\r\n".utf8.contains(bytes[at]) { at += 1 }
                return at > start
            }
        }

        mutating func space() {
            while at < bytes.count, " \t\r\n".utf8.contains(bytes[at]) { at += 1 }
        }

        mutating func eat(_ byte: UInt8) -> Bool {
            guard at < bytes.count, bytes[at] == byte else { return false }
            at += 1
            return true
        }

        /// A string's UTF-8 after unescaping. A lone surrogate becomes U+FFFD,
        /// as Go decodes it.
        mutating func string() -> [UInt8]? {
            guard eat(UInt8(ascii: "\"")) else { return nil }
            var out: [UInt8] = []
            while at < bytes.count {
                let byte = bytes[at]
                at += 1
                switch byte {
                case UInt8(ascii: "\""):
                    return out
                case UInt8(ascii: "\\"):
                    guard at < bytes.count else { return nil }
                    let escape = bytes[at]
                    at += 1
                    switch escape {
                    case UInt8(ascii: "\""), UInt8(ascii: "\\"), UInt8(ascii: "/"): out.append(escape)
                    case UInt8(ascii: "b"): out.append(0x08)
                    case UInt8(ascii: "f"): out.append(0x0C)
                    case UInt8(ascii: "n"): out.append(0x0A)
                    case UInt8(ascii: "r"): out.append(0x0D)
                    case UInt8(ascii: "t"): out.append(0x09)
                    case UInt8(ascii: "u"):
                        guard let unit = hex4() else { return nil }
                        var scalar = Unicode.Scalar(unit)
                        if (0xD800 ..< 0xDC00).contains(unit), bytes[at...].starts(with: Array(#"\u"#.utf8)) {
                            let mark = at
                            at += 2
                            if let low = hex4(), (0xDC00 ..< 0xE000).contains(low) {
                                scalar = Unicode.Scalar(0x10000 + ((UInt32(unit) - 0xD800) << 10) + (UInt32(low) - 0xDC00))
                            } else {
                                at = mark
                            }
                        }
                        out.append(contentsOf: Array(String(Character(scalar ?? "\u{FFFD}")).utf8))
                    default:
                        return nil
                    }
                default:
                    out.append(byte)
                }
            }
            return nil
        }

        mutating func hex4() -> UInt16? {
            guard at + 4 <= bytes.count,
                  let unit = UInt16(String(decoding: bytes[at ..< at + 4], as: UTF8.self), radix: 16)
            else { return nil }
            at += 4
            return unit
        }
    }
}
