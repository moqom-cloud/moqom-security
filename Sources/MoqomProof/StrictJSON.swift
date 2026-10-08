// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

import Foundation

/// One JSON object, read so that it means the same here as in Go and Rust.
///
/// Parsers disagree on a member named twice (Go keeps the last, others the
/// first), on whether a name matches regardless of case, on `null` for a member
/// that is a string, and on whether `1.7e9` is an integer. So this refuses
/// anything that is not RFC 8259 JSON, invalid UTF-8, an unpaired surrogate
/// escape, a number too large for a double, nesting deeper than
/// ``maximumDepth``, and any object, at any depth, that names a member twice.
/// Names are compared after unescaping and byte for byte, as Go and Rust
/// compare them, rather than by Swift's canonical-equivalence `==`. Members are
/// looked up by exact name, and each accessor refuses a value of another type,
/// `null` included.
struct StrictJSON {
    /// Arrays and objects nested inside one another, the outermost object
    /// included: `serde_json`'s limit.
    static let maximumDepth = 127

    struct Invalid: Error {}

    private let members: [[UInt8]: ArraySlice<UInt8>]

    /// Whether the object has a member named `name`, compared byte for byte.
    func has(_ name: String) -> Bool { members[Array(name.utf8)] != nil }

    /// The object `json`, or nil if it is anything else or not strict JSON.
    init?(_ json: Data) {
        let bytes = ArraySlice(json)
        guard Self.isUTF8(bytes) else { return nil }
        self.init(bytes: bytes)
    }

    private init?(bytes: ArraySlice<UInt8>) {
        var scanner = Scanner(bytes: bytes)
        scanner.space()
        guard scanner.peek == UInt8(ascii: "{"), scanner.value(depth: 1) else { return nil }
        scanner.space()
        guard scanner.at == bytes.endIndex else { return nil }
        members = scanner.top
    }

    /// The member `name` as a string, or `nil` if it is absent.
    func string(_ name: String) throws(Invalid) -> String? {
        guard let value = members[Array(name.utf8)] else { return nil }
        var scanner = Scanner(bytes: value)
        guard let text = scanner.string(), scanner.at == value.endIndex else { throw Invalid() }
        return String(decoding: text, as: UTF8.self)
    }

    /// The member `name` as an integer literal (no fraction, no exponent, not
    /// `-0`, which `serde_json` reads as a float) that fits in 64 bits, or
    /// `nil` if it is absent.
    func integer(_ name: String) throws(Invalid) -> Int64? {
        guard let value = members[Array(name.utf8)] else { return nil }
        let digits = value.first == UInt8(ascii: "-") ? value.dropFirst() : value[...]
        guard let first = digits.first, digits.allSatisfy({ (0x30 ... 0x39).contains($0) }),
              first != 0x30 || (digits.count == 1 && digits.count == value.count),
              let integer = Int64(String(decoding: value, as: UTF8.self))
        else { throw Invalid() }
        return integer
    }

    /// The member `name` as an object, or `nil` if it is absent.
    func object(_ name: String) throws(Invalid) -> StrictJSON? {
        guard let value = members[Array(name.utf8)] else { return nil }
        guard let object = StrictJSON(bytes: value) else { throw Invalid() }
        return object
    }

    /// Whether `bytes` are UTF-8, which refuses overlong forms and encoded
    /// surrogates.
    private static func isUTF8(_ bytes: ArraySlice<UInt8>) -> Bool {
        var decoder = UTF8()
        var iterator = bytes.makeIterator()
        while true {
            switch decoder.decode(&iterator) {
            case .scalarValue: continue
            case .emptyInput: return true
            case .error: return false
            }
        }
    }

    private struct Scanner {
        let bytes: ArraySlice<UInt8>
        var at: Int
        /// The outermost object's members, each value's bytes as they appear.
        var top: [[UInt8]: ArraySlice<UInt8>] = [:]

        init(bytes: ArraySlice<UInt8>) {
            self.bytes = bytes
            at = bytes.startIndex
        }

        var peek: UInt8? { at < bytes.endIndex ? bytes[at] : nil }

        /// A value whose arrays and objects open at nesting `depth`.
        mutating func value(depth: Int) -> Bool {
            space()
            guard let byte = peek else { return false }
            switch byte {
            case UInt8(ascii: "{"):
                guard depth <= StrictJSON.maximumDepth else { return false }
                at += 1
                var names = Set<[UInt8]>()
                space()
                if eat(UInt8(ascii: "}")) { return true }
                repeat {
                    space()
                    guard let name = string(), names.insert(name).inserted else { return false }
                    space()
                    guard eat(UInt8(ascii: ":")) else { return false }
                    space()
                    let start = at
                    guard value(depth: depth + 1) else { return false }
                    if depth == 1 { top[name] = bytes[start ..< at] }
                    space()
                } while eat(UInt8(ascii: ","))
                return eat(UInt8(ascii: "}"))
            case UInt8(ascii: "["):
                guard depth <= StrictJSON.maximumDepth else { return false }
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
            case UInt8(ascii: "t"): return literal("true")
            case UInt8(ascii: "f"): return literal("false")
            case UInt8(ascii: "n"): return literal("null")
            default:
                return number()
            }
        }

        mutating func literal(_ word: String) -> Bool {
            guard bytes[at...].starts(with: word.utf8) else { return false }
            at += word.utf8.count
            return true
        }

        /// RFC 8259's number grammar, and a value a double can hold.
        mutating func number() -> Bool {
            let start = at
            _ = eat(UInt8(ascii: "-"))
            if !eat(UInt8(ascii: "0")) {
                guard let first = peek, (0x31 ... 0x39).contains(first) else { return false }
                digits()
            }
            if eat(UInt8(ascii: ".")) {
                guard digits() else { return false }
            }
            if eat(UInt8(ascii: "e")) || eat(UInt8(ascii: "E")) {
                if !eat(UInt8(ascii: "+")) { _ = eat(UInt8(ascii: "-")) }
                guard digits() else { return false }
            }
            return Double(String(decoding: bytes[start ..< at], as: UTF8.self))?.isFinite ?? false
        }

        @discardableResult
        mutating func digits() -> Bool {
            let start = at
            while let byte = peek, (0x30 ... 0x39).contains(byte) { at += 1 }
            return at > start
        }

        mutating func space() {
            while let byte = peek, " \t\r\n".utf8.contains(byte) { at += 1 }
        }

        mutating func eat(_ byte: UInt8) -> Bool {
            guard peek == byte else { return false }
            at += 1
            return true
        }

        /// A string's UTF-8 after unescaping, or `nil` for anything else,
        /// including an unpaired surrogate escape or a raw control character.
        mutating func string() -> [UInt8]? {
            guard eat(UInt8(ascii: "\"")) else { return nil }
            var out: [UInt8] = []
            while let byte = peek {
                at += 1
                switch byte {
                case UInt8(ascii: "\""):
                    return out
                case UInt8(ascii: "\\"):
                    guard let escape = peek else { return nil }
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
                        var scalar: Unicode.Scalar?
                        switch unit {
                        case 0xD800 ..< 0xDC00:
                            guard eat(UInt8(ascii: "\\")), eat(UInt8(ascii: "u")),
                                  let low = hex4(), (0xDC00 ..< 0xE000).contains(low)
                            else { return nil }
                            scalar = Unicode.Scalar(0x10000 + ((UInt32(unit) - 0xD800) << 10) + (UInt32(low) - 0xDC00))
                        case 0xDC00 ..< 0xE000:
                            return nil
                        default:
                            scalar = Unicode.Scalar(unit)
                        }
                        guard let scalar else { return nil }
                        out.append(contentsOf: Array(String(Character(scalar)).utf8))
                    default:
                        return nil
                    }
                case 0x00 ..< 0x20:
                    return nil
                default:
                    out.append(byte)
                }
            }
            return nil
        }

        mutating func hex4() -> UInt16? {
            guard at + 4 <= bytes.endIndex,
                  bytes[at ..< at + 4].allSatisfy({ ($0 >= 0x30 && $0 <= 0x39) || (($0 | 0x20) >= 0x61 && ($0 | 0x20) <= 0x66) }),
                  let unit = UInt16(String(decoding: bytes[at ..< at + 4], as: UTF8.self), radix: 16)
            else { return nil }
            at += 4
            return unit
        }
    }
}
