// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

import Foundation
import Testing

@testable import MoqomToken

@Suite("Strict JSON")
struct StrictJSONTests {
    @Test("unique members, at any depth, pass", arguments: [
        #"{}"#,
        #"{"a":1,"A":2,"b":[{"a":1},{"a":1}],"c":{"a":{"a":null}}}"#,
        #" { "s":"x\"y\\z\u00e9" , "t" : [ true, false, -1.5e3 ] } "#,
        // Canonically equivalent, but different code points: distinct to Go and Rust.
        "{\"\u{E9}\":1,\"e\u{301}\":2}",
    ])
    func unique(_ json: String) {
        #expect(StrictJSON.isValid(Data(json.utf8)))
    }

    @Test("a duplicate anywhere is refused", arguments: [
        #"{"a":1,"a":1}"#,
        #"{"sub":"ada","s\u0075b":"eve"}"#,
        #"{"x":[{"b":{"c":1,"c":2}}]}"#,
        "{\"\u{1F600}\":1,\"\\ud83d\\ude00\":2}",
        #"{"\ud800":1,"\udbff":2}"#,
        #"{"a":1"#,
    ])
    func duplicate(_ json: String) {
        #expect(!StrictJSON.isValid(Data(json.utf8)))
    }

    @Test("anything two parsers could read differently is refused", arguments: [
        #"{"a":"\ud800"}"#, #"{"a":"\udc00"}"#, #"{"a":"\ud800\u0041"}"#, #"{"a":"\u+fff"}"#,
        #"{"a":01}"#, #"{"a":-0.}"#, #"{"a":.5}"#, #"{"a":+1}"#, #"{"a":1e400}"#, #"{"a":0x10}"#,
        #"{"a":tru}"#, #"{"a":nan}"#, "{\"a\":\"\u{01}\"}", "\u{FEFF}{}", #"{} {}"#,
        String(repeating: "[", count: 128) + String(repeating: "]", count: 128),
    ])
    func refused(_ json: String) {
        #expect(!StrictJSON.isValid(Data(json.utf8)))
    }

    @Test("invalid UTF-8 is refused", arguments: [[0xFF], [0xED, 0xA0, 0x80], [0xC0, 0xAF]] as [[UInt8]])
    func notUTF8(_ bytes: [UInt8]) {
        #expect(!StrictJSON.isValid(Data([UInt8(ascii: "\"")] + bytes + [UInt8(ascii: "\"")])))
    }

    @Test("integers are integer literals")
    func integers() throws {
        let json = try #require(StrictJSON(Data(#"{"a":0,"b":-9223372036854775808,"c":1.0,"d":1e3,"e":-0,"f":9223372036854775808}"#.utf8)))
        #expect(try json.integer("a") == 0)
        #expect(try json.integer("b") == .min)
        for name in ["c", "d", "e", "f"] {
            #expect(throws: StrictJSON.Invalid.self) { try json.integer(name) }
        }
        #expect(try json.integer("z") == nil)
    }
}
