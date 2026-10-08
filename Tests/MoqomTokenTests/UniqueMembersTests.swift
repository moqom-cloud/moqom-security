// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

import Foundation
import Testing

@testable import MoqomToken

@Suite("Duplicate member names")
struct UniqueMembersTests {
    @Test("unique members, at any depth, pass", arguments: [
        #"{}"#,
        #"{"a":1,"A":2,"b":[{"a":1},{"a":1}],"c":{"a":{"a":null}}}"#,
        #" { "s":"x\"y\\z\u00e9" , "t" : [ true, false, -1.5e3 ] } "#,
        // Canonically equivalent, but different code points: distinct to Go and Rust.
        "{\"\u{E9}\":1,\"e\u{301}\":2}",
    ])
    func unique(_ json: String) {
        #expect(UniqueMembers.check(Data(json.utf8)))
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
        #expect(!UniqueMembers.check(Data(json.utf8)))
    }
}
