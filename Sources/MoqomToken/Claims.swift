// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

import Foundation

/// What the holder may do, the `moqt` claim.
///
/// Parsed strictly: a field this build does not know is refused, because a field
/// added later is as likely to narrow a grant as to widen one, and a verifier
/// that ignored a narrowing would enforce more than was issued.
public struct Grant: Hashable, Sendable {
    /// The room it admits the holder to; empty names none. The library carries
    /// it without interpreting it: what a token naming no room may do is the
    /// product's rule.
    public var room: String
    /// Media kinds the holder may publish (`pub`), a bitmask whose bit positions
    /// belong to the deployment's protocol.
    public var publish: UInt8
    /// Moderation capabilities (`cap`), a bitmask likewise.
    public var capabilities: UInt32
    /// The holder owns the room (`own`).
    public var owner: Bool
    /// The holder is backstage (`bs`).
    public var backstage: Bool
    /// The holder passed an age check (`age`).
    public var ageVerified: Bool
    /// The holder is another relay's link to this one (`rly`).
    public var relay: Bool

    public init(
        room: String = "",
        publish: UInt8 = 0,
        capabilities: UInt32 = 0,
        owner: Bool = false,
        backstage: Bool = false,
        ageVerified: Bool = false,
        relay: Bool = false
    ) {
        self.room = room
        self.publish = publish
        self.capabilities = capabilities
        self.owner = owner
        self.backstage = backstage
        self.ageVerified = ageVerified
        self.relay = relay
    }
}

/// What a token asserts.
///
/// Unknown top-level claims are ignored, so an issuer can add one without
/// upgrading every verifier first; the grant is the exception. A `null` member
/// is refused rather than read as absent.
public struct Claims: Hashable, Sendable {
    /// `iss`: the deployment that issued the token.
    public var issuer: String
    /// `sub`: the holder's username.
    public var subject: String
    /// `aud`: the customer the token is for.
    public var tenant: String
    /// `jti`: the token's identifier.
    public var id: String
    /// `iat`, Unix seconds; 0 when absent.
    public var issuedAt: Int64
    /// `exp`, Unix seconds.
    public var expires: Int64
    /// `cnf.jkt`: the RFC 7638 SHA-256 thumbprint of the device key.
    public var thumbprint: String
    /// `moqt`: what the holder may do.
    public var grant: Grant
    /// `via`: the username whose following brought the holder in. Provenance,
    /// not authorisation: it grants nothing.
    public var via: String
    /// `e2ee`: the room's end-to-end encryption policy, for the client.
    public var e2ee: String

    public init(
        issuer: String = "",
        subject: String,
        tenant: String,
        id: String = "",
        issuedAt: Int64,
        expires: Int64,
        thumbprint: String,
        grant: Grant = Grant(),
        via: String = "",
        e2ee: String = ""
    ) {
        self.issuer = issuer
        self.subject = subject
        self.tenant = tenant
        self.id = id
        self.issuedAt = issuedAt
        self.expires = expires
        self.thumbprint = thumbprint
        self.grant = grant
        self.via = via
        self.e2ee = e2ee
    }

    /// `iat` as a date.
    public var issuedAtDate: Date { Date(timeIntervalSince1970: TimeInterval(issuedAt)) }
    /// `exp` as a date.
    public var expiresDate: Date { Date(timeIntervalSince1970: TimeInterval(expires)) }

    /// Claims from their JSON, read as a verifier reads them.
    public init(json: Data) throws(TokenError) {
        guard json.first(where: { !" \t\r\n".utf8.contains($0) }) == UInt8(ascii: "{"),
              let claims = try? JSONDecoder().decode(Wire.self, from: json),
              UniqueMembers.check(json)
        else { throw .malformed("claims are not JSON") }
        self = claims.claims
    }

    /// The canonical JSON: the member order and escaping every implementation
    /// writes, which the sign vectors pin.
    public var json: Data {
        var members = [
            ("iss", JSON.string(issuer)), ("sub", JSON.string(subject)), ("aud", JSON.string(tenant)),
            ("jti", JSON.string(id)), ("iat", String(issuedAt)), ("exp", String(expires)),
            ("cnf", JSON.object([("jkt", JSON.string(thumbprint))])), ("moqt", grant.json),
        ]
        if !via.isEmpty { members.append(("via", JSON.string(via))) }
        if !e2ee.isEmpty { members.append(("e2ee", JSON.string(e2ee))) }
        return Data(JSON.object(members).utf8)
    }

    /// Whether `thumbprint` is an RFC 7638 SHA-256 thumbprint: 43 characters
    /// of canonical unpadded base64url, decoding to 32 bytes. A token bound to
    /// anything else is bound to no key at all, since no proof of possession
    /// can match it, so a signer refuses to mint one and a verifier to accept
    /// one (``TokenError/thumbprint``).
    public static func isValidThumbprint(_ thumbprint: String) -> Bool {
        thumbprint.utf8.count == 43 && Data(base64URL: thumbprint)?.count == 32
    }

    /// The signing input under key `kid`, checked as `Signer.sign(_:)` checks it.
    func signingInput(algorithm: Algorithm, keyID: String) throws(TokenError) -> String {
        if subject.isEmpty || tenant.isEmpty || thumbprint.isEmpty { throw .incomplete }
        if !Self.isValidThumbprint(thumbprint) { throw .thumbprint }
        let lifetime = expires.subtractingReportingOverflow(issuedAt)
        if issuedAt == 0 || lifetime.overflow || lifetime.partialValue <= 0
            || lifetime.partialValue > TokenLimits.maximumLifetime {
            throw .lifetime
        }
        let header = JSON.object([
            ("alg", JSON.string(algorithm.rawValue)), ("typ", JSON.string(TokenLimits.type)),
            ("kid", JSON.string(keyID)),
        ])
        return Data(header.utf8).base64URL + "." + json.base64URL
    }
}

extension Grant {
    var json: String {
        var members: [(String, String)] = []
        if !room.isEmpty { members.append(("room", JSON.string(room))) }
        members.append(("pub", String(publish)))
        members.append(("cap", String(capabilities)))
        if owner { members.append(("own", "true")) }
        if backstage { members.append(("bs", "true")) }
        if ageVerified { members.append(("age", "true")) }
        if relay { members.append(("rly", "true")) }
        return JSON.object(members)
    }
}

/// A member name as written, for reading objects whose names are checked.
struct Member: CodingKey {
    let stringValue: String
    init(_ name: String) { stringValue = name }
    init?(stringValue: String) { self.stringValue = stringValue }
    var intValue: Int? { nil }
    init?(intValue _: Int) { nil }
}

extension KeyedDecodingContainer<Member> {
    /// The member's value, the default when it is absent, and an error when it
    /// is null or of the wrong type.
    func value<T: Decodable>(_ name: String, or absent: T) throws -> T {
        let key = Member(name)
        guard contains(key) else { return absent }
        if try decodeNil(forKey: key) {
            throw DecodingError.valueNotFound(T.self, .init(codingPath: codingPath + [key], debugDescription: "null"))
        }
        return try decode(T.self, forKey: key)
    }

    /// Refuse any member not in `known`.
    func only(_ known: Set<String>) throws {
        for key in allKeys where !known.contains(key.stringValue) {
            throw DecodingError.dataCorruptedError(forKey: key, in: self, debugDescription: "unknown member")
        }
    }
}

private struct Wire: Decodable {
    let claims: Claims

    struct WireGrant: Decodable {
        let grant: Grant
        init(from decoder: any Decoder) throws {
            let c = try decoder.container(keyedBy: Member.self)
            try c.only(["room", "pub", "cap", "own", "bs", "age", "rly"])
            grant = try Grant(
                room: c.value("room", or: ""), publish: c.value("pub", or: 0), capabilities: c.value("cap", or: 0),
                owner: c.value("own", or: false), backstage: c.value("bs", or: false),
                ageVerified: c.value("age", or: false), relay: c.value("rly", or: false)
            )
        }
    }

    struct WireConfirmation: Decodable {
        let jkt: String
        init(from decoder: any Decoder) throws {
            jkt = try decoder.container(keyedBy: Member.self).value("jkt", or: "")
        }
    }

    init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: Member.self)
        claims = try Claims(
            issuer: c.value("iss", or: ""), subject: c.value("sub", or: ""), tenant: c.value("aud", or: ""),
            id: c.value("jti", or: ""), issuedAt: c.value("iat", or: 0), expires: c.value("exp", or: 0),
            thumbprint: c.value("cnf", or: WireConfirmation?.none)?.jkt ?? "",
            grant: c.value("moqt", or: WireGrant?.none)?.grant ?? Grant(),
            via: c.value("via", or: ""), e2ee: c.value("e2ee", or: "")
        )
    }
}

/// JSON as the Go implementation writes it: no insignificant whitespace, HTML
/// characters left alone, the short escapes for the five control characters
/// that have one, and U+2028 and U+2029 escaped.
enum JSON {
    static func object(_ members: [(String, String)]) -> String {
        "{" + members.map { string($0.0) + ":" + $0.1 }.joined(separator: ",") + "}"
    }

    static func string(_ text: String) -> String {
        var out = "\""
        for scalar in text.unicodeScalars {
            switch scalar {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\u{08}": out += "\\b"
            case "\u{0C}": out += "\\f"
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            case "\u{2028}", "\u{2029}": out += String(format: "\\u%04x", scalar.value)
            case _ where scalar.value < 0x20: out += String(format: "\\u%04x", scalar.value)
            default: out.unicodeScalars.append(scalar)
            }
        }
        return out + "\""
    }
}
