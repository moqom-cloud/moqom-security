// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

import Foundation
import Synchronization

/// Remembers which proof nonces have been spent.
///
/// A store shared by every checker of one certificate is what makes a proof
/// single-use across connections.
public protocol NonceStore: Sendable {
    /// Record `nonce` as spent until `until`. Called only for a proof that
    /// passed every other check.
    ///
    /// - Throws: ``ProofError/replayed`` if it already is,
    ///   ``ProofError/overloaded`` if the store cannot remember another.
    func spend(_ nonce: String, until: Date, now: Date) throws(ProofError)
}

/// An in-process ``NonceStore``.
///
/// It forgets everything on restart, so a proof captured and never delivered
/// could be replayed after one, within its window and its token's lifetime.
/// When full it refuses rather than evicts: evicting would choose which proof
/// becomes replayable.
public final class MemoryNonceStore: NonceStore {
    /// One per session in a token lifetime, far past what one endpoint serves.
    public static let defaultCapacity = 100_000

    private let capacity: Int
    private let spent = Mutex<[String: Date]>([:])

    public init(capacity: Int = defaultCapacity) {
        self.capacity = capacity
    }

    /// Expired entries are swept when the store is full, the only moment they
    /// can matter.
    public func spend(_ nonce: String, until: Date, now: Date) throws(ProofError) {
        let outcome: ProofError? = spent.withLock { spent in
            if spent.count >= capacity {
                spent = spent.filter { $0.value > now }
            }
            if spent.count >= capacity { return .overloaded }
            if spent[nonce] != nil { return .replayed }
            spent[nonce] = until
            return nil
        }
        if let outcome { throw outcome }
    }

    /// How many nonces are held, for tests and metrics.
    public var remembered: Int { spent.withLock { $0.count } }
}
