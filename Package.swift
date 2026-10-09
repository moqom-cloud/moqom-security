// swift-tools-version: 6.2
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

import PackageDescription

let strict: [SwiftSetting] = [
    .swiftLanguageMode(.v6),
    .enableUpcomingFeature("ExistentialAny"),
]

let package = Package(
    name: "MoqomSecurity",
    // CryptoKit's ML-DSA-65 and ML-KEM-768, including Secure Enclave ML-DSA,
    // arrive in the 26 release train.
    platforms: [.iOS(.v26), .macOS(.v26), .visionOS(.v26), .tvOS(.v26)],
    products: [
        .library(name: "MoqomToken", targets: ["MoqomToken"]),
        .library(name: "MoqomProof", targets: ["MoqomProof"]),
        .library(name: "MoqomSFrame", targets: ["MoqomSFrame"]),
        .library(name: "MoqomMLS", targets: ["MoqomMLS"]),
    ],
    targets: [
        .target(name: "MoqomToken", swiftSettings: strict),
        .target(name: "MoqomProof", swiftSettings: strict),
        .target(name: "MoqomSFrame", swiftSettings: strict),
        .target(name: "MoqomMLS", dependencies: ["MoqomSFrame"], swiftSettings: strict),
        .testTarget(name: "MoqomTokenTests", dependencies: ["MoqomToken", "MoqomProof"], swiftSettings: strict),
        .testTarget(name: "MoqomProofTests", dependencies: ["MoqomProof"], swiftSettings: strict),
        .testTarget(name: "MoqomSFrameTests", dependencies: ["MoqomSFrame"], swiftSettings: strict),
        .testTarget(name: "MoqomMLSTests", dependencies: ["MoqomMLS", "MoqomSFrame"], swiftSettings: strict),
    ]
)
