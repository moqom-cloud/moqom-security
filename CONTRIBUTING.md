# Contributing

Thanks for wanting to help. These libraries are Apache-2.0 and maintained by
Elliott Wave LLC. Issues and pull requests are welcome; security issues go to
[SECURITY.md](SECURITY.md), not to an issue.

## Before you open a pull request

1. **Sign the CLA.** The first pull request you open asks you to sign the
   [Copyright Assignment Agreement](.github/CLA.md) by leaving a comment.
   Elliott Wave LLC owns all of MOQOM's intellectual property, open source
   included, so your contribution's copyright is assigned to it; you get a
   permanent licence back to use your own work for anything.
2. **Change all three languages, or none.** A behaviour change lands in Swift,
   Go and Rust together, with the vectors that pin it.
3. **Vectors before code.** A fix for a bug starts with the vector that fails.
4. **No primitives.** Compose CryptoKit, the Go standard library or AWS-LC;
   never implement an algorithm here.

## Building and testing

```sh
swift test                                  # Swift, at the repository root
(cd go && go test ./...)                    # Go
(cd rust && cargo test --workspace)         # Rust
```

Swift needs Xcode 26 or a Swift 6.2 toolchain with the 26 SDKs.
