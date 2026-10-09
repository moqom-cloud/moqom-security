// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

import CryptoKit
import Foundation
import Testing

@testable import MoqomMLS
import MoqomSFrame

/// MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87, the suite every group uses:
/// HPKE over pure ML-KEM-1024 with HKDF-SHA512 and ML-DSA-87 signatures, held
/// to Go's `crypto/hpke` and `crypto/mldsa` (the control plane's), and the
/// group lifecycle in it end to end. Its key schedule is held to the RFC by
/// `PublishedVectorTests`.
@Suite("MLS post-quantum cipher suite (ML-KEM-1024, ML-DSA-87)")
struct MLSPostQuantumSuiteTests {
    private let suite = MLSCipherSuite.mls256MLKEM1024MLDSA87
    private let room = Data("acme/room-42".utf8)

    @Test("identifiers: the ML-DSA suite is the default, and post-quantum in both halves")
    func identifiers() {
        #expect(MLSCipherSuite.default == suite)
        #expect(MLSCipherSuite.supported.first == suite)
        #expect(MLSCipherSuite(identifier: 0xF0AC) == suite)
        // Private use (RFC 9420 §17.1).
        #expect((0xF000 ... 0xFFFF).contains(suite.identifier))
        #expect(suite.name == "MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87")
        #expect(suite.hasPostQuantumKEM && suite.hasPostQuantumSignatures)
        #expect(MLSCipherSuite.supported == [suite])
        // The AES-128 suites are not implemented, so nothing can name one.
        #expect(MLSCipherSuite(identifier: 0x0001) == nil)
        #expect(MLSCipherSuite(identifier: 0xF0A1) == nil)
        // Nor are MOQOM's earlier ML-KEM-768 and ML-DSA-65 suites.
        #expect(MLSCipherSuite(identifier: 0xF0AA) == nil)
        #expect(MLSCipherSuite(identifier: 0xF0AB) == nil)
        #expect(suite.hashLength == 64 && suite.aeadKeyLength == 32)
        #expect(suite.publicKeyLength == 1568 && suite.encapsulationLength == 1568)
        #expect(suite.signatureKeyLength == 2592)
    }

    @Test("HPKE (0x0042, 0x0003, 0x0002): opens what Go's crypto/hpke sealed")
    func hpkeAgainstGo() throws {
        let seed = hex("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f")
        let key = try MLKEM1024.PrivateKey(seedRepresentation: seed, publicKey: nil)
        #expect(key.publicKey.rawRepresentation == hex(Self.goKEMPublicKey))
        #expect(key.seedRepresentation == seed)
        let opened = try MLKEMHPKE.open(
            HPKECiphertext(kemOutput: hex(Self.goEnc), ciphertext: hex("2d32a13ca04aaafaa8dbbec82bc0e53c73eea9377e122554b8b586a35ae624c0e5460b3575")),
            seed: seed,
            info: hex("4d4f514f4d2063726f73732d636865636b20696e666f")
        )
        #expect(opened == hex("6a6f696e6572207365637265742066726f6d20476f"))
        #expect(throws: (any Error).self) {
            _ = try MLKEMHPKE.open(
                HPKECiphertext(kemOutput: hex(Self.goEnc), ciphertext: hex("2d32a13ca04aaafaa8dbbec82bc0e53c73eea9377e122554b8b586a35ae624c0e5460b3575")),
                seed: seed,
                info: Data("other info".utf8)
            )
        }
    }

    @Test("ML-DSA-87: the same key from the same seed as Go, and Go's signature verifies")
    func mlDSAAgainstGo() throws {
        let key = try MLDSA87.PrivateKey(seedRepresentation: hex("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"), publicKey: nil)
        #expect(key.publicKey.rawRepresentation == hex(Self.goSignatureKey))
        let message = hex("4d4f514f4d2063726f73732d636865636b206d657373616765")
        #expect(key.publicKey.isValidSignature(hex(Self.goSignature), for: message))
        #expect(!key.publicKey.isValidSignature(hex(Self.goSignature), for: message + Data([0])))
    }

    @Test("SignWithLabel and EncryptWithLabel round-trip, bound to their labels")
    func labelled() throws {
        let signing = try suite.generateSignatureKeyPair()
        #expect(signing.privateKey.count == 32 && signing.publicKey.count == 2592)
        let signature = try suite.signWithLabel(signing.privateKey, label: "GroupInfoTBS", content: room)
        #expect(signature.count == 4627)
        #expect(suite.verifyWithLabel(signing.publicKey, label: "GroupInfoTBS", content: room, signature: signature))
        #expect(!suite.verifyWithLabel(signing.publicKey, label: "Other", content: room, signature: signature))
        // An Ed25519 key is the wrong size for this suite and is refused outright.
        let ed25519 = Curve25519.Signing.PrivateKey().publicKey.rawRepresentation
        #expect(!suite.verifyWithLabel(ed25519, label: "GroupInfoTBS", content: room, signature: signature))

        let pair = try suite.generateKeyPair()
        let secret = suite.randomSecret()
        #expect(secret.count == 64)
        let sealed = try suite.encryptWithLabel(pair.publicKey, label: "Welcome", context: room, plaintext: secret)
        #expect(sealed.kemOutput.count == 1568)
        #expect(try suite.decryptWithLabel(pair.privateKey, label: "Welcome", context: room, ciphertext: sealed) == secret)
        #expect(throws: MLSError.decryptionFailed) {
            _ = try suite.decryptWithLabel(pair.privateKey, label: "UpdatePathNode", context: room, ciphertext: sealed)
        }
        let other = try suite.generateKeyPair()
        #expect(throws: MLSError.decryptionFailed) {
            _ = try suite.decryptWithLabel(other.privateKey, label: "Welcome", context: room, ciphertext: sealed)
        }
    }

    @Test("a key package is ML-DSA signed, with ML-KEM keys, and is refused relabelled")
    func keyPackage() throws {
        let package = try MLSKeyPackageBundle.generate(identity: "bob/b").keyPackage
        #expect(package.cipherSuite == suite)
        #expect(package.signatureKey.count == 2592)
        #expect(package.initKey.count == 1568 && package.encryptionKey.count == 1568)
        #expect(package.signature.count == 4627)
        #expect(package.isValid)
        let encoded = package.encoded
        #expect(encoded[2 ..< 4] == Data([0xF0, 0xAC]))
        #expect(try MLSKeyPackage.decode(encoded) == package)

        // Relabelled to either earlier ML-KEM suite or either AES-128 suite, it
        // does not decode at all.
        var relabelled = encoded
        relabelled[3] = 0xAB
        #expect(throws: MLSError.unsupported) { _ = try MLSKeyPackage.decode(relabelled) }
        relabelled[3] = 0xAA
        #expect(throws: MLSError.unsupported) { _ = try MLSKeyPackage.decode(relabelled) }
        relabelled[3] = 0xA1
        #expect(throws: MLSError.unsupported) { _ = try MLSKeyPackage.decode(relabelled) }
        relabelled[2] = 0x00
        relabelled[3] = 0x01
        #expect(throws: MLSError.unsupported) { _ = try MLSKeyPackage.decode(relabelled) }
    }

    @Test("found, add, rotate, remove and rejoin: every member agrees on every epoch")
    func lifecycle() throws {
        let alice = try MLSGroup.create(groupID: room, bundle: .generate(identity: "alice/a"))
        #expect(alice.cipherSuite == suite)
        let bob = try MLSKeyPackageBundle.generate(identity: "bob/b")
        let carol = try MLSKeyPackageBundle.generate(identity: "carol/c")
        let add = try alice.commit(adding: [bob.keyPackage, carol.keyPackage])
        let welcome = try #require(add.welcome)
        let bobGroup = try MLSGroup.join(welcome, bundle: bob)
        let carolGroup = try MLSGroup.join(welcome, bundle: carol)
        #expect(bobGroup.epochAuthenticator == add.next.epochAuthenticator)
        #expect(carolGroup.epochAuthenticator == add.next.epochAuthenticator)
        #expect(bobGroup.cipherSuite == suite)

        // Bob rotates; Alice and Carol follow.
        let rotate = try bobGroup.commit()
        guard case .advanced(let aliceNext) = try add.next.process(rotate.message),
              case .advanced(let carolNext) = try carolGroup.process(rotate.message)
        else { Issue.record("rotation not followed"); return }
        #expect(aliceNext.epochAuthenticator == rotate.next.epochAuthenticator)
        #expect(carolNext.epochAuthenticator == rotate.next.epochAuthenticator)

        // SFrame keys from the epoch agree too.
        #expect(aliceNext.sframeKeys(suite: .aes256GcmSha512).map(\.keyID)
            == carolNext.sframeKeys(suite: .aes256GcmSha512).map(\.keyID))
        #expect(try aliceNext.exporter(label: "x", length: 32) == carolNext.exporter(label: "x", length: 32))

        // Alice removes Carol; Carol is told, Bob follows.
        let carolLeaf = try #require(aliceNext.leaf(of: "carol/c"))
        let remove = try aliceNext.commit(removing: [carolLeaf])
        guard case .removed = try carolNext.process(remove.message) else {
            Issue.record("Carol was not told she was removed"); return
        }
        guard case .advanced(let bobAfter) = try rotate.next.process(remove.message) else {
            Issue.record("removal not followed"); return
        }
        #expect(bobAfter.epochAuthenticator == remove.next.epochAuthenticator)
        #expect(bobAfter.memberCount == 2)

        // A commit with its ML-DSA signature broken is refused.
        let forged = try remove.next.commit()
        var signature = forged.message.signature
        signature[signature.startIndex] ^= 1
        let tampered = MLSCommitMessage(
            groupID: forged.message.groupID, epoch: forged.message.epoch, sender: forged.message.sender,
            commit: forged.message.commit, signature: signature, confirmationTag: forged.message.confirmationTag
        )
        #expect(throws: MLSError.badSignature) { _ = try bobAfter.process(tampered) }
    }

    @Test("sizes on the wire: what one member costs a commit and a Welcome")
    func wireSizes() throws {
        var group = try MLSGroup.create(groupID: room, bundle: .generate(identity: "alice/a"))
        var commits: [Int] = []
        var welcomes: [Int] = []
        var packages: [Int] = []
        for index in 0 ..< 4 {
            let joiner = try MLSKeyPackageBundle.generate(identity: "member/\(index)")
            packages.append(joiner.keyPackage.encoded.count)
            let add = try group.commit(adding: [joiner.keyPackage])
            commits.append(add.message.encoded.count)
            welcomes.append(try #require(add.welcome).encoded.count)
            group = add.next
        }
        let commitPerMember = Set(zip(commits.dropFirst(), commits).map { $0 - $1 })
        let welcomePerMember = Set(zip(welcomes.dropFirst(), welcomes).map { $0 - $1 })
        // Two ML-KEM keys, an ML-DSA key and an ML-DSA signature.
        #expect(packages.allSatisfy { (10_360 ... 10_400).contains($0) })
        // One HPKE ciphertext (1,568 + 80 bytes) and its framing per member.
        #expect(commitPerMember.allSatisfy { (1_650 ... 1_665).contains($0) })
        // One leaf (identity, 2,592-byte ML-DSA key, 1,568-byte leaf key) per member.
        #expect(welcomePerMember.allSatisfy { (4_165 ... 4_190).contains($0) })
        print("pq-suite sizes: key package \(packages), commit +\(commitPerMember), welcome +\(welcomePerMember)")
        // The control plane's maxCommitBytes is 3.5 MiB: a room of 800 fits
        // in a Welcome and in a rotation commit.
        let limit = 7 << 19
        #expect(800 * (commitPerMember.max() ?? 0) < limit)
        #expect(800 * (welcomePerMember.max() ?? 0) < limit)
    }

    private static let goKEMPublicKey = "e31930e6653b077953d80c947f99bc1c14458995303f552118392f1c195e4b5878093a72f3a42700a1aa62e769dd29081bd9cf9f446876939f4b83bb16c2cc0a44a97bb51713ba0a20b267cdb00b8e692b48c825165a972827584d21beca983cc02444f03120e434c6c58c1fff1c1afe02085dfb6a19cb1c1ff14ec87703f650380ab18ad362a408ec91e2e11001930370b98010a349e63764a2c36e823c1b65f47e991464bc7ba4b0d96494b59294518f855441c7e423a924cd9605b9e0e5cf8c2356da6a0d9ef1b366b3a1797982e23bc9f86831d8f9011b51ac75d5af682713a0682211a6752d3c08583c509e8086346c4e3d7c7b30f910f76c26f73c7164f0cbe909b881ec1d6a3c1e10b173fff4890ddc378a2764336c6110cabc9f129764a143be677c81fa4d92b5cd8ffc1fd428c731856d4418061480b46ed5985dca1cb8580065e8331142805a24c25a066987522c1df0bc19155fb031c5d45521872b37ec891d66a57bec550da4473d0f219eaa53284deb7a4fc4c6926870d17c3607bb4f86357207130a94c5ce74f51cef74c8513bcf2454c89d26a9c227928ee0ca857a5dea9093948685e0d29028b9a234ac8282d28205d81a48f517d64510f2902bdc8050e3f7114a838ef1eabce792830a2ab6a873a5d05805bb5378e925abbfd112e29016d85633a4cc101b443ef7193e35027213802c1a5327327131ddf6c3b3b01c81a4000ce86c679c92c7962549c07c0b0105674ab29a224184818598093a41dc3534d0ae4217059efc5e2c76b437e214ce4662d87a75e143337775491b60c302bb3c2a07357539749cc7b5f839731906c44930268b5b22b51b68ea650911191f3fb53d9722a86ecba94d54ce05d798ff91ae800a4944326a5765a19ec6a83e26ce0d259e2a40bf64e5bf9a88130e3a5546e23b9ecc1b63d50c16fa59fa308b9cd2831ba31f7d8883be892fbe026a57122492f32fedd7cc486396f022be7eb53ce319c419fcb01b1b5ab4a3822a9ccfff7147b9b4bda97299686593b617cadc076f3901b05194b205c9051d2581aa2b2fae15c4c89b95fbb67cedca1a2a5501f4f09087955cd54b216c9c08e70200f6499fd06a221468a24fe623bec34bcef40ecf946bfa564e0489abab040e2c898f65733e9fe617f5832258752052dc96286617670b9b67c591c9c10b0e85cb03e5af72bb33dc044391accd6ec79afda76ef1d724204c9608ea3209a7cec4ac6ece9c32d2c7667e04986335bb960b999f8078b9a5655536c557544a114b3a59619adcc6631665412b058a99e8540bda243a748b25c360df73ae9b854720353eb63240fb5b2336b737426200a571712725c943d9638978629d8b1a0ffa0463b56c249061f08947893a1b8daa0c90f8af0157b3d90262e7a6837e3072e849c85738a0b56c4e5c4505bd91749b6106d3c50ff914c3fea04dc0f60033b67583dc5a75f0a4b396c0bbe98c26c4cc9885883c680915f8010b1c80635410f250b63c183a33549419804d27005ddbd499e485c2f271908d93be21fa2abebb70172c22a1e03971b62a65fb2d7fa209e6348c05f487b7e24592b98824c0678cd00fc9e3581e377245c9a3b09c5066ca838004ce4f2c8bcc3795ea710a9f680170f915ccc3c808b6ab1b930d22e5ab15997714317977dc2c9fa5421c84cb22f74f8d919bcf54906f814b989149df8b263cb4a88d72512d8249c875afb20bc838c91e33f311894a54f926bae998a257b0c03c28627590a0a53b2a004575b416c44ae9a98cb8314773b975548c86a244c6f44e356b9864031be11c325eeab1ead3cba3068b007d205910bc7997534cb27dabb1b3e65b37fb9648b2c95e1cb7582c267c036168012b0b339966c1d11f7fe193c529832d7a4ec2c863246a3ad8839e7e6a69b98a747da928c4ac5ebfc28c00208a9d8a2457350adc22925a252b7b1863b683620b1944a5e819369bb57516867ad78628bb73d6ca217f92548de415ef8b0aab2992aea8b62ef1321878832e035b4a3a7700bc3b06435af32536ebb6077feb5d457cb36722999a40b37a055ca066c8eab575a913aa11c80c9490c41fbcc4ea1aa29f932c51d70dbfdac3a4f6bdadbb9ad8fa00bbb038e1349d6a11769df24e70025b902019a9730532276827c263f153cfbde192e33bcbb4e899516d8692005a304443e017e57c0d897dfdaf4f053bfb9a"
    private static let goEnc = "126d9d287da840dcf225cccc3d76ea28b8d8b8376d0deec248abf23905d20712fe3a704ad1afc1005e85a01f957918d9e2ed7d39ba5681db25ba2ebc09b29c68ad97685a913948aab95af911b922db356217d8402af085c20a74b2cb98be9cf20477f416ccf4f060626d154c7ade6ded60df9a9802a02e547ea868522c08711751190367d086ceebdd6edb5829d6cec1b6a9bd090ba2186e17bbfc5072e8479a0e8d14eb5e10fc81c372f93a908fb20385936169343003b8c4c1e6c582c4ce973ce1c356ce7291c52464e0fa2b58d47fb5dbb66bb09e5082db5a41fb425e9420001c46dda1e715bffe216c1ee4cdc57c871c207661af8491c51b9bf30d70130420a243ed25c7648d9d9be8de713c39373b2ca986fe99bf69d8cf33cf6f02753155e41d9d045fabef2f52a16aca4c8e22401668d93780512cfb74b571b5b148e5b018e196a8aa8269e156722acc0864d6c2657b58e474580469e521915c00ea3a0990828b5ef6d0b55f2427eeaa266a1a34042fc04c786807e37ceeef226862c7d519ee684335954f4f720bc2b0761f950665696a0f82d2bfb6e64da480e5454d50383cd9246deab94b4c3bb6d224b99c142e11fbd16bd4c70c71f4baec461e9e87e9140e658f1e38cac141dca23f9c919d3541b7f7b88ed3735f53d2cca61f89de313ed87258e02692fbfcf78732bc20ad54ecfa91838e397aeec79145a3874a58c49d0229f245288c8d8b386c51f8e870533a82eea7c3216697ebe5faad5d1882b3879d5c52b7f6176fad1938acedbc7979f0833c1ba58acff713bc6973681e5a58a633d6224f6cf4e891fe7018d6c77e6c0af365e2f2915428a1cf4fb1dbec265ba4cb1413e62158d9a4bc2b30da43dc14be63a404f3781a9e6367ecaa0389b7af9b272e49492092c5f428f3a27078291a910735b13ff4b905555859086199d7d05267074da41d5338a77dbe846094e1fd4b5126fa6a4e0cb4c216ded474e289dfa12b8bd09ea3c69b59532b4a784fd0c62e11d309cff5a987030c9f0896cea8ae8878ae2b01cddc92eb8296e679cf6f66442926bbfae3d21e6580f17f1df4b4eddef1e2dcb6da57ee507c7c8192d01031982c568065ba0b9ea3777b9713844a20f1abc7e6b24047a12528fcca51b1c0ffd117d2a98dce9fe9c44900aa63af7093cfe1e75b57cc120c57d9ae5bf17db5252b93326ca589db87efdfb616112e1bbd7cccc3f4cd289cf17a7ffc9025c5f0add0da6df8403aa51a708d19e0b861c8700221ac0da60559b459ec446f879b14b0b31aa01488eea30940937b8a8840b4b3b6c17d5d5d8a22fdebed522339746974da57d23c05b850630d92c889928b5a4466cdb94b80e61807425ff776b7650c3c00365c76da9cbf17ecea1138fc7e159d8f59382f63c6ebd58fb9fc3ff0af9b76486529493c7cd10b4399e92c399539b2fa8032b591e88988a11d54b6a65a4d379af89beb76c609a159b792d0124e772652f8156370e11184e271ae43cc196ef86f2949c0f3ba1f9646696cd27f3dc6ac5444aec7ad011499d70022845e0b22b6e216e4da03f53140a92ebd9832ee656a28551293475c48fd139dce1f434c9c3fcf1fdc29cec1bb5e6ff037b2cb911dc4f427e48201cb6f96022aa8f264f0d262626b3da1cdfc00bce00057f35e5cdf8af265ecb57300fa57884609a09dca59e04b1efd36176ff1ef4c3156e1ef976c4815586bb34329762728416b65db90f8b9484e5d1d8d47ec8b09c7100e9590ccd1595fe2aa3188c01c7145eff11e40fbfaf1826888003601acf35d2771339abd7958ed19705ac278aee85ec5876d34507d6315c94e89cc2495afefb07c76eacb6f7b3500683520065cec50f63566e325175d036ff2ac9a9ab9617349dc1b31f09202675a4f7395559094295506196b3ef321bad227eeff8192c65334b392552396b17773fc1dc184e54b3f5e1f17c544958aa2ec505bb387158fa8e1fb776c0cd55caec162380a5b876fdc76d550177e46a12e5dbd7a23d03151a837c166826b99ec88db7f6e26d177eb84137e72a907694bddeb9c0372eca48566884c64a42c99dd82c9bbdab740c83ed2070d790a2e9347e43a34792b382b6b861751a41016fc990a2da42e8243538f701cd6eb42eec93a13608eb5c8e460bb04f3bcfe10ac84a4ee88fdadac30411d7d0c43ea32c875b99e25d6705fe0fa5cbbe89612fc"
    private static let goSignatureKey = "cfa845578dd53533dbaafeb7e8e5dd9140eb9335f1bea972f636929db7882a63d8265c018935cf68df99d4f7f1ce2d3d33d842d74344a572e6d54eda0e9aa5a898438e15ef300f81349b46d92354923fbbc0c4c20249f9b2ba2d06f70a8e61ed3c77f28c26b716718776a3eb233c12314bb6b94b8a0f9c40db28ff8cb573ce4d492acf9815954d06557d2015bb175533e25a385fc707b8c6ce1c83eeede12991e4affd93aac2ef12589a27e3bb3e00184e1555902459ed2d1462f939ee4a672fe0c0f5645b69cdff19edd9b1a82605cc93615b396a965398db41650c0fafcddebfd75b2cad6443caa1dc7356cc7643d0c10999c7cd0f92bf609d26f25eb810fa38968ec4a73959a544d67e5f67a9d762a13ea1c3f813d7b4f09210e1af7f1215b8f297d7eb5f8c6647ee2740abd4226265a39f60fe3aabaa949fa0f154be5d7f6bea4c50a913547f1e2049ead839759378a71df9d70608360174ea987727b39abaf59ad4cbbaf82bccaa91a72442ebfac4e50b66c8e3c4da0db2cabc6221445a2ec4bd11f2f29c62b6e23be5a7bd32da22a7db0b7491c1021d80e39deb0d091bb3adc5c4076b03941216a632f730558f1e0e724436121b08a5bda4cb34f7a90ed81d32d87776fd6e27105f9552f85243fa49701a6b0b2fe3959456b55b4856810d79d49e0c6447dcd6d4c3fd329fed9542492399397a3bed81c1dade8ee3c89e539445433215debe98a9338957d410d5177c529e5505a92eb349c5736cd28f59e7c96c032087418f84f456798057eacbc1bb314c0b76b321d86ba915175cac5d8329c2b88fddd08fbe5f0ee6a086b864bbb89e7160f0cf4685f5fc232c9ab5dcf82d1136d4f5ebf5978bcf2deebdbc9c2c6da855ced6bfad8184c19c1ba55e0ae590453fa9a838d62a9db5e4152eaaed446c208783e3eaf6837ad973544f51f0244fdf18ee5731fa42d6f963d2f3bae82da39f02768bd92f13f201e10d6363c632b06ddd4449d2287a6e6e804baec3b79cd6dc0a79e303c3e1f9faa147845f12b5d7f01530a59a2f80a596269f3655e542242da65aa831fcf49c1336ce3dc766e30ff96e7671f811dc992fd9db69565182aa353a25c14782272e63cde2ed8963261b992b3fc39c1a17ebbf4de063e07b0839fd59f99deb7cbc02e25dcc18a431ccbabef48538f8d9d962816549b749377d871df7cff29b5e200d8a553df6a66908a01ef87d4be7818084af45abfa051c407795a805d75e8b05d2fb6f5751d7e7ba4f8999ce23c611560d2288105f558ca68496d7e0bf6ca9e5016e14c488da07d9a3a73c01a96298a17382751daf8f17fd8dd495087c9ec427bb973193ba5474aa3af4b00e8b5052d475eb017aa25d2ac1c5baf8800a27c14d2aa4e857d197df40570383b639168eb098191e1f7cde404d27098796faf7779e6951edf89992d05b252fd567e31e17dd12a70e6c8cb7771743f68f0863e73b4d2aab4b1ee7bc62e37ca36b1f7e57743062ed056458b7a6682f5f56c9560037eca2519961679be143d9b2ea52e91c547646583695d5a26663e0dab7022f75760063ef7554d1fd7c7a34746ebaa927d6d2e39f0e689c6001e3fc0adad662abcfcb7d97adc3728862432cfbcc3b2f6a5b8681734f21148af2a1dc96b32e50bdd07a2f1c4f2ccd8ae33187c8d4ea38f85439c4beac23897621d0b0a34cb4875c596f35abfc83fb565e5af7e25378cf63d857d888287971f4012c6374ec739e650451bad6f9b509eeaef0e69fa925e88d6e78de4da7b2baba2b24393ffbfb2683a5293e2c9ce842d56c1d900bfca4c6b268df866e9f31cb99a339eb0adceaab43dfc35463d026a38ee5dae5cc073a81cdf28521af0f7f3e86469a3c8b0a5a074c2c885e2e577f13f70b8c455436f1e8226772925c7d14997e04b696003d52315540f86e4ac8f62fdc04330b9dc94a85606cb8e7a27da52782bc5c11f206aa93228851f2834dc43fdc483aef8ed8bb8be7699ee122cc02424241791092afe341a616141385258cc9d9570c473f1a0e179b78cce3d73c9f39daf9d2a86fb9f8c81b7338d42b98c097d1b774b6d8adcaf0d4662d9e30ed6383c6c5a09e8d686af29d2a3663c8e54c452e8a74dadfc9387a00ee49deade86a5213ec8cb20f859881c4c67214b02dad0a1d6d725ceceb4a458cd1486e07c875774a70162479ca07faa670d05def84b1309374bd484085f6b7e6ef952773f637d7f7752afab3e3856f12944132d44572ad0aa396303a06de662af338ac78c8aef8f080b0843c681ac7d0233641c5a6ef8244b419a1c31489a36f4c0dcccb05bd8f0fbff2200e177ae9f1d3699373431315b41c4c4158ec6087fb8b3750581af4f898b01e7dbb60438af4033aef52b496cbfdc20b318dfe98ab87f3f0191750a0d69df766206d718e94bcb136fecc61d6807f1e7561cdae2c19affcadcd2b84b1adbb560261fdc673aee6984293c31a996dfc8b806d282e0fe62234aad497d0ba2a1ef0de7c04e81895fc717e1bd81aa61f419c069dbff20d0acd31d83b83564efbd914f92e62878cf6d0b21ca1118271efcbda2def9e0fc40c67b19afcf77a0c9cc657dbb89ba09754c0036cc2d85717c1d04652482f2148030b80594702335e868c9b7c262228e77a12ee43a17edfac26faaa296c8311b60b03557234ce2c8df2cc05b41f8c369d8308182f49fee5ccebd6351e0ac2a04c5bf9bd1d3d51486c60dd9c6624cb0aeaf9cdeb8b56952fead00f48e1e5ae52ad002b19f443b4bde242da7dfe3541d5ff801fd4857c57c1bea41c1dcd5d8d1c6c6680819d2a773d3c2a42ab39d6f7c8c52544b50679836aa0e9ff3c195b4c13bafff9153211a24dc9c8fbab06401f314cdbd741ab679e93c02403838387c04ac55ef017b359e6b6f1993f57ea9cb51807a2b288c51c964c6d0533d3ae69249c6ff1359182bcd9b70d624c51bd4b193abd0d7ff4518fcf68b84fdc9e728ec13e72335e6ee782759ae69cdfd31d9db18dcd30270dcd2d93aa70f96d81317e712a96944d31121d988281232e05c1ce42d9875ecf59e214983a31cf5ecdf113a958b4c56618b623e3e85ce0b2aaba3c2a4e1a98dbb592b1aba97433fed6d0cc5a6b95ea1044fafd2de10cd4ea488801b981c9642f849256deb8610de1bafe09ffe4e9914e06b0919bfd0b16bdcef513383146d489a4eb353865ad011c3701f726f748ac55bb4bb8ef3483640a8361076944f0bce0c453c8e13b6c99a386750324ca7181f6e1f1e3a745223e446a83a41bb6a9de8f72dddcbd7257cb0a7f32f42925a7639665a7cb5963825f189a678615c08b43ed07b8ef1c7d16ad5eefd510972808c07c487ec28a96ffcd16d494592bf17c8beb6e1ad7bfb0a29cba5f5f987a760987a3611b589a5ca0b2e9faa8f14a2162ce9aafcbf539d43beb59f00967e670bd33c7fccf59ebac9e670bfc791ad73a31a3cde5cb8afd94a203d5245cf5273d26de81cd74e85ec5acebb6f2b0573df0193f1ece509a7c9035c99224f1c4211b984d75f17d56de862e1d712ad9e673041248a3f828f49c1deacf3e471148315415711626142d68e87b846a82b4660be79b85caa25a34546894122f289d44654156dda3dd632e2b6d2781ea8273f8c4f9f6a7e509ae33dad096a0f604"
    private static let goSignature = "48b974a8ba0d14482c27b3a90e984c4e85997764f59268536a4ed19194918fdac4382e95f33e924e67417e16c69756caf2cbf5a0a36a0f6b014fb6d5a4738261c6614e94fe0a782d038a114b7947d47807f34f14dfe132bdb09744123fcf7da202d87a2a770bc8fdb85cc35f4f6d9e1cf68b7375ba326554d831971303e04081f50a53883287e6099658177c1d47dd3072a0801fbd110955bfc3cddcfead2bf4975aa87095477c82ee8416cc4be05ae975643838beb71c6cdf2d2afb6a9acdd11da2f1dee2b719fbc8fa80d735319d73eff9947c969bbb02a81211c76b26593820693bd33ad747db7c7cc3582e40f981f5f7f8eb25fd513527b42a1fef24515347a81d061699b2eaf7e1c3e4fd1b1fa1326932a2e86da36e79e837ea30e97c6313c9cbcf3885db1d79f1268e57d67714229ec0d2ca5852e790911473922db428dc50a1e3d1a4aa8f5658b0b603ddf1d4d3991375ec49e8a57277f84037b29bb9301393fc7583b7603e53c4f8de88852a1bbb35a8e13b85f672c360a6af1be1d6e6c8e3e90b82bcb11368e2adfee32f237c673c982ff7676f08bf4628169a2b40136936e9171e136cb6b681b4c8d33156e5a475894750c136192123ed57a10e07b543665854674921f54efe68efc5ef52519b64a2e01e5ef3a8f2282217c175b5dd0fa59dfedb27faaa1a28c467e6f785a9a7942de9cb68cc267f15afa33340ad79a2902df5f23b90b3ecdebe0cf43f9b638d41cb09bb0e4eef6250cfdbef77607f29cf4dfae1129b1dde4776d96455d476fa22aa13e395dfc5447246a16ff91cb5e18f6051ea39d84e6fb73befce1ffd704ee96342e1a47a6a499a8ca5332fd11061ede90449d467c8b6602b059e137ce7dd44eccdabaa61512739dab4bda5ab5bb484952f2ca29b247c9ce8b6389c35e2fa27c011f4e08b457fafc6e37a484ee9c02b1d3110d206fce6548fef45f89fde911e2e99083e556c2cb3455887922a874179553abf9eb3a0e9ce37bf68efba379a0eb1da91fb78b09d5922424e9de438169fb0a1e83a36c51bc71cf28a7a8685d237f2e42038506502e7102d2d143f56f8f1b350c7baa0b1c04d9ef4417a6b790cf8a7c3dd4dcc6b81c5898a8a8c83592bb99f9e24c21856a7253f27577e302f6d74020bd464df718102c13d37c1e77f74cef9807667d6ae7c4c31c4823ba25a3079b709727acf157e8b9d89cac369eaad88c5240e2e85ac019f6976cfd4dbf5ca8459ef4bc07dd9ab2ed1268c74f38d30dcfbb92cd814fb9148e95a81d4a71113f1ece3d9e9c883a26a8fd06bc4e4bddd72c8cc6143b55a3811b066f0ec41e6e15a411b9ea0e3b93d26941e6fa394e30e01aff0f5855c145e101e4ef9bb78b163f3a9e7c94327c0cb3142920eae14176191a069d70cc66151c06575088a186eeaeb6ac51c366c4d8ff98299d4d8235462b0d9372830d635b7017e4ba5339061af1f1beec6c1b445ff12f1ef9776901ec8e703e59c02fcaa85104f1373236255210ae9dc9b976a1bc6de2924fa48a66e34e45d5b68f7811375a49a45c4088d57e968a9c524421016a9aacaa83cb3641bbfa3a0493063130de405a2e93b1744fb8cc6e433236e1307e4c69e668c0c3f03cef44c482f1c4e81d02770ddb5e148d218dc2e7d166b31af848af687a250d10a1bc4b2aea9c95cc96a07748e0003bd0c8d30c667e46cc1002b6b360a7f7cddccdbeb0901505d37193a3a334848158f4042ab474cbc23d8f1bc5bf2aef45967374b5a6dbef273f76a8b7f4a92f4b6d768af672bd9e747f4a0fff7b1db8b651fb5bcf3796410f46a909129a5e1c6bae8661396c1d1abe5ea0f592c6ba56e1131c0d5e0b41335b550121bce2804df0a2d8c77c86978213ebd4485a7285f14edfedd1638156906ccbb0047526bcfbbdda3ebdaea5fa8a7b0e2934bfbe8ed177a6098791e0e3a3759772a562c85bd30277d1a9a96b373bc793a55c6e3a27ff9caa030a54e7a0363372400d45596be8b7e61b56a1cf353787407749749cbb7dec37812cf7a5f7ce41f7038fadc96d096ae39feeeeb91118de6ee1155620133d7ea742c233f1bd1e84ae6d85aaf0c7339ba45546191412512cf3de5d20a9967ff66ba52d157bc39547551ef142c74c19e8c3ce7bbd8ca62da42b3bbeb62aabd6a419cb768796f26cd242c5bd3ec6ff1951fed9da0337bfe2b5d8a566e2f47d7e036606f0a49d92d08191022ac08384f9da2f5804ca84339f0f505c87d5a6cb2ef172704a37b9cc3138080af0ac3d7ba8f81e1e70fcab84ed69820da26ab6f61291c287c8f50f607c0b08e51a6c6309397406891800afa5a9b01da98144afea3e078125bbb9056c8f2e9c42026d1275474cba751d29013eed1f7e92609a41935a0c2bbbbd1f18d6a6a7d8222b899cff0889aeb0ce670da00115d87d5f46edc9e1ffd7610486f8e94adbf18e568685677e20fb94011f849c35dc9988eb4646206ae59dba28e002f0cb8ed96a4438c88efd199565873ea2bc0eba0e30ccbb8e67def2fd6b30c586b641270329fde739e15d09aaf317f4dd1434e4f9e7edc2aa9e755c64eb86970b95718925094d5719d3497b3f8184d4de121ff4c1a701f158b8f52de71215346ac9b470bf923d99b02d2992241da69366d4893cae62889c021fccaf5cc0eb083a25bf665e3a92aa66bb55957b32ffb9c9945ad706954f5efded3df6290b71e35a184cc174dc0c8bd159219e69e3a568efbd311bba4d5fc57aa0a2f9c18d63dfdab6bccac1ddb8541dc55796c43d1f8f6830f0a4132523e386f534b9e572d1e90f87309b2a7b43d9c07c89595c2407231758348f02055a1e6101e57053ee6050868f64e6c9a3a2350209c6535c3fae17702f20da9a321827e811e1a26cdf1c6dd099b48cad5c4f9f96e0d706e952dbc92a1ce45d79708832a69cfb78e0547a6a12ad482dbb08c3c9dfb94b509ecfbd0b585de67bdb38a35ca5877435b9eea9347180d51e38a061091fbcc44104a9a0f2617cfae9c3db973e8a6d44b73569cb3385bff0531a42900724aa3afccd6c3afe71e7b2b7ee6bd979a46146f6638b192488522ad20c5f992fe0b359b3baae930a632b430f1039196c30ff51a209e8e7a612705c5a447ddfb8f9d0073d55292b5cc5d458cd9dbb35ddbdd154373edbf85d4f8a2716d8f1d9e60011d6704fac00d3d076ed48476c378234d62a5aa57436c6dda7e7792009fac4a9b3bbd44b0f5b32e8cf03aaa76f858bf3e0682779ca0ccbb116a675703c26bc79b3c328b4ac601911848cf246b103dfae16655dc2c6b203255ee162f0bb07294f3fa17c383831a7be5215874d5a5f2e8baed67d6a71e6f4711e6e6e4e29886aedf971f6a710185a1391312aa37a35ade2fe42126fb142940afdc1fa1e3eeafde3c5bbfd614950b9c4573fa3904e6e081b836b02129d084b1cafd707433c6ad43fbfa5ae4844e27bac6bf51cc7b3893cc731cac0ce115df0c95af5592c199921d02c3256b03e709753cb584d4632157a3d9cc4950b491349ccdb09a2b08124ac798b28c608d5b1e0323cbb20fdeff14d070b053d140752cb54f8a527abd03b556d3dbc90930f7adaf5bc055135bd6e10f8a0bb9343f6d9d6699368f148918400af7f0c760f42a0945dec1de086b01b4818906d40f16061112cd8d770b5520c395842291e27894707f16aa48e58e457876b244da18b59a609c3f2438549ac3ee02109d555d47cd898941cd679cb208b369137ea7910168757e32b032a27a4bbed2ee2793b3f3ee8d0dbdcc5a01357c47faf41b287f12ae4965058cb8ed73fa98362f6a1dc62a8bf999a917a313f368c5a7d1cc726ebacd1feea8c50fbbd2068130c1ab63f3d8a9cd37eef7324690767efbab96863767ab75b1dfe0a6a2c40c7735d0d815967d35e6ad07feac5194a4ac5b8ab5f63ef136bbead4202a27f1b4c324a1525b390e9449e985d7c2b0c405089e640fa15039eab8fbc6b41489791b684628c148c786580bd0c65de53d77a15d9ab9f2d350382a6371cd76d5151be18766f2cec25bf7db4e6807fd9b086ec1a0691fcd6594da21a2f7b757e209ec50c79495b70fdf968fcba6fd39d79008cc74255da1da4ff60ba63358f27dd180c3a3912e5c46b9ae24b5b19a2e2d22185773df9b9c1b9b4ef33017eaa555839a1565196b15b63c6ea003a44b9c4df52681c2f46c5fa00eb1c5c7cb6f76a57f7afb34cbb5e21133e1a50eb126c8c24d2f11c0a90dd66cdd05a33c66249f8c25d6eaaf9cef1df400134d5ae931947d730cce9a72411f6e5c3b7616a438fc5fcb2d5a12c9a14e13b005f5f77856a3b201d0e5bb6b6f91c6014ca4ec63c54d968a27f57775c74c7f068d4ef704e55a761cc5ff708f9e380316887373d6beff8c373824f248ecb8c1b847d1c949b11a2e44d0ad324a639005ef979649f71956a979a4ca55191ec1a714fc9d5dbb969ba097164fea8c7cfa3c517b314bc58078800a4dffd073cfcb1eb5d29691b1d67611eb1b46921f878796fed2c6431fe9816c2ea25d1f4e49faa1efd79928f284e21bbe53c0edaf780f329a51b01e291e1838dea7257c93e09a427a866ebb9dabcc18bdb90c86558081a6a4d40d9edf3c54ef7c4a04a5a6f1ce6ecb15bc2bfcae5ede0bdc9ab84e2fcc1c6db652ad31c58a871152de8efa41c1b7b0a83e4f973ada22a688b9339eae48dc9308c0a7881ac92a41d3f31c3340778816a082dbe7877987a569f5414638df865b14e4123ce2e7b2f26e3d78aada4314a3987301f2fc547aed1557021b9cda4a71a1241e988c1875f1db37353dab7c47918d96c37a3332ae05f78bb384d693d13da5bcd93d054df7664ff3a4066171b1468637f9dd180ddcb869b84da5abbaf8dc3e9253dd09522ffb8b351de02d75c387a1df1c4a4c282cbcc9e5964ea24b3e230c4dc2ff1b7fad25310df3e0ff26ec1385790b07a7edc75863e322eb14fd63aa50e21e65e50912f9e7a1c27dda5cd076559fa81928ee813e9ddef1d7068437eb937220685fce49546a2c3d4623138409611a161b23eec729e886ac9d6c0360b5b148170c690363eb4879af90ff416d18379c06517291eb42c962b17ba560a6ce416ddeca5b843b6e4c5a485c43320786773ee2519550660013b64fd33ecf1bd715549ec4c5c8b907a850b5d9f81d55281875afd858d8150bb9b1674c68a9f67e40dd9d0d0ee7ecb21a8805790d82195ef2a9f061c48a4c78a7e7f8d971eb275cb549f6db80ef62cb95f153f447fbc0b079e3d5fc1c12e07a67eb482de4295927a997bb6b447464ac33aa330bf2edc5ab9048262b34a6d5bb0b7f544839c76516d91c0be2df419d7cd6cd9aeebe88ba36e755dd97945b6515629eb784c53a2e19af58c9c2487f8196716e8dc027af54071622b1e3c5b59b263088287b3cdcae11819c95a1f7353ca0b9fc4ad4796828f039a30239683a778ec56ded7ea1e728e590216090d26580f2d4d013130f6837eb429f9e2fa6683b027cf5273534f0b8688544743969e3a79eda7db2405622665f26ce6572c1b1fa9b73aa5013dfabe7503bac3285eeee013d8e9682f2d0694cd25f9543480b58c36f5bfbb79f2480246f4fe72fac1cc233523be1ea4f1c9d6a8437a4c6eba29d4786071fee45e3527c1aa9cdf30889077e704c994227eb56cda8bc77394c121c4d456e5ff42f1df874acea5c177a7f51a2a839da78ff4a7bf7208de5e0e4a3dfe0f3f82d6dae6bab9ee3eccb0b9c0ec737d2111eb69676c900ff4e3f2b97d21acb88d07cd79bed5fb160771101b0202a48a3ac95193c75b149bb71a17c610d91c8d9ee845654771bad1c8556cbb0582f13924ed34da261626adc3f445318e47d85e2a300bd6e6a5bf92c76e27a0fcec90359c3bc3e3276f9133bca4f7f00ed882600b75705906f86ef90453f05eaf3ec4948d3e414996bc6cd846df8b686d6a41974c3e37c35824d96a58a9a463c6895db55a7d1f987fe71451164ce1b787f8c893913aaf7a274cad03d06e6ea7b705e05511f4ed685e14259932b275c4fba182b00d2a9af4176a21556925d0eac299f9f3dd8fde2a8679740cc7656bcbac0fef01b5a66a1ffb5156298839a5890fb232e377bde4df80334872575513be795e3f28795bdc5cb2cbc469677f9341f60a0cac80d654008a3406ea94ef5a289307c06761da39ebe10f4afeaa1c9e96a2c8fc1a172423697d06bf0d9e8dc60aacfa18b7832f1b108726dd1ecdb654b6998b467263943608832beae2e091681b3a631cbac217583dcd0ad4cdc58564af67c68aa7ffbbf807ee03ec3cd80a7710afb171dd25e680cb6da56d45dd2a0b67042a11bd428baa0905b4a96f79d418312a0340cd736bfa177ba851e41e55eef723024e77f198fce4078dd2fe18df144ec479545fbaad1c9c948cc19715b3699b90a7f0d616f92aab2cf539197aba1aa373843484e8ea3d5e00343495356818fb0d400173136484a50595f747f8d00000000000000000000000000000000000000000000000000000003050c10121b2430"
}

private func hex(_ string: String) -> Data {
    var data = Data(capacity: string.count / 2)
    var index = string.startIndex
    while index < string.endIndex {
        let next = string.index(index, offsetBy: 2)
        data.append(UInt8(string[index ..< next], radix: 16)!)
        index = next
    }
    return data
}
