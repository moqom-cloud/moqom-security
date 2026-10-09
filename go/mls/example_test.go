// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

package mls_test

import (
	"bytes"
	"errors"
	"fmt"
	"log"

	"github.com/moqom-cloud/moqom-security/go/mls"
)

// Alice founds a group and adds Bob from his key package. Bob joins from the
// Welcome, Alice rotates her leaf key with an empty commit, and both end on
// the same epoch with the same epoch authenticator and SFrame base key.
func Example() {
	room := []byte("acme/room-42")
	alice, err := mls.GenerateKeyPackage("alice/phone", mls.FoundingSuite)
	if err != nil {
		log.Fatal(err)
	}
	bob, err := mls.GenerateKeyPackage("bob/laptop", mls.FoundingSuite)
	if err != nil {
		log.Fatal(err)
	}

	// Alice reads Bob's published key package and commits to add him.
	bobPackage, err := mls.ParseKeyPackage(bob.KeyPackage.Encode())
	if err != nil {
		log.Fatal(err)
	}
	aliceGroup, err := mls.CreateGroup(room, alice)
	if err != nil {
		log.Fatal(err)
	}
	add, err := aliceGroup.Commit([]*mls.KeyPackage{bobPackage}, nil)
	if err != nil {
		log.Fatal(err)
	}
	aliceGroup = add.Next // once the delivery service accepts add.Message

	// Bob joins from the Welcome.
	welcome, err := mls.DecodeWelcome(add.Welcome.Encode())
	if err != nil {
		log.Fatal(err)
	}
	bobGroup, err := mls.Join(welcome, bob)
	if err != nil {
		log.Fatal(err)
	}

	// An empty commit refreshes Alice's leaf key; Bob follows it.
	update, err := aliceGroup.Commit(nil, nil)
	if err != nil {
		log.Fatal(err)
	}
	aliceGroup = update.Next
	message, err := mls.DecodeCommitMessage(update.Message.Encode())
	if err != nil {
		log.Fatal(err)
	}
	bobGroup, _, err = bobGroup.Process(message)
	if err != nil {
		log.Fatal(err)
	}

	aliceBase, err := aliceGroup.Exporter(mls.SFrameExporterLabel, nil, 32)
	if err != nil {
		log.Fatal(err)
	}
	bobBase, err := bobGroup.Exporter(mls.SFrameExporterLabel, nil, 32)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("epoch:", aliceGroup.Epoch(), bobGroup.Epoch())
	fmt.Println("leaves:", aliceGroup.OwnLeaf(), bobGroup.OwnLeaf())
	fmt.Println("same authenticator:", bytes.Equal(aliceGroup.EpochAuthenticator(), bobGroup.EpochAuthenticator()))
	fmt.Println("same SFrame base key:", bytes.Equal(aliceBase, bobBase))
	// Output:
	// epoch: 2 2
	// leaves: 0 1
	// same authenticator: true
	// same SFrame base key: true
}

// A delivery service checks a key package before accepting it. A package
// whose signature does not verify is refused with ErrBadSignature.
func ExampleParseKeyPackage() {
	bundle, err := mls.GenerateKeyPackage("bob/laptop", mls.FoundingSuite)
	if err != nil {
		log.Fatal(err)
	}
	data := bundle.KeyPackage.Encode()

	k, err := mls.ParseKeyPackage(data)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(k.Identity), k.CipherSuite)

	data[len(data)-1] ^= 1
	_, err = mls.ParseKeyPackage(data)
	fmt.Println(errors.Is(err, mls.ErrBadSignature))
	// Output:
	// bob/laptop MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87 (0xf0ac)
	// true
}

// Removing a member: the removed member's Process reports removed, and it
// can follow the group no further.
func ExampleGroup_Process() {
	alice, err := mls.GenerateKeyPackage("alice/phone", mls.FoundingSuite)
	if err != nil {
		log.Fatal(err)
	}
	bob, err := mls.GenerateKeyPackage("bob/laptop", mls.FoundingSuite)
	if err != nil {
		log.Fatal(err)
	}
	aliceGroup, err := mls.CreateGroup([]byte("acme/room-42"), alice)
	if err != nil {
		log.Fatal(err)
	}
	add, err := aliceGroup.Commit([]*mls.KeyPackage{bob.KeyPackage}, nil)
	if err != nil {
		log.Fatal(err)
	}
	bobGroup, err := mls.Join(add.Welcome, bob)
	if err != nil {
		log.Fatal(err)
	}

	leaf, _ := add.Next.LeafOf("bob/laptop")
	remove, err := add.Next.Commit(nil, []uint32{leaf})
	if err != nil {
		log.Fatal(err)
	}
	_, removed, err := bobGroup.Process(remove.Message)
	fmt.Println("removed:", removed, err)
	// Output:
	// removed: true <nil>
}

// A broadcast viewer is not a member. The committer seals each epoch's SFrame
// base key to the viewer's ML-KEM-1024 key, for one group and epoch only.
func ExampleSealAudience() {
	groupID := []byte("acme/room-42")
	base := make([]byte, 32) // from Group.Exporter(SFrameExporterLabel, nil, 32)

	private, public, err := mls.GenerateAudienceKeyPair()
	if err != nil {
		log.Fatal(err)
	}
	envelope, err := mls.SealAudience(base, public, groupID, 7)
	if err != nil {
		log.Fatal(err)
	}

	opened, err := mls.OpenAudience(envelope, private, groupID, 7)
	fmt.Println(bytes.Equal(opened, base), err)
	_, err = mls.OpenAudience(envelope, private, groupID, 8)
	fmt.Println(errors.Is(err, mls.ErrDecryptionFailed))
	// Output:
	// true <nil>
	// true
}
