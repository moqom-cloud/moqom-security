// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

package sframe_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/moqom-cloud/moqom-security/go/sframe"
)

// A publisher seals one MoQ object and a subscriber opens it. Both derive the
// same key from the epoch's base key, which in a room is exported from the MLS
// group under sframe.MLSExporterLabel.
func Example() {
	baseKey := bytes.Repeat([]byte{0x2A}, 32)
	keyID := sframe.MLSKeyID(3, 14) // leaf 3, epoch 14

	key, err := sframe.NewKey(keyID, baseKey, sframe.AES256GCMSHA512)
	if err != nil {
		panic(err)
	}
	sender := sframe.NewSender(key)
	receiver := sframe.NewReceiver(sframe.DefaultReplayWindow)
	receiver.Add(key)

	metadata := sframe.Metadata{
		Group:    5,
		Object:   2,
		Priority: 64,
		Properties: []sframe.Property{
			sframe.IntegerProperty(0x78, 1_000_000), // capture time
			sframe.IntegerProperty(0x7A, 1),         // temporal layer
		},
	}
	object, err := sender.ProtectObject([]byte("frame"), metadata)
	if err != nil {
		panic(err)
	}
	fmt.Println("object:", len(object), "bytes, header", hex.EncodeToString(object[:2]))

	// A relay that relabels the object's group, or flips a bit, is caught.
	moved := metadata
	moved.Group = 6
	_, err = receiver.UnprotectObject(object, moved)
	fmt.Println("moved to group 6:", sframe.Class(err))

	damaged := bytes.Clone(object)
	damaged[len(damaged)-1] ^= 0x01
	_, err = receiver.UnprotectObject(damaged, metadata)
	fmt.Println("one bit flipped:", sframe.Class(err))

	// Neither failure used up the counter, so the real object still opens.
	payload, err := receiver.UnprotectObject(object, metadata)
	fmt.Printf("opened: %q %v\n", payload, err)

	_, err = receiver.UnprotectObject(object, metadata)
	fmt.Println("delivered again:", sframe.Class(err))

	// Output:
	// object: 23 bytes, header 803e
	// moved to group 6: authentication_failure
	// one bit flipped: authentication_failure
	// opened: "frame" <nil>
	// delivered again: replay
}

// The replay window accepts objects that arrive out of order, up to 1,023
// counters behind the highest seen with the default window of 1,024.
func Example_replayWindow() {
	ctx, err := sframe.NewContext(sframe.AES128GCMSHA256, 1, bytes.Repeat([]byte{0x2A}, 16))
	if err != nil {
		panic(err)
	}
	metadata := sframe.Metadata{Group: 0, Priority: 128}

	objects := make([][]byte, 1025) // counters 0 to 1024
	for i := range objects {
		objects[i], err = ctx.Seal([]byte{byte(i)}, metadata)
		if err != nil {
			panic(err)
		}
	}

	for _, counter := range []int{1024, 1, 0, 1} {
		_, err := ctx.Open(objects[counter], metadata)
		var replay *sframe.ReplayError
		switch {
		case err == nil:
			fmt.Println(counter, "opened")
		case errors.As(err, &replay):
			fmt.Println(counter, "refused as a replay of counter", replay.Counter)
		default:
			fmt.Println(counter, err)
		}
	}

	// Output:
	// 1024 opened
	// 1 opened
	// 0 refused as a replay of counter 0
	// 1 refused as a replay of counter 1
}
