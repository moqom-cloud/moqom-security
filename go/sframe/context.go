// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

package sframe

// Context seals and opens MoQ objects under one key. Sealing owns the counter
// and opening keeps the replay window, as Sender and Receiver do; a room with
// a key per sender uses those directly.
//
// The counter starts at 0 for every new context. Never create two contexts
// that seal under the same base key and KID, including one after a restart;
// see Sender.
type Context struct {
	key      *Key
	sender   *Sender
	receiver *Receiver
}

// NewContext derives the key for keyID from baseKey, with the default replay
// window.
func NewContext(suite CipherSuite, keyID uint64, baseKey []byte) (*Context, error) {
	return NewContextWindow(suite, keyID, baseKey, DefaultReplayWindow)
}

// NewContextWindow is NewContext with a replay window of its own.
func NewContextWindow(suite CipherSuite, keyID uint64, baseKey []byte, replayWindow uint64) (*Context, error) {
	key, err := NewKey(keyID, baseKey, suite)
	if err != nil {
		return nil, err
	}
	receiver := NewReceiver(replayWindow)
	receiver.Add(key)
	return &Context{key: key, sender: NewSender(key), receiver: receiver}, nil
}

// Key is the context's key.
func (c *Context) Key() *Key { return c.key }

// Seal returns the SFrame object: header, ciphertext, tag.
func (c *Context) Seal(payload []byte, metadata Metadata) ([]byte, error) {
	return c.sender.ProtectObject(payload, metadata)
}

// Open returns the payload, if object authenticates under this key with
// metadata and its counter has not been seen.
func (c *Context) Open(object []byte, metadata Metadata) ([]byte, error) {
	return c.receiver.UnprotectObject(object, metadata)
}
