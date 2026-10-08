// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

package sframe

import (
	"encoding/binary"
	"slices"
)

// Metadata is the canonical description of one MoQ object, bound into the tag
// with its payload: the fields a relay reads to schedule, which it can then
// read and not change.
type Metadata struct {
	Group      uint64
	Object     uint64
	Priority   uint8
	Properties []Property
}

// Property is one object property. Even types carry a varint and odd types
// carry bytes; a mismatched pair has no encoding.
type Property struct {
	Type    uint64
	Integer uint64
	Bytes   []byte
	isBytes bool
}

// IntegerProperty is an even-typed property.
func IntegerProperty(t, value uint64) Property { return Property{Type: t, Integer: value} }

// BytesProperty is an odd-typed property.
func BytesProperty(t uint64, value []byte) Property {
	return Property{Type: t, Bytes: value, isBytes: true}
}

// IsBytes says which of Integer and Bytes the property carries.
func (p Property) IsBytes() bool { return p.isBytes }

const (
	varIntMaximum         = 1<<62 - 1
	maximumPropertyLength = 1<<16 - 1
)

// Encode is the AAD appended to the SFrame header: the MOQT wire encoding of
// the same fields, QUIC varints throughout, and properties as a count followed
// by type-delta-coded pairs sorted by type, keeping the given order among
// equal types.
func (m Metadata) Encode() ([]byte, error) {
	out := make([]byte, 0, 16)
	var err error
	put := func(v uint64) {
		if err == nil && v > varIntMaximum {
			err = ErrInvalidMetadata
		}
		out = appendVarInt(out, v)
	}
	put(m.Group)
	put(m.Object)
	out = append(out, m.Priority)
	put(uint64(len(m.Properties)))

	sorted := slices.Clone(m.Properties)
	slices.SortStableFunc(sorted, func(a, b Property) int {
		switch {
		case a.Type < b.Type:
			return -1
		case a.Type > b.Type:
			return 1
		}
		return 0
	})
	var previous uint64
	for _, p := range sorted {
		put(p.Type - previous)
		previous = p.Type
		if p.isBytes != (p.Type%2 == 1) || len(p.Bytes) > maximumPropertyLength {
			return nil, ErrInvalidMetadata
		}
		if p.isBytes {
			put(uint64(len(p.Bytes)))
			out = append(out, p.Bytes...)
		} else {
			put(p.Integer)
		}
	}
	if err != nil {
		return nil, err
	}
	return out, nil
}

func appendVarInt(out []byte, v uint64) []byte {
	switch {
	case v <= 63:
		return append(out, byte(v))
	case v <= 16383:
		return binary.BigEndian.AppendUint16(out, uint16(v)|0x4000)
	case v <= 1_073_741_823:
		return binary.BigEndian.AppendUint32(out, uint32(v)|0x8000_0000)
	default:
		return binary.BigEndian.AppendUint64(out, v|0xC000_0000_0000_0000)
	}
}
