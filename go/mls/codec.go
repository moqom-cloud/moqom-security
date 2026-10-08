// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

package mls

import (
	"encoding/binary"
	"fmt"
)

// The TLS presentation language as RFC 9420 §2.1 uses it: big-endian integers
// and vectors prefixed with the RFC's variable-length size.

type writer struct{ bytes []byte }

func (w *writer) uint8(v uint8)   { w.bytes = append(w.bytes, v) }
func (w *writer) uint16(v uint16) { w.bytes = binary.BigEndian.AppendUint16(w.bytes, v) }
func (w *writer) uint32(v uint32) { w.bytes = binary.BigEndian.AppendUint32(w.bytes, v) }
func (w *writer) uint64(v uint64) { w.bytes = binary.BigEndian.AppendUint64(w.bytes, v) }
func (w *writer) raw(data []byte) { w.bytes = append(w.bytes, data...) }

// length is RFC 9420 §2.1.2: one, two or four bytes, the top two bits giving
// which.
func (w *writer) length(n int) {
	switch {
	case n < 1<<6:
		w.uint8(uint8(n))
	case n < 1<<14:
		w.uint16(uint16(n) | 0x4000)
	case n < 1<<30:
		w.uint32(uint32(n) | 0x8000_0000)
	default:
		panic("mls: vectors are limited to 2^30 bytes")
	}
}

func (w *writer) vector(data []byte) {
	w.length(len(data))
	w.raw(data)
}

type reader struct {
	data []byte
	err  error
}

func (r *reader) fail(detail string) {
	if r.err == nil {
		r.err = fmt.Errorf("%w: %s", ErrMalformed, detail)
	}
}

func (r *reader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || len(r.data) < n {
		r.fail("truncated")
		return nil
	}
	out := r.data[:n:n]
	r.data = r.data[n:]
	return out
}

func (r *reader) uint8() uint8 {
	if b := r.take(1); b != nil {
		return b[0]
	}
	return 0
}

func (r *reader) uint16() uint16 {
	if b := r.take(2); b != nil {
		return binary.BigEndian.Uint16(b)
	}
	return 0
}

func (r *reader) uint32() uint32 {
	if b := r.take(4); b != nil {
		return binary.BigEndian.Uint32(b)
	}
	return 0
}

func (r *reader) uint64() uint64 {
	if b := r.take(8); b != nil {
		return binary.BigEndian.Uint64(b)
	}
	return 0
}

// length refuses a value not written in its shortest form, as the RFC
// requires.
func (r *reader) length() int {
	first := r.uint8()
	if r.err != nil {
		return 0
	}
	switch first >> 6 {
	case 0:
		return int(first)
	case 1:
		value := int(first&0x3f)<<8 | int(r.uint8())
		if r.err == nil && value < 1<<6 {
			r.fail("length not minimally encoded")
		}
		return value
	case 2:
		rest := r.take(3)
		if rest == nil {
			return 0
		}
		value := int(first&0x3f)<<24 | int(rest[0])<<16 | int(rest[1])<<8 | int(rest[2])
		if value < 1<<14 {
			r.fail("length not minimally encoded")
		}
		return value
	default:
		r.fail("reserved length prefix")
		return 0
	}
}

func (r *reader) vector() []byte {
	n := r.length()
	if r.err != nil {
		return nil
	}
	return r.take(n)
}

// finish is the error so far, or ErrMalformed if anything is left over.
func (r *reader) finish() error {
	if r.err == nil && len(r.data) != 0 {
		r.fail("trailing bytes")
	}
	return r.err
}

// cipherSuite reads a version and suite, refusing either if not implemented.
func (r *reader) cipherSuite() (CipherSuite, error) {
	version, suite := r.uint16(), CipherSuite(r.uint16())
	if r.err != nil {
		return 0, r.err
	}
	if version != protocolVersion || !suite.Known() {
		return 0, fmt.Errorf("%w: version %#04x suite %#04x", ErrUnsupported, version, uint16(suite))
	}
	return suite, nil
}
