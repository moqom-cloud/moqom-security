// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Elliott Wave LLC

package proof

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"unicode/utf8"
)

// maxNesting is how many arrays and objects may sit inside one another, the
// outermost object included: serde_json's limit.
const maxNesting = 127

// object decodes one JSON object into its members, refusing anything two
// parsers could read differently: invalid UTF-8, a `\u` escape of an unpaired
// surrogate, a number too large for a float64, nesting deeper than
// [maxNesting], or an object anywhere inside that names a member twice.
// encoding/json would replace the first two with U+FFFD and keep the last of a
// duplicate, where other parsers refuse or keep the first.
func object(data []byte) (map[string]json.RawMessage, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("not UTF-8")
	}
	if !json.Valid(data) {
		return nil, errors.New("not JSON")
	}
	if trimmed := bytes.TrimLeft(data, " \t\r\n"); len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, errors.New("not a JSON object")
	}
	if !pairedSurrogates(data) {
		return nil, errors.New("an unpaired surrogate escape")
	}
	if err := uniqueMembers(data); err != nil {
		return nil, err
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(data, &members); err != nil {
		return nil, errors.New("not a JSON object")
	}
	return members, nil
}

// uniqueMembers refuses JSON in which any object, at any depth, names a member
// twice. Names are compared after unescaping and byte for byte, so "jti" and
// "j\u0074i" are the same and "jti" and "JTI" are not. It also refuses nesting
// deeper than [maxNesting], and (as Token does) a number that overflows a
// float64.
func uniqueMembers(data []byte) error {
	type level struct {
		names   map[string]bool
		wantKey bool
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	var stack []*level
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if token == json.Delim('}') || token == json.Delim(']') {
			stack = stack[:len(stack)-1]
			continue
		}
		var top *level
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		if top != nil && top.names != nil {
			if top.wantKey {
				name, _ := token.(string)
				if top.names[name] {
					return fmt.Errorf("member %q appears twice", name)
				}
				top.names[name], top.wantKey = true, false
				continue
			}
			top.wantKey = true
		}
		if (token == json.Delim('{') || token == json.Delim('[')) && len(stack) == maxNesting {
			return fmt.Errorf("nested deeper than %d", maxNesting)
		}
		switch token {
		case json.Delim('{'):
			stack = append(stack, &level{names: map[string]bool{}, wantKey: true})
		case json.Delim('['):
			stack = append(stack, &level{})
		}
	}
}

// pairedSurrogates reports whether every `\u` escape in valid JSON data that
// names a surrogate is a high one followed at once by a low one.
func pairedSurrogates(data []byte) bool {
	inString := false
	for i := 0; i < len(data); i++ {
		switch {
		case !inString:
			inString = data[i] == '"'
		case data[i] == '"':
			inString = false
		case data[i] == '\\':
			i++
			if data[i] != 'u' {
				continue
			}
			unit := hexUnit(data[i+1 : i+5])
			i += 4
			switch {
			case unit >= 0xDC00 && unit < 0xE000:
				return false
			case unit >= 0xD800 && unit < 0xDC00:
				if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
					return false
				}
				if low := hexUnit(data[i+3 : i+7]); low < 0xDC00 || low >= 0xE000 {
					return false
				}
				i += 6
			}
		}
	}
	return true
}

func hexUnit(digits []byte) uint64 {
	unit, _ := strconv.ParseUint(string(digits), 16, 16)
	return unit
}
