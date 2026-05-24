package eventstream

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// HeaderValueType is the AWS event-stream wire tag for header values.
type HeaderValueType uint8

const (
	HeaderBoolTrue  HeaderValueType = 0
	HeaderBoolFalse HeaderValueType = 1
	HeaderByte      HeaderValueType = 2
	HeaderShort     HeaderValueType = 3
	HeaderInteger   HeaderValueType = 4
	HeaderLong      HeaderValueType = 5
	HeaderByteArray HeaderValueType = 6
	HeaderString    HeaderValueType = 7
	HeaderTimestamp HeaderValueType = 8
	HeaderUUID      HeaderValueType = 9
)

// HeaderValue is a tagged union for the 10 wire types.
type HeaderValue struct {
	Type HeaderValueType
	Bool bool
	Int  int64  // Byte / Short / Integer / Long / Timestamp (ms epoch)
	Bin  []byte // ByteArray / String (utf-8 bytes) / UUID (16 bytes)
}

// String returns the value as a string when Type is HeaderString, else "".
func (v HeaderValue) String() string {
	if v.Type == HeaderString {
		return string(v.Bin)
	}
	return ""
}

// Headers is an ordered name→value map for one event-stream frame.
// Insertion order is preserved (encoder writes in order).
type Headers struct {
	names  []string
	values map[string]HeaderValue
}

// NewHeaders returns an empty Headers ready to use.
func NewHeaders() *Headers {
	return &Headers{values: make(map[string]HeaderValue)}
}

// Set inserts or replaces a header.
func (h *Headers) Set(name string, value HeaderValue) {
	if _, ok := h.values[name]; !ok {
		h.names = append(h.names, name)
	}
	h.values[name] = value
}

// SetString is shorthand for Set with a HeaderString value.
func (h *Headers) SetString(name, value string) {
	h.Set(name, HeaderValue{Type: HeaderString, Bin: []byte(value)})
}

// Get returns the value and ok=true if present.
func (h *Headers) Get(name string) (HeaderValue, bool) {
	v, ok := h.values[name]
	return v, ok
}

// GetString returns the string value, or "" if missing or wrong type.
func (h *Headers) GetString(name string) string {
	v, ok := h.values[name]
	if !ok {
		return ""
	}
	return v.String()
}

// MessageType returns the value of ":message-type".
func (h *Headers) MessageType() string { return h.GetString(":message-type") }

// EventType returns the value of ":event-type".
func (h *Headers) EventType() string { return h.GetString(":event-type") }

// ExceptionType returns the value of ":exception-type".
func (h *Headers) ExceptionType() string { return h.GetString(":exception-type") }

// ErrorCode returns the value of ":error-code".
func (h *Headers) ErrorCode() string { return h.GetString(":error-code") }

// Names returns the insertion-order list of header names.
func (h *Headers) Names() []string {
	out := make([]string, len(h.names))
	copy(out, h.names)
	return out
}

// parseHeaders decodes the headers block (length = headerLength bytes).
func parseHeaders(data []byte) (*Headers, error) {
	h := NewHeaders()
	offset := 0
	for offset < len(data) {
		if offset+1 > len(data) {
			return nil, fmt.Errorf("eventstream: header truncated reading name length at %d", offset)
		}
		nameLen := int(data[offset])
		offset++
		if nameLen == 0 {
			return nil, errors.New("eventstream: header name length is zero")
		}
		if offset+nameLen > len(data) {
			return nil, fmt.Errorf("eventstream: header truncated reading name (need %d, have %d)", nameLen, len(data)-offset)
		}
		name := string(data[offset : offset+nameLen])
		offset += nameLen

		if offset+1 > len(data) {
			return nil, fmt.Errorf("eventstream: header truncated reading type tag at %d", offset)
		}
		typeTag := HeaderValueType(data[offset])
		offset++

		value, consumed, err := parseHeaderValue(data[offset:], typeTag)
		if err != nil {
			return nil, fmt.Errorf("eventstream: header %q: %w", name, err)
		}
		offset += consumed
		h.Set(name, value)
	}
	return h, nil
}

func parseHeaderValue(data []byte, t HeaderValueType) (HeaderValue, int, error) {
	switch t {
	case HeaderBoolTrue:
		return HeaderValue{Type: t, Bool: true}, 0, nil
	case HeaderBoolFalse:
		return HeaderValue{Type: t, Bool: false}, 0, nil
	case HeaderByte:
		if len(data) < 1 {
			return HeaderValue{}, 0, errors.New("byte: need 1 byte")
		}
		return HeaderValue{Type: t, Int: int64(int8(data[0]))}, 1, nil
	case HeaderShort:
		if len(data) < 2 {
			return HeaderValue{}, 0, errors.New("short: need 2 bytes")
		}
		return HeaderValue{Type: t, Int: int64(int16(binary.BigEndian.Uint16(data)))}, 2, nil
	case HeaderInteger:
		if len(data) < 4 {
			return HeaderValue{}, 0, errors.New("integer: need 4 bytes")
		}
		return HeaderValue{Type: t, Int: int64(int32(binary.BigEndian.Uint32(data)))}, 4, nil
	case HeaderLong, HeaderTimestamp:
		if len(data) < 8 {
			return HeaderValue{}, 0, errors.New("long/timestamp: need 8 bytes")
		}
		return HeaderValue{Type: t, Int: int64(binary.BigEndian.Uint64(data))}, 8, nil
	case HeaderByteArray, HeaderString:
		if len(data) < 2 {
			return HeaderValue{}, 0, errors.New("bytearray/string: need length prefix")
		}
		l := int(binary.BigEndian.Uint16(data))
		if len(data) < 2+l {
			return HeaderValue{}, 0, fmt.Errorf("bytearray/string: need %d bytes after prefix, have %d", l, len(data)-2)
		}
		buf := make([]byte, l)
		copy(buf, data[2:2+l])
		return HeaderValue{Type: t, Bin: buf}, 2 + l, nil
	case HeaderUUID:
		if len(data) < 16 {
			return HeaderValue{}, 0, errors.New("uuid: need 16 bytes")
		}
		buf := make([]byte, 16)
		copy(buf, data[:16])
		return HeaderValue{Type: t, Bin: buf}, 16, nil
	default:
		return HeaderValue{}, 0, fmt.Errorf("unknown header value type %d", t)
	}
}

// encode serializes h to its wire form.
func (h *Headers) encode() []byte {
	var out []byte
	for _, name := range h.names {
		v := h.values[name]
		out = append(out, byte(len(name)))
		out = append(out, name...)
		out = append(out, byte(v.Type))
		switch v.Type {
		case HeaderBoolTrue, HeaderBoolFalse:
			// no value bytes
		case HeaderByte:
			out = append(out, byte(int8(v.Int)))
		case HeaderShort:
			var b [2]byte
			binary.BigEndian.PutUint16(b[:], uint16(int16(v.Int)))
			out = append(out, b[:]...)
		case HeaderInteger:
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], uint32(int32(v.Int)))
			out = append(out, b[:]...)
		case HeaderLong, HeaderTimestamp:
			var b [8]byte
			binary.BigEndian.PutUint64(b[:], uint64(v.Int))
			out = append(out, b[:]...)
		case HeaderByteArray, HeaderString:
			var b [2]byte
			binary.BigEndian.PutUint16(b[:], uint16(len(v.Bin)))
			out = append(out, b[:]...)
			out = append(out, v.Bin...)
		case HeaderUUID:
			out = append(out, v.Bin...)
		}
	}
	return out
}
