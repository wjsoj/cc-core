package eventstream

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
)

const (
	// PreludeSize is the fixed prelude length: total_length(4) + header_length(4) + prelude_crc(4).
	PreludeSize = 12
	// MinMessageSize is prelude + message_crc(4).
	MinMessageSize = PreludeSize + 4
	// MaxMessageSize is the hard ceiling AWS enforces.
	MaxMessageSize uint32 = 16 * 1024 * 1024
)

// Frame is one decoded event-stream message.
type Frame struct {
	Headers *Headers
	Payload []byte
}

// MessageType is the value of the ":message-type" header (e.g. "event", "exception", "error").
func (f *Frame) MessageType() string { return f.Headers.MessageType() }

// EventType is the value of the ":event-type" header.
func (f *Frame) EventType() string { return f.Headers.EventType() }

// PayloadJSON unmarshals Payload into v.
func (f *Frame) PayloadJSON(v any) error { return json.Unmarshal(f.Payload, v) }

// ParseError signals a structurally invalid frame.
type ParseError struct {
	Stage string // "prelude" | "data"
	Msg   string
}

func (e *ParseError) Error() string { return "eventstream: " + e.Stage + ": " + e.Msg }

func preludeErr(format string, args ...any) *ParseError {
	return &ParseError{Stage: "prelude", Msg: fmt.Sprintf(format, args...)}
}
func dataErr(format string, args ...any) *ParseError {
	return &ParseError{Stage: "data", Msg: fmt.Sprintf(format, args...)}
}

// ParseFrame tries to decode one frame from buf.
//
// Returns (frame, n, nil) on success — n is the number of bytes consumed.
// Returns (nil, 0, nil) if buf does not yet contain a complete frame.
// Returns (nil, 0, err) on structural error; recovery is caller's choice.
func ParseFrame(buf []byte) (*Frame, int, error) {
	if len(buf) < PreludeSize {
		return nil, 0, nil
	}
	totalLen := binary.BigEndian.Uint32(buf[0:4])
	headerLen := binary.BigEndian.Uint32(buf[4:8])
	preludeCRC := binary.BigEndian.Uint32(buf[8:12])

	if totalLen < uint32(MinMessageSize) {
		return nil, 0, preludeErr("total_length %d below minimum %d", totalLen, MinMessageSize)
	}
	if totalLen > MaxMessageSize {
		return nil, 0, preludeErr("total_length %d above maximum %d", totalLen, MaxMessageSize)
	}
	if got := CRC32(buf[0:8]); got != preludeCRC {
		return nil, 0, preludeErr("prelude crc mismatch: have %#x want %#x", got, preludeCRC)
	}

	tl := int(totalLen)
	hl := int(headerLen)
	if len(buf) < tl {
		return nil, 0, nil // incomplete, wait for more
	}

	msgCRC := binary.BigEndian.Uint32(buf[tl-4 : tl])
	if got := CRC32(buf[0 : tl-4]); got != msgCRC {
		return nil, 0, dataErr("message crc mismatch: have %#x want %#x", got, msgCRC)
	}

	if PreludeSize+hl > tl-4 {
		return nil, 0, dataErr("header_length %d overruns message", hl)
	}

	headers, err := parseHeaders(buf[PreludeSize : PreludeSize+hl])
	if err != nil {
		return nil, 0, dataErr("%v", err)
	}

	payload := make([]byte, tl-4-PreludeSize-hl)
	copy(payload, buf[PreludeSize+hl:tl-4])

	return &Frame{Headers: headers, Payload: payload}, tl, nil
}

// EncodeFrame serializes a frame to wire bytes (used for tests + outbound frames).
func EncodeFrame(headers *Headers, payload []byte) []byte {
	if headers == nil {
		headers = NewHeaders()
	}
	headerBytes := headers.encode()
	totalLen := uint32(PreludeSize + len(headerBytes) + len(payload) + 4)

	out := make([]byte, 0, int(totalLen))
	var prelude [PreludeSize]byte
	binary.BigEndian.PutUint32(prelude[0:4], totalLen)
	binary.BigEndian.PutUint32(prelude[4:8], uint32(len(headerBytes)))
	binary.BigEndian.PutUint32(prelude[8:12], CRC32(prelude[0:8]))
	out = append(out, prelude[:]...)
	out = append(out, headerBytes...)
	out = append(out, payload...)

	var crcBuf [4]byte
	binary.BigEndian.PutUint32(crcBuf[:], CRC32(out))
	out = append(out, crcBuf[:]...)
	return out
}
