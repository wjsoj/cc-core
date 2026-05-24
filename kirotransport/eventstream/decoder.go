package eventstream

import (
	"encoding/binary"
	"errors"
	"io"
)

// DefaultMaxBuffer is the soft cap on internal buffering (16 MiB).
const DefaultMaxBuffer = 16 * 1024 * 1024

// ErrBufferOverflow is returned when Feed would exceed MaxBuffer.
var ErrBufferOverflow = errors.New("eventstream: buffer overflow")

// Decoder is a stateful streaming decoder that holds a rolling buffer and
// emits Frames as they become complete.
//
// Typical use:
//
//	dec := eventstream.NewDecoder()
//	for {
//	    n, err := r.Read(chunk)
//	    if n > 0 { _ = dec.Feed(chunk[:n]) }
//	    for {
//	        frame, ok, derr := dec.Next()
//	        if derr != nil { /* handle parse error; dec.Skip(1) to step over */ break }
//	        if !ok { break }
//	        // dispatch frame
//	    }
//	    if err == io.EOF { break }
//	}
type Decoder struct {
	buf       []byte
	maxBuffer int
}

// NewDecoder returns a new Decoder with the default 16 MiB buffer cap.
func NewDecoder() *Decoder { return &Decoder{maxBuffer: DefaultMaxBuffer} }

// SetMaxBuffer overrides the buffer cap. Must be > 0.
func (d *Decoder) SetMaxBuffer(max int) {
	if max > 0 {
		d.maxBuffer = max
	}
}

// Feed appends data to the internal buffer.
func (d *Decoder) Feed(p []byte) error {
	if len(d.buf)+len(p) > d.maxBuffer {
		return ErrBufferOverflow
	}
	d.buf = append(d.buf, p...)
	return nil
}

// Next attempts to decode one frame.
//
// ok=true: frame ready.
// ok=false, err=nil: need more data (call Feed and retry).
// err != nil: structural error; caller decides recovery (typically Skip(1) for
// prelude errors or SkipFrame() for data errors).
func (d *Decoder) Next() (frame *Frame, ok bool, err error) {
	if len(d.buf) == 0 {
		return nil, false, nil
	}
	f, n, err := ParseFrame(d.buf)
	if err != nil {
		return nil, false, err
	}
	if f == nil {
		return nil, false, nil
	}
	d.buf = d.buf[n:]
	return f, true, nil
}

// Skip advances past n bytes in the buffer (recovery helper).
func (d *Decoder) Skip(n int) {
	if n < 0 {
		n = 0
	}
	if n > len(d.buf) {
		n = len(d.buf)
	}
	d.buf = d.buf[n:]
}

// SkipFrame uses the total_length from a malformed frame to step past it.
// Returns the number of bytes skipped, or 0 if the buffer is too short or
// the length looks unreasonable (in which case caller should Skip(1)).
func (d *Decoder) SkipFrame() int {
	if len(d.buf) < PreludeSize {
		return 0
	}
	total := int(binary.BigEndian.Uint32(d.buf[0:4]))
	if total < MinMessageSize || total > len(d.buf) || uint32(total) > MaxMessageSize {
		return 0
	}
	d.buf = d.buf[total:]
	return total
}

// Buffered returns how many bytes are currently held.
func (d *Decoder) Buffered() int { return len(d.buf) }

// ReadAll drains r through the decoder and returns all frames. Used by tests
// and one-shot consumers; streaming callers should use Feed/Next directly.
func ReadAll(r io.Reader) ([]*Frame, error) {
	dec := NewDecoder()
	buf := make([]byte, 32*1024)
	var frames []*Frame
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if ferr := dec.Feed(buf[:n]); ferr != nil {
				return frames, ferr
			}
			for {
				f, ok, perr := dec.Next()
				if perr != nil {
					return frames, perr
				}
				if !ok {
					break
				}
				frames = append(frames, f)
			}
		}
		if err == io.EOF {
			return frames, nil
		}
		if err != nil {
			return frames, err
		}
	}
}
