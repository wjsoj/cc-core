package stream

import (
	"bufio"
	"bytes"
	"io"
)

// SSEScanner is a line-by-line Server-Sent Events parser that surfaces
// each input line to the caller along with the current event-type
// context. Designed for use cases where the caller wants to:
//
//   - forward the original bytes downstream verbatim (or with rewrites),
//   - AND simultaneously inspect data: payloads keyed by their event:
//     type to accumulate state (usage counts, tool-use snapshots, ...).
//
// Callers iterate via Scan(); after each successful Scan(), Line() is
// the raw line as read (including its trailing \n where present),
// Event() is the most recently seen event-type, and Data() is the
// trimmed payload when the line begins with "data:" — otherwise "".
//
// The scanner is intentionally minimal: it doesn't parse the JSON
// payload, doesn't dispatch to handlers, doesn't manage backpressure.
// Wire those concerns at the call site.
type SSEScanner struct {
	r          *bufio.Reader
	curLine    []byte
	curEvent   string
	curData    []byte // non-nil when curLine started with "data:"
	scanErr    error
	bufSize    int
}

// NewSSEScanner returns a scanner over r. bufSize is the bufio reader
// buffer (default 64 KiB when 0 — large enough to hold one SSE event
// line of a typical Anthropic/OpenAI response).
func NewSSEScanner(r io.Reader, bufSize int) *SSEScanner {
	if bufSize <= 0 {
		bufSize = 64 * 1024
	}
	return &SSEScanner{
		r:       bufio.NewReaderSize(r, bufSize),
		bufSize: bufSize,
	}
}

// Scan reads the next line from the stream. Returns true on success,
// false at EOF or on read error; check Err for cause. The trailing
// newline is preserved on Line() so callers can re-emit byte-perfect.
func (s *SSEScanner) Scan() bool {
	line, err := s.r.ReadBytes('\n')
	if len(line) == 0 {
		s.scanErr = err
		return false
	}
	s.curLine = line
	s.curData = nil
	trim := bytes.TrimRight(line, "\r\n")
	switch {
	case bytes.HasPrefix(trim, []byte("event:")):
		s.curEvent = string(bytes.TrimSpace(trim[6:]))
	case bytes.HasPrefix(trim, []byte("data:")):
		s.curData = bytes.TrimSpace(trim[5:])
	}
	// Defer the read error to the NEXT Scan() so the caller still gets
	// to emit the final partial line returned alongside io.EOF.
	if err != nil {
		s.scanErr = err
	}
	return true
}

// Line returns the most recent line (with original trailing newline).
// Valid only after Scan() returned true.
func (s *SSEScanner) Line() []byte { return s.curLine }

// Event returns the most recently seen `event: <name>` value, or "" if
// no event line has been seen yet in the stream.
func (s *SSEScanner) Event() string { return s.curEvent }

// Data returns the trimmed payload when the current line started with
// `data: ` — otherwise nil. Subsequent non-data lines do NOT clear it
// across Scan calls (each Scan rewrites it from the current line).
func (s *SSEScanner) Data() []byte { return s.curData }

// Err returns the underlying read error after Scan returns false.
// io.EOF is normal termination and is returned as nil per the
// bufio.Scanner convention.
func (s *SSEScanner) Err() error {
	if s.scanErr == io.EOF {
		return nil
	}
	return s.scanErr
}
