package codexws

import (
	"bytes"
	"net"
	"strings"
)

// maxHandshakeBuffer caps how much of an outbound WebSocket upgrade we will
// hold while waiting for the end of the header block. A genuine handshake is
// ~2 KB (the bearer JWT and x-codex-turn-metadata dominate); anything past this
// is not a handshake we understand, so we stop buffering and pass it straight
// through rather than growing without bound.
const maxHandshakeBuffer = 64 << 10

// handshakeOrderConn rewrites the header block of the FIRST request written to
// the connection so it goes out in the captured order, then gets out of the way.
//
// Why this exists: gorilla builds an *http.Request and calls req.Write, and Go
// emits the request line, then Host, then User-Agent, then every remaining
// header sorted ALPHABETICALLY. No genuine client produces that order — real
// Codex sends a fixed semantic order (see handshakeHeaderOrder), and header
// order on HTTP/1.1 is a well-known client-fingerprinting signal, which is the
// whole reason this package pins a uTLS ClientHello in the first place.
// Fingerprinting the TLS layer while emitting an alphabetised header block
// leaves the two halves disagreeing.
//
// Intercepting the bytes is the least invasive fix available: gorilla owns the
// Sec-WebSocket-Key generation and the response parsing, so reimplementing the
// upgrade by hand would duplicate all of that for one ordering concern.
type handshakeOrderConn struct {
	net.Conn
	order []string
	buf   []byte
	done  bool
}

func newHandshakeOrderConn(c net.Conn, order []string) net.Conn {
	return &handshakeOrderConn{Conn: c, order: order}
}

// Write buffers until the end of the request header block, rewrites it, and
// forwards. Everything after the handshake passes through untouched, so the
// WebSocket frame path pays nothing.
//
// It reports len(p) consumed as soon as it has buffered the bytes, even though
// they have not reached the wire yet. That is legal for an io.Writer and is
// what makes this transparent to gorilla; a write error that happens at flush
// time surfaces to gorilla as a failure to read the handshake response, which
// it already handles.
func (c *handshakeOrderConn) Write(p []byte) (int, error) {
	if c.done {
		return c.Conn.Write(p)
	}
	c.buf = append(c.buf, p...)
	idx := bytes.Index(c.buf, []byte("\r\n\r\n"))
	if idx < 0 {
		if len(c.buf) > maxHandshakeBuffer {
			// Not something we recognize as a handshake. Flush verbatim and
			// stop interfering — degrading to the old behaviour beats
			// corrupting the stream.
			c.done = true
			pending := c.buf
			c.buf = nil
			if _, err := c.Conn.Write(pending); err != nil {
				return 0, err
			}
		}
		return len(p), nil
	}

	head := c.buf[:idx+4]
	rest := c.buf[idx+4:]
	c.done = true
	c.buf = nil

	if _, err := c.Conn.Write(reorderHeaderBlock(head, c.order)); err != nil {
		return 0, err
	}
	if len(rest) > 0 {
		if _, err := c.Conn.Write(rest); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

// reorderHeaderBlock rewrites one complete HTTP/1.1 request head (request line
// through the terminating blank line) so its headers appear in `order`.
//
// Two things happen per header:
//
//   - Position: headers named in `order` come first, in that order. Anything
//     not named keeps its relative order and follows — dropping an unexpected
//     header would be worse than misplacing it.
//   - Spelling: a matched header's name is rewritten to the exact case in
//     `order`. This is what turns gorilla's "Sec-WebSocket-Extensions" into the
//     captured lowercase "sec-websocket-extensions", and it is why the order
//     list stores names in captured case rather than canonical case.
//
// Duplicate headers of the same name keep their relative order. A malformed
// head (no request line, or a line without a colon) is returned unchanged.
func reorderHeaderBlock(head []byte, order []string) []byte {
	lines := strings.Split(string(head), "\r\n")
	if len(lines) < 2 {
		return head
	}
	requestLine := lines[0]
	// The split of a well-formed head ends with two empty strings (from the
	// final "\r\n\r\n"); header lines are everything between.
	var headers []string
	for _, ln := range lines[1:] {
		if ln == "" {
			continue
		}
		if !strings.Contains(ln, ":") {
			return head
		}
		headers = append(headers, ln)
	}

	used := make([]bool, len(headers))
	var out []string
	for _, want := range order {
		for i, ln := range headers {
			if used[i] {
				continue
			}
			name, value, ok := strings.Cut(ln, ":")
			if !ok || !strings.EqualFold(strings.TrimSpace(name), want) {
				continue
			}
			used[i] = true
			out = append(out, want+":"+value)
		}
	}
	for i, ln := range headers {
		if !used[i] {
			out = append(out, ln)
		}
	}

	var b strings.Builder
	b.Grow(len(head))
	b.WriteString(requestLine)
	b.WriteString("\r\n")
	for _, ln := range out {
		b.WriteString(ln)
		b.WriteString("\r\n")
	}
	b.WriteString("\r\n")
	return []byte(b.String())
}
