package codexws

import (
	"bufio"
	"bytes"
	"errors"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// fakeConn records everything written to it.
type fakeConn struct {
	net.Conn
	out bytes.Buffer
}

func (c *fakeConn) Write(p []byte) (int, error) { return c.out.Write(p) }
func (c *fakeConn) Close() error                { return nil }

// Go writes request headers alphabetically. This asserts we replay them in the
// order a genuine Codex client uses instead.
func TestHandshakeOrderConnReordersHeaders(t *testing.T) {
	raw := "GET /backend-api/codex/responses HTTP/1.1\r\n" +
		"Host: chatgpt.com\r\n" +
		"User-Agent: Codex Desktop/x\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Extensions: permessage-deflate\r\n" +
		"Sec-WebSocket-Key: abc\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Upgrade: websocket\r\n" +
		"authorization: Bearer tok\r\n" +
		"chatgpt-account-id: acct\r\n" +
		"openai-beta: responses_websockets=2026-02-06\r\n" +
		"originator: Codex Desktop\r\n" +
		"session-id: s\r\n" +
		"thread-id: s\r\n" +
		"version: 1\r\n" +
		"x-client-request-id: s\r\n" +
		"x-codex-beta-features: f\r\n" +
		"x-codex-turn-metadata: {}\r\n" +
		"x-codex-window-id: s:0\r\n" +
		"\r\n"

	inner := &fakeConn{}
	c := newHandshakeOrderConn(inner, handshakeHeaderOrder)
	if _, err := c.Write([]byte(raw)); err != nil {
		t.Fatalf("Write: %v", err)
	}

	got := inner.out.String()
	if !strings.HasPrefix(got, "GET /backend-api/codex/responses HTTP/1.1\r\n") {
		t.Fatalf("request line was altered: %q", got)
	}
	names := headerNames(got)
	want := handshakeHeaderOrder
	if len(names) != len(want) {
		t.Fatalf("got %d headers %v, want %d %v", len(names), names, len(want), want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Errorf("header %d = %q, want %q (full order: %v)", i, names[i], want[i], names)
		}
	}
	// Name casing must be rewritten to the captured spelling — this is what
	// turns gorilla's "Sec-WebSocket-Extensions" into the lowercase form.
	if !strings.Contains(got, "sec-websocket-extensions: permessage-deflate\r\n") {
		t.Error("sec-websocket-extensions was not rewritten to the captured casing")
	}
	if strings.Contains(got, "Sec-WebSocket-Extensions:") {
		t.Error("the canonical-cased extensions header must not survive")
	}
}

// End-to-end against the real producer: build the request exactly as gorilla
// does, let net/http serialize it, and prove that what comes out the other side
// is still a parseable HTTP request with every header intact — and that Go's
// alphabetical order really was replaced by the captured one.
func TestHandshakeOrderConnAgainstRealRequestWrite(t *testing.T) {
	u, err := url.Parse("https://chatgpt.com/backend-api/codex/responses")
	if err != nil {
		t.Fatal(err)
	}
	req := &http.Request{
		Method:     http.MethodGet,
		URL:        u,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     BuildUpstreamHeaders("tok", "acct", "sess", "", "", ""),
		Host:       u.Host,
	}
	// The four headers gorilla owns, written the way gorilla writes them.
	req.Header["Upgrade"] = []string{"websocket"}
	req.Header["Connection"] = []string{"Upgrade"}
	req.Header["Sec-WebSocket-Key"] = []string{"dGhlIHNhbXBsZSBub25jZQ=="}
	req.Header["Sec-WebSocket-Version"] = []string{"13"}
	req.Header["Sec-WebSocket-Extensions"] = []string{
		"permessage-deflate; server_no_context_takeover; client_no_context_takeover"}

	inner := &fakeConn{}
	c := newHandshakeOrderConn(inner, handshakeHeaderOrder)
	if err := req.Write(c); err != nil {
		t.Fatalf("req.Write: %v", err)
	}
	out := inner.out.String()

	// Still a valid HTTP request.
	parsed, err := http.ReadRequest(bufio.NewReader(strings.NewReader(out)))
	if err != nil {
		t.Fatalf("reordered handshake no longer parses: %v\n%s", err, out)
	}
	if parsed.Host != "chatgpt.com" || parsed.URL.Path != "/backend-api/codex/responses" {
		t.Errorf("request line damaged: %s %s", parsed.Host, parsed.URL.Path)
	}
	// Values survived, including the one Go would have canonicalized away.
	if got := parsed.Header.Get("Sec-WebSocket-Key"); got != "dGhlIHNhbXBsZSBub25jZQ==" {
		t.Errorf("Sec-WebSocket-Key = %q", got)
	}
	if got := parsed.Header.Get("Session-Id"); got != "sess" {
		t.Errorf("session-id value lost: %q", got)
	}

	// Regression: writing the UA under a lowercase key alone made net/http fill
	// its dedicated slot with the default, so the handshake carried TWO
	// User-Agent headers — one of them "Go-http-client/1.1".
	if strings.Contains(out, "Go-http-client") {
		t.Errorf("net/http's default User-Agent reached the wire:\n%s", out)
	}
	if n := strings.Count(strings.ToLower(out), "user-agent:"); n != 1 {
		t.Errorf("expected exactly one User-Agent header, got %d:\n%s", n, out)
	}

	names := headerNames(out)
	if len(names) != len(handshakeHeaderOrder) {
		t.Fatalf("got %d headers %v, want the full captured set %v",
			len(names), names, handshakeHeaderOrder)
	}
	for i, want := range handshakeHeaderOrder {
		if names[i] != want {
			t.Fatalf("header %d = %q, want %q\nfull: %v", i, names[i], want, names)
		}
	}
	// Sanity: this order is genuinely different from what Go emits unaided.
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	if reflect.DeepEqual(sorted, names) {
		t.Error("emitted order is alphabetical — the reorder did not take effect")
	}
}

// Only the handshake is rewritten; every subsequent write is a WebSocket frame
// and must pass through byte-for-byte.
func TestHandshakeOrderConnPassesThroughAfterHandshake(t *testing.T) {
	inner := &fakeConn{}
	c := newHandshakeOrderConn(inner, handshakeHeaderOrder)
	if _, err := c.Write([]byte("GET / HTTP/1.1\r\nHost: h\r\n\r\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	inner.out.Reset()

	frame := []byte{0x81, 0x03, 'a', 'b', 'c'}
	if _, err := c.Write(frame); err != nil {
		t.Fatalf("Write frame: %v", err)
	}
	if !bytes.Equal(inner.out.Bytes(), frame) {
		t.Errorf("frame bytes altered: got %v, want %v", inner.out.Bytes(), frame)
	}
}

// Request.Write goes through a bufio.Writer, so the head can in principle
// arrive in pieces. Reordering must still work, and nothing may reach the wire
// until the header block is complete.
func TestHandshakeOrderConnHandlesSplitWrites(t *testing.T) {
	raw := "GET / HTTP/1.1\r\nHost: h\r\nsession-id: s\r\nauthorization: Bearer t\r\n\r\n"
	inner := &fakeConn{}
	c := newHandshakeOrderConn(inner, handshakeHeaderOrder)

	for i := 0; i < len(raw); i += 7 {
		end := i + 7
		if end > len(raw) {
			end = len(raw)
		}
		if _, err := c.Write([]byte(raw[i:end])); err != nil {
			t.Fatalf("Write chunk: %v", err)
		}
		if end < len(raw) && inner.out.Len() != 0 {
			t.Fatalf("bytes leaked before the header block was complete (at %d)", end)
		}
	}
	names := headerNames(inner.out.String())
	want := []string{"Host", "authorization", "session-id"}
	if len(names) != len(want) {
		t.Fatalf("got headers %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Errorf("header %d = %q, want %q", i, names[i], want[i])
		}
	}
}

// Anything we do not recognize as a handshake must be forwarded untouched
// rather than buffered forever.
func TestHandshakeOrderConnGivesUpOnOversizedInput(t *testing.T) {
	inner := &fakeConn{}
	c := newHandshakeOrderConn(inner, handshakeHeaderOrder)
	blob := bytes.Repeat([]byte("x"), maxHandshakeBuffer+1)
	if _, err := c.Write(blob); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if !bytes.Equal(inner.out.Bytes(), blob) {
		t.Errorf("oversized input must be flushed verbatim (%d bytes out, %d in)",
			inner.out.Len(), len(blob))
	}
}

// A header not present in the order list must be kept, not dropped.
func TestReorderHeaderBlockKeepsUnknownHeaders(t *testing.T) {
	head := []byte("GET / HTTP/1.1\r\nsession-id: s\r\nx-something-new: v\r\nauthorization: b\r\n\r\n")
	got := string(reorderHeaderBlock(head, handshakeHeaderOrder))
	if !strings.Contains(got, "x-something-new: v\r\n") {
		t.Errorf("unknown header was dropped: %q", got)
	}
	names := headerNames(got)
	// Known headers first in captured order, unknown ones trailing.
	if names[0] != "authorization" || names[1] != "session-id" || names[2] != "x-something-new" {
		t.Errorf("unexpected order %v", names)
	}
}

func TestReorderHeaderBlockLeavesMalformedInputAlone(t *testing.T) {
	head := []byte("GET / HTTP/1.1\r\nnot-a-header-line\r\n\r\n")
	if got := reorderHeaderBlock(head, handshakeHeaderOrder); !bytes.Equal(got, head) {
		t.Errorf("malformed head must pass through unchanged, got %q", got)
	}
}

func headerNames(head string) []string {
	var out []string
	for _, ln := range strings.Split(head, "\r\n")[1:] {
		if ln == "" {
			continue
		}
		name, _, ok := strings.Cut(ln, ":")
		if !ok {
			continue
		}
		out = append(out, name)
	}
	return out
}

// Guard against the wrapper swallowing a write error from the underlying conn.
func TestHandshakeOrderConnPropagatesWriteError(t *testing.T) {
	inner := &errConn{}
	c := newHandshakeOrderConn(inner, handshakeHeaderOrder)
	if _, err := c.Write([]byte("GET / HTTP/1.1\r\nHost: h\r\n\r\n")); err == nil {
		t.Error("a failing underlying write must surface")
	}
}

type errConn struct{ net.Conn }

func (c *errConn) Write([]byte) (int, error)   { return 0, errors.New("boom") }
func (c *errConn) Close() error                { return nil }
func (c *errConn) SetDeadline(time.Time) error { return nil }
