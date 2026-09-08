package codexws

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// scriptedConn is a scripted Conn: it hands back queued frames, then the queued
// error (io.EOF by default), and records what was written to it.
type scriptedConn struct {
	mu      sync.Mutex
	frames  []string
	readErr error
	writes  [][]byte
	pings   int
	pingErr error
	closed  bool
}

func newScriptedConn(frames ...string) *scriptedConn { return &scriptedConn{frames: frames} }

func (f *scriptedConn) WriteJSON(any) error { return nil }
func (f *scriptedConn) WriteMessage(_ int, d []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes = append(f.writes, append([]byte(nil), d...))
	return nil
}

func (f *scriptedConn) ReadMessage() (int, []byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.frames) == 0 {
		if f.readErr != nil {
			return 0, nil, f.readErr
		}
		return 0, nil, io.EOF
	}
	next := f.frames[0]
	f.frames = f.frames[1:]
	return TextMessage, []byte(next), nil
}

func (f *scriptedConn) Ping(time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pings++
	return f.pingErr
}
func (f *scriptedConn) SetReadDeadline(time.Time) error  { return nil }
func (f *scriptedConn) SetWriteDeadline(time.Time) error { return nil }
func (f *scriptedConn) HandshakeResponse() *http.Response {
	return &http.Response{StatusCode: http.StatusSwitchingProtocols}
}
func (f *scriptedConn) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func (f *scriptedConn) isClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

func drain(t *testing.T, r io.Reader) string {
	t.Helper()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	return string(b)
}

func TestSSEStreamRendersEventAndDataLines(t *testing.T) {
	conn := newScriptedConn(
		`{"type":"response.created","id":"resp_1"}`,
		`{"type":"response.output_text.delta","delta":"hi"}`,
		`{"type":"response.completed","usage":{"input_tokens":3}}`,
	)
	s := NewSSEStream(conn, SSEStreamOptions{})
	got := drain(t, s)

	want := "event: response.created\ndata: {\"type\":\"response.created\",\"id\":\"resp_1\"}\n\n" +
		"event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"hi\"}\n\n" +
		"event: response.completed\ndata: {\"type\":\"response.completed\",\"usage\":{\"input_tokens\":3}}\n\n"
	if got != want {
		t.Fatalf("rendered SSE mismatch:\n got %q\nwant %q", got, want)
	}
	if !s.Terminal() {
		t.Fatal("Terminal() = false after response.completed")
	}
	if s.Frames() != 3 {
		t.Fatalf("Frames() = %d, want 3", s.Frames())
	}
	if err := s.Err(); err != nil {
		t.Fatalf("Err() = %v, want nil", err)
	}
	if conn.isClosed() {
		t.Fatal("SSEStream closed the connection; the pool owns it")
	}
}

// A turn that stops before a terminal event must be reported as non-terminal so
// the caller discards the socket instead of pooling one with queued leftovers.
func TestSSEStreamTruncatedTurnIsNotTerminal(t *testing.T) {
	conn := newScriptedConn(`{"type":"response.output_text.delta","delta":"partial"}`)
	conn.readErr = errors.New("websocket: close 1006 (abnormal closure)")
	s := NewSSEStream(conn, SSEStreamOptions{})

	b, err := io.ReadAll(s)
	if err == nil {
		t.Fatal("ReadAll succeeded on a truncated turn")
	}
	if !strings.Contains(string(b), "partial") {
		t.Fatalf("pre-break bytes lost: %q", b)
	}
	if s.Terminal() {
		t.Fatal("Terminal() = true without a terminal event")
	}
	if s.Err() == nil {
		t.Fatal("Err() = nil after an abnormal close")
	}
}

// The adapter's terminal set has to match the HTTP relay's, or a turn ending on
// the odd one out is either logged as truncated or hangs. response.done is the
// one that other implementations add and ours must not.
func TestIsTerminalEventMatchesRelaySet(t *testing.T) {
	for _, typ := range []string{"response.completed", "response.failed", "response.incomplete", "response.cancelled", "response.canceled"} {
		if !IsTerminalEvent([]byte(`{"type":"` + typ + `"}`)) {
			t.Errorf("IsTerminalEvent(%s) = false", typ)
		}
	}
	for _, typ := range []string{"response.done", "response.created", "keepalive", "response.output_text.delta"} {
		if IsTerminalEvent([]byte(`{"type":"` + typ + `"}`)) {
			t.Errorf("IsTerminalEvent(%s) = true", typ)
		}
	}
}

func dialer(conn Conn) DialFunc {
	return func(context.Context) (Conn, *http.Response, error) {
		return conn, &http.Response{StatusCode: http.StatusSwitchingProtocols}, nil
	}
}

func TestPoolReusesIdleConnection(t *testing.T) {
	p := NewPool(PoolConfig{})
	defer p.Close()
	first := newScriptedConn()

	l1, err := p.Acquire(context.Background(), "acct|sess", dialer(first))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if l1.Reused {
		t.Fatal("first acquire reported Reused")
	}
	l1.Release(true)

	l2, err := p.Acquire(context.Background(), "acct|sess", dialer(newScriptedConn()))
	if err != nil {
		t.Fatalf("Acquire (2): %v", err)
	}
	if !l2.Reused {
		t.Fatal("second acquire did not reuse the pooled connection")
	}
	if l2.Conn != Conn(first) {
		t.Fatal("second acquire returned a different connection")
	}
	if first.pings != 1 {
		t.Fatalf("reuse probe pings = %d, want 1", first.pings)
	}
	l2.Release(true)
}

// A dead pooled socket must be detected by the probe rather than by burning the
// turn's first read.
func TestPoolProbeReplacesDeadConnection(t *testing.T) {
	p := NewPool(PoolConfig{})
	defer p.Close()
	dead := newScriptedConn()
	dead.pingErr = errors.New("broken pipe")

	l1, _ := p.Acquire(context.Background(), "k", dialer(dead))
	l1.Release(true)

	fresh := newScriptedConn()
	l2, err := p.Acquire(context.Background(), "k", dialer(fresh))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if l2.Reused {
		t.Fatal("leased a connection whose probe failed")
	}
	if !dead.isClosed() {
		t.Fatal("dead connection was not closed")
	}
	if l2.Conn != Conn(fresh) {
		t.Fatal("did not dial a replacement")
	}
	l2.Release(true)
}

// Concurrent turns on one conversation get their own socket instead of
// serializing: gorilla allows one reader per connection.
func TestPoolConcurrentTurnGetsEphemeralConnection(t *testing.T) {
	p := NewPool(PoolConfig{})
	defer p.Close()
	pooled := newScriptedConn()
	l1, _ := p.Acquire(context.Background(), "k", dialer(pooled))

	extra := newScriptedConn()
	l2, err := p.Acquire(context.Background(), "k", dialer(extra))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if l2.Reused {
		t.Fatal("handed out a busy connection")
	}
	// The ephemeral one closes on release and never displaces the pooled entry.
	l2.Release(true)
	if !extra.isClosed() {
		t.Fatal("ephemeral connection was not closed on release")
	}
	if p.Len() != 1 {
		t.Fatalf("pool holds %d entries, want 1", p.Len())
	}
	l1.Release(true)
}

// keep=false is what every abnormal turn end passes. The socket may still have
// that turn's frames queued, so it must not survive into the next turn.
func TestPoolReleaseWithoutKeepClosesAndEvicts(t *testing.T) {
	p := NewPool(PoolConfig{})
	defer p.Close()
	conn := newScriptedConn()
	l, _ := p.Acquire(context.Background(), "k", dialer(conn))
	l.Release(false)

	if !conn.isClosed() {
		t.Fatal("connection survived a keep=false release")
	}
	if p.Len() != 0 {
		t.Fatalf("pool holds %d entries after eviction, want 0", p.Len())
	}
}

func TestPoolRetiresConnectionPastMaxAge(t *testing.T) {
	p := NewPool(PoolConfig{MaxAge: time.Nanosecond})
	defer p.Close()
	old := newScriptedConn()
	l, _ := p.Acquire(context.Background(), "k", dialer(old))
	time.Sleep(2 * time.Millisecond)
	l.Release(true)

	if !old.isClosed() {
		t.Fatal("connection past MaxAge was pooled instead of retired")
	}
	if p.Len() != 0 {
		t.Fatalf("pool holds %d entries, want 0", p.Len())
	}
}

func TestPoolIdleTTLClosesConnection(t *testing.T) {
	p := NewPool(PoolConfig{IdleTTL: 5 * time.Millisecond})
	defer p.Close()
	conn := newScriptedConn()
	l, _ := p.Acquire(context.Background(), "k", dialer(conn))
	l.Release(true)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if conn.isClosed() {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if !conn.isClosed() {
		t.Fatal("idle connection was never closed")
	}
	if p.Len() != 0 {
		t.Fatalf("pool holds %d entries after the idle sweep, want 0", p.Len())
	}
}

// An empty key names no conversation, so there is nothing to reuse it for and
// pooling it under "" would hand one conversation's socket to another.
func TestPoolEmptyKeyIsEphemeral(t *testing.T) {
	p := NewPool(PoolConfig{})
	defer p.Close()
	conn := newScriptedConn()
	l, err := p.Acquire(context.Background(), "", dialer(conn))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if p.Len() != 0 {
		t.Fatalf("empty key was pooled (%d entries)", p.Len())
	}
	l.Release(true)
	if !conn.isClosed() {
		t.Fatal("ephemeral connection survived release")
	}
}
