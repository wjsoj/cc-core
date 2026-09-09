package codexws

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

// contentFreeForTest mirrors the predicate the proxies pass in: the opening
// declarations plus the keepalive heartbeat carry nothing a client can see.
func contentFreeForTest(payload []byte) bool {
	var ev struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(payload, &ev) != nil {
		return false
	}
	switch ev.Type {
	case "response.created", "response.in_progress", "keepalive",
		"response.output_item.added", "response.content_part.added":
		return true
	}
	return false
}

// heartbeatConn parks the turn exactly the way the backend does: it never
// stops answering, it just never says anything. Each read blocks for gap and
// then returns another keepalive, so the per-frame deadline is reset forever
// and only a stall budget can end the turn.
type heartbeatConn struct {
	mu       sync.Mutex
	gap      time.Duration
	deadline time.Time
	reads    int
}

func (h *heartbeatConn) WriteJSON(any) error            { return nil }
func (h *heartbeatConn) WriteMessage(int, []byte) error { return nil }
func (h *heartbeatConn) Ping(time.Time) error           { return nil }
func (h *heartbeatConn) SetWriteDeadline(time.Time) error {
	return nil
}
func (h *heartbeatConn) HandshakeResponse() *http.Response {
	return &http.Response{StatusCode: http.StatusSwitchingProtocols}
}
func (h *heartbeatConn) Close() error { return nil }

func (h *heartbeatConn) SetReadDeadline(t time.Time) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.deadline = t
	return nil
}

func (h *heartbeatConn) ReadMessage() (int, []byte, error) {
	h.mu.Lock()
	gap, deadline := h.gap, h.deadline
	h.reads++
	n := h.reads
	h.mu.Unlock()
	// Honour the deadline the way a real socket does, so a budget that expires
	// mid-wait surfaces as a timeout rather than another heartbeat.
	if !deadline.IsZero() && time.Until(deadline) < gap {
		time.Sleep(time.Until(deadline))
		return 0, nil, timeoutErr{}
	}
	time.Sleep(gap)
	_ = n
	return TextMessage, []byte(`{"type":"keepalive","sequence_number":1}`), nil
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

var _ net.Error = timeoutErr{}

// TestStallBudgetEndsAParkedTurn is the regression for ten hours of production
// hangs: keepalives every gap keep resetting the per-frame deadline, so without
// a stall budget this read never returns and 6.8% of turns sat until the client
// gave up at ~600s.
func TestStallBudgetEndsAParkedTurn(t *testing.T) {
	conn := &heartbeatConn{gap: 20 * time.Millisecond}
	s := NewSSEStream(conn, SSEStreamOptions{
		ReadTimeout:  time.Hour, // deliberately useless, as in production
		StallTimeout: 120 * time.Millisecond,
		ContentFree:  contentFreeForTest,
	})

	_, err := io.ReadAll(s)
	if !errors.Is(err, ErrStalled) {
		t.Fatalf("read error = %v, want ErrStalled", err)
	}
	if s.Terminal() {
		t.Fatal("a parked turn must not report a terminal event")
	}
	if !errors.Is(s.Err(), ErrStalled) {
		t.Fatalf("Err() = %v, want ErrStalled — this is what keeps the connection out of the pool", s.Err())
	}
}

// TestStallBudgetRetiresOnFirstContent is the other half: a turn that opens
// slowly but does produce output must be allowed to run past the budget, or
// the fix trades a hang for a truncation.
func TestStallBudgetRetiresOnFirstContent(t *testing.T) {
	conn := newScriptedConn(
		`{"type":"response.created"}`,
		`{"type":"keepalive","sequence_number":1}`,
		`{"type":"response.output_text.delta","delta":"hi"}`,
		`{"type":"response.completed","response":{"id":"r1"}}`,
	)
	s := NewSSEStream(conn, SSEStreamOptions{
		StallTimeout: 50 * time.Millisecond,
		ContentFree:  contentFreeForTest,
	})

	// Drain the content-free opening, then sleep past the budget before reading
	// the rest: once content has arrived the budget must no longer apply.
	buf := make([]byte, 4096)
	if _, err := s.Read(buf); err != nil {
		t.Fatalf("first read: %v", err)
	}
	for i := 0; i < 2; i++ {
		if _, err := s.Read(buf); err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
	}
	time.Sleep(80 * time.Millisecond)
	if _, err := s.Read(buf); err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("read after budget elapsed: %v, want the turn to continue", err)
	}
	if !s.Terminal() {
		t.Fatal("terminal event missed — the budget must retire on content, not end the turn")
	}
	if s.Err() != nil {
		t.Fatalf("Err() = %v, want nil", s.Err())
	}
}

// TestStallBudgetDisabledByZero pins the opt-out, because the config default
// has to be able to restore the old behaviour without a code change.
func TestStallBudgetDisabledByZero(t *testing.T) {
	conn := newScriptedConn(`{"type":"keepalive","sequence_number":1}`)
	s := NewSSEStream(conn, SSEStreamOptions{ContentFree: contentFreeForTest})
	if _, err := io.ReadAll(s); err != nil {
		t.Fatalf("read: %v, want a clean EOF", err)
	}
	if s.Err() != nil {
		t.Fatalf("Err() = %v, want nil", s.Err())
	}
}

// TestStallErrorOnlyClaimsTimeouts guards the classification: a socket that
// dies of something other than a deadline must keep its own error, or a real
// transport fault gets laundered into a capacity shed and retried forever.
func TestStallErrorOnlyClaimsTimeouts(t *testing.T) {
	conn := newScriptedConn()
	conn.readErr = errors.New("connection reset by peer")
	s := NewSSEStream(conn, SSEStreamOptions{
		StallTimeout: time.Nanosecond, // already expired
		ContentFree:  contentFreeForTest,
	})
	time.Sleep(time.Millisecond)
	if _, err := io.ReadAll(s); errors.Is(err, ErrStalled) {
		t.Fatal("a reset was reported as a stall")
	}
}
