package codexws

import (
	"bytes"
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

// TestStallBudgetRearmsOnContent is the regression for the first version of
// this fix, which retired the budget on the first content frame and so changed
// nothing in production: a parked turn emits its opening delta within a couple
// of seconds and parks after that, and a budget the delta retires never fires.
// Content must push the deadline forward, not remove it.
func TestStallBudgetRearmsOnContent(t *testing.T) {
	conn := &deltaThenParkConn{gap: 20 * time.Millisecond}
	s := NewSSEStream(conn, SSEStreamOptions{
		ReadTimeout:  time.Hour,
		StallTimeout: 120 * time.Millisecond,
		ContentFree:  contentFreeForTest,
	})

	// Bounded rather than a plain ReadAll: the bug this guards against does not
	// return a wrong answer, it returns nothing at all, and an unbounded read
	// would sit here until the package timeout instead of naming the failure.
	type result struct {
		out []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		out, err := io.ReadAll(s)
		done <- result{out, err}
	}()

	var out []byte
	select {
	case r := <-done:
		out = r.out
		if !errors.Is(r.err, ErrStalled) {
			t.Fatalf("read error = %v, want ErrStalled — the turn parked after its first delta", r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the read never returned: the budget was retired by the first content frame and the parked turn ran forever — this is the production bug verbatim")
	}
	// The delta must still have reached the caller: post-content the turn
	// cannot be failed over, and swallowing what did arrive would turn a
	// truncation into a silent empty response.
	if !bytes.Contains(out, []byte("response.output_text.delta")) {
		t.Fatalf("the content frame never reached the caller: %q", out)
	}
	if s.Terminal() {
		t.Fatal("a parked turn must not report a terminal event")
	}
}

// TestStallBudgetAllowsASlowButLiveTurn is the other half: a turn that keeps
// producing content, each frame arriving inside the budget, must run as long as
// it likes. Total elapsed here exceeds the budget several times over.
func TestStallBudgetAllowsASlowButLiveTurn(t *testing.T) {
	frames := make([]string, 0, 12)
	for i := 0; i < 10; i++ {
		frames = append(frames, `{"type":"response.output_text.delta","delta":"x"}`)
	}
	frames = append(frames, `{"type":"response.completed","response":{"id":"r1"}}`)
	conn := &pacedConn{frames: frames, gap: 20 * time.Millisecond}

	s := NewSSEStream(conn, SSEStreamOptions{
		StallTimeout: 60 * time.Millisecond,
		ContentFree:  contentFreeForTest,
	})
	start := time.Now()
	if _, err := io.ReadAll(s); err != nil {
		t.Fatalf("read: %v, want a clean end", err)
	}
	if elapsed := time.Since(start); elapsed < 120*time.Millisecond {
		t.Fatalf("turn took %s — it did not actually outlive the budget, so this proved nothing", elapsed)
	}
	if !s.Terminal() {
		t.Fatal("terminal event missed: a live turn was cut off by the budget")
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

// deltaThenParkConn reproduces the production shape exactly: the opening
// frames, one real delta a couple of frames in, then keepalives forever.
type deltaThenParkConn struct {
	mu       sync.Mutex
	gap      time.Duration
	deadline time.Time
	n        int
}

func (c *deltaThenParkConn) WriteJSON(any) error              { return nil }
func (c *deltaThenParkConn) WriteMessage(int, []byte) error   { return nil }
func (c *deltaThenParkConn) Ping(time.Time) error             { return nil }
func (c *deltaThenParkConn) SetWriteDeadline(time.Time) error { return nil }
func (c *deltaThenParkConn) Close() error                     { return nil }
func (c *deltaThenParkConn) HandshakeResponse() *http.Response {
	return &http.Response{StatusCode: http.StatusSwitchingProtocols}
}

func (c *deltaThenParkConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadline = t
	return nil
}

func (c *deltaThenParkConn) ReadMessage() (int, []byte, error) {
	c.mu.Lock()
	gap, deadline := c.gap, c.deadline
	c.n++
	n := c.n
	c.mu.Unlock()

	if !deadline.IsZero() && time.Until(deadline) < gap {
		time.Sleep(time.Until(deadline))
		return 0, nil, timeoutErr{}
	}
	time.Sleep(gap)
	switch n {
	case 1:
		return TextMessage, []byte(`{"type":"response.created"}`), nil
	case 2:
		return TextMessage, []byte(`{"type":"response.output_text.delta","delta":"Thinking"}`), nil
	default:
		return TextMessage, []byte(`{"type":"keepalive","sequence_number":1}`), nil
	}
}

// pacedConn replays frames with a fixed gap, honouring the read deadline.
type pacedConn struct {
	mu       sync.Mutex
	frames   []string
	gap      time.Duration
	deadline time.Time
}

func (c *pacedConn) WriteJSON(any) error              { return nil }
func (c *pacedConn) WriteMessage(int, []byte) error   { return nil }
func (c *pacedConn) Ping(time.Time) error             { return nil }
func (c *pacedConn) SetWriteDeadline(time.Time) error { return nil }
func (c *pacedConn) Close() error                     { return nil }
func (c *pacedConn) HandshakeResponse() *http.Response {
	return &http.Response{StatusCode: http.StatusSwitchingProtocols}
}

func (c *pacedConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadline = t
	return nil
}

func (c *pacedConn) ReadMessage() (int, []byte, error) {
	c.mu.Lock()
	gap, deadline := c.gap, c.deadline
	if len(c.frames) == 0 {
		c.mu.Unlock()
		return 0, nil, io.EOF
	}
	next := c.frames[0]
	c.frames = c.frames[1:]
	c.mu.Unlock()

	if !deadline.IsZero() && time.Until(deadline) < gap {
		time.Sleep(time.Until(deadline))
		return 0, nil, timeoutErr{}
	}
	time.Sleep(gap)
	return TextMessage, []byte(next), nil
}

// TestDisarmStallLeavesOnlyTheReadTimeout is the regression for the second half
// of the parked-turn story. The budget is there to convert a park into a
// failover; once the caller has written a byte downstream there is no failover
// left to convert it into, and firing anyway turns a slow turn into a truncated
// one. Production ran a day like that: 141 of 326 truncated streams were a
// committed response cut at the budget.
//
// gap deliberately exceeds ReadTimeout so the read times out on its own — the
// assertion is about which error the timeout is reported as, not whether one
// happens.
func TestDisarmStallLeavesOnlyTheReadTimeout(t *testing.T) {
	conn := &heartbeatConn{gap: 300 * time.Millisecond}
	s := NewSSEStream(conn, SSEStreamOptions{
		ReadTimeout:  100 * time.Millisecond,
		StallTimeout: 20 * time.Millisecond,
		ContentFree:  contentFreeForTest,
	})
	s.DisarmStall()

	_, err := io.ReadAll(s)
	if errors.Is(err, ErrStalled) {
		t.Fatal("a disarmed budget still ended the turn as a stall — post-commit that is a truncation the client pays for and nobody can act on")
	}
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("read error = %v, want the plain read timeout", err)
	}
	if !errors.Is(s.Err(), err) {
		t.Fatalf("Err() = %v, want the same %v", s.Err(), err)
	}
}

// TestStallStaysArmedUntilDisarmed pins the default: a stream nobody disarms
// keeps the budget, because the withhold window is open until the caller says
// otherwise.
func TestStallStaysArmedUntilDisarmed(t *testing.T) {
	conn := &heartbeatConn{gap: 300 * time.Millisecond}
	s := NewSSEStream(conn, SSEStreamOptions{
		ReadTimeout:  100 * time.Millisecond,
		StallTimeout: 20 * time.Millisecond,
		ContentFree:  contentFreeForTest,
	})

	if _, err := io.ReadAll(s); !errors.Is(err, ErrStalled) {
		t.Fatalf("read error = %v, want ErrStalled", err)
	}
}
