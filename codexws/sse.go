package codexws

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// Rendering an upstream WebSocket turn as the SSE byte stream the HTTP path
// already parses.
//
// The two Codex transports carry the same events; only the envelope differs.
// Over HTTP the backend writes
//
//	event: response.output_text.delta
//	data: {"type":"response.output_text.delta",...}
//
// and over the WebSocket it sends that same JSON object as one text message,
// with no event line because a WS message needs no framing. So an adapter that
// re-adds the two SSE lines lets an entire HTTP-shaped response pipeline —
// line reader, shed classification, usage extraction, keepalive relay, chat
// bridge — consume a WebSocket turn without knowing it is one.
//
// This is what makes WebSocket egress a transport swap rather than a second
// implementation of the response path. Writing a parallel WS-native relay would
// mean maintaining two copies of the shed-withholding and usage-accounting
// rules, which is precisely where a divergence would be both easy to introduce
// and invisible until it cost money.

// terminalEventTypes are the frame types that end a turn.
//
// This set is deliberately identical to the one the HTTP relay uses to decide
// `sawTerminal`. If the two disagree, every turn ending on the extra type is
// logged as a truncated stream (the adapter stopped, the relay never saw its
// terminal) or hangs until the read deadline (the relay stopped, the adapter
// kept waiting). `response.done` is NOT here for that reason: some clients
// treat it as terminal, our relay does not, and adding it on one side only is
// exactly the failure above.
var terminalEventTypes = map[string]bool{
	"response.completed":  true,
	"response.failed":     true,
	"response.incomplete": true,
	"response.cancelled":  true,
	"response.canceled":   true,
}

// IsTerminalEvent reports whether a Codex event payload ends the turn.
func IsTerminalEvent(payload []byte) bool {
	return terminalEventTypes[eventType(payload)]
}

func eventType(payload []byte) string {
	var ev struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(payload, &ev) != nil {
		return ""
	}
	return ev.Type
}

// ErrStalled ends a turn that ran its whole StallTimeout without producing a
// single content-bearing frame. It is deliberately distinct from a read
// timeout: a stalled turn is one the backend accepted and then never
// scheduled, which is a capacity refusal wearing a heartbeat, and the caller
// should withhold it and fail over rather than surface it.
var ErrStalled = errors.New("codexws: upstream produced no content within the stall budget")

// SSEStreamOptions configures one turn's worth of adaptation.
type SSEStreamOptions struct {
	// ReadTimeout bounds the wait for each individual frame. It is a safety
	// net, not a turn budget: the backend parks a queued turn and heartbeats
	// with `keepalive` frames roughly every 30s, so anything under about a
	// minute will cut off turns that were merely waiting for capacity. Zero
	// disables the deadline, which leaves a silently-dead socket able to hang
	// the request until the client gives up.
	ReadTimeout time.Duration

	// StallTimeout bounds the gap between content-bearing frames, and it
	// exists because ReadTimeout cannot bound that at all.
	//
	// When the backend cannot schedule a turn over the WebSocket it does not
	// shed it the way the HTTP transport does — it parks the turn and
	// heartbeats `keepalive` about every 30s, indefinitely. Every one of those
	// frames resets the per-frame deadline, so ReadTimeout never fires however
	// large or small it is set: the socket is not idle, it is just useless.
	// Production ran ten hours that way. 6.8% of turns sat through keepalives
	// until the client gave up at ~600s, none of them ever failed over, and
	// the withheld-shed telemetry that had logged 1116 rescued turns in a
	// single pre-WebSocket hour recorded exactly zero.
	//
	// It bounds the gap and not just the opening because the first version of
	// this bounded only the opening and changed nothing. A parked turn is not
	// silent from the start: it emits its opening frames and a first reasoning
	// delta within a couple of seconds — measured at 1.6-6.3s — and parks
	// after that. A budget the first delta retires is a budget that never
	// fires. Rearming on each content frame covers both, and the caller still
	// separates them, because whether anything reached the client is what
	// decides between an invisible failover and a truncation the client
	// retries.
	//
	// Size it against total turn duration, which is the ceiling on any gap
	// inside one: across 345 successful turns the slowest ran 104s end to end
	// and p99 was 75s, so a gap beyond about two minutes cannot belong to a
	// turn that was going to finish.
	//
	// Zero disables the budget and restores the hang.
	StallTimeout time.Duration

	// ContentFree classifies a frame payload as carrying nothing the client
	// could see, and so nothing that forecloses a retry elsewhere. The budget
	// above is rearmed by every frame this rejects, and untouched by every
	// frame it accepts.
	//
	// It is supplied by the caller rather than hardcoded here so that it stays
	// the same predicate the caller's own withhold logic uses. If the two
	// disagree, this stream can abort a turn whose opening frames the caller
	// had already committed to the client — a failover that is no longer
	// invisible. Nil treats every frame as content, which retires the budget
	// on the first frame of any kind.
	ContentFree func(payload []byte) bool
}

// SSEStream adapts one turn of upstream WebSocket frames into SSE bytes.
//
// It reads until a terminal event, which it emits before reporting io.EOF. The
// underlying Conn is NEVER closed here — the connection outlives the turn and
// belongs to whoever leased it, which is the entire point of pooling it.
type SSEStream struct {
	conn Conn
	opt  SSEStreamOptions

	mu       sync.Mutex
	pending  []byte
	done     bool
	terminal bool
	frames   int
	err      error
	// stallAt is the instant the turn is abandoned if no content has arrived by
	// then. Every content frame pushes it forward. Zero when the caller set no
	// StallTimeout, and a zero value is what every check below tests, so an
	// unset budget costs nothing.
	stallAt time.Time
}

// NewSSEStream wraps conn for the duration of one turn.
func NewSSEStream(conn Conn, opt SSEStreamOptions) *SSEStream {
	s := &SSEStream{conn: conn, opt: opt}
	if opt.StallTimeout > 0 {
		s.stallAt = time.Now().Add(opt.StallTimeout)
	}
	return s
}

// Terminal reports whether the turn ended on a terminal event. A false here
// after the stream is drained means the socket stopped mid-turn and must not be
// returned to a pool: the next turn on it would read this turn's leftovers.
func (s *SSEStream) Terminal() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.terminal
}

// Frames reports how many upstream frames were rendered. Zero distinguishes "the
// socket was dead on arrival" from "the turn ran and then broke", which is what
// decides whether a reused connection is worth retrying on a fresh one.
func (s *SSEStream) Frames() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.frames
}

// Err returns the read error that ended the stream, if any. io.EOF is reported
// as nil — a clean terminal event is not an error. ErrStalled is reported as
// itself, which is also what keeps a parked connection out of the pool.
func (s *SSEStream) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if errors.Is(s.err, io.EOF) {
		return nil
	}
	return s.err
}

func (s *SSEStream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	for len(s.pending) == 0 {
		if s.done {
			if s.err != nil {
				return 0, s.err
			}
			return 0, io.EOF
		}
		if err := s.fillLocked(); err != nil {
			s.done = true
			s.err = err
			if len(s.pending) == 0 {
				return 0, err
			}
			break
		}
	}

	n := copy(p, s.pending)
	s.pending = s.pending[n:]
	return n, nil
}

// fillLocked pulls one upstream frame and renders it into pending.
func (s *SSEStream) fillLocked() error {
	for {
		// The stall budget has to bound the read as well as the frames, or a
		// backend that parks a turn and then stops heartbeating too would sit
		// here for the whole ReadTimeout. Whichever deadline comes first wins.
		if deadline, ok := s.readDeadlineLocked(); ok {
			if err := s.conn.SetReadDeadline(deadline); err != nil {
				return err
			}
		}
		mt, data, err := s.conn.ReadMessage()
		if err != nil {
			return s.classifyReadErrLocked(err)
		}
		if mt != TextMessage || len(data) == 0 {
			// Binary and control frames carry nothing the SSE pipeline can
			// read. Skipping rather than erroring keeps an unrecognised future
			// frame type from breaking a turn that is otherwise fine.
			continue
		}
		s.frames++
		typ := eventType(data)
		if err := s.noteStallProgressLocked(data); err != nil {
			return err
		}
		if terminalEventTypes[typ] {
			s.terminal = true
			s.done = true
		}
		s.pending = appendSSEEvent(s.pending, typ, data)
		return nil
	}
}

// readDeadlineLocked picks the earlier of the per-frame deadline and what is
// left of the stall budget.
func (s *SSEStream) readDeadlineLocked() (time.Time, bool) {
	var deadline time.Time
	if s.opt.ReadTimeout > 0 {
		deadline = time.Now().Add(s.opt.ReadTimeout)
	}
	if !s.stallAt.IsZero() && (deadline.IsZero() || s.stallAt.Before(deadline)) {
		deadline = s.stallAt
	}
	return deadline, !deadline.IsZero()
}

// classifyReadErrLocked names a read that timed out while the stall budget was
// still running for what it is. The distinction is what the caller keys its
// failover on, and a bare i/o timeout would send a parked turn down the
// truncated-stream path instead.
func (s *SSEStream) classifyReadErrLocked(err error) error {
	if s.stallAt.IsZero() || time.Now().Before(s.stallAt) {
		return err
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return ErrStalled
	}
	return err
}

// noteStallProgressLocked rearms the stall budget on every content-bearing
// frame, and abandons the turn when a content-free one arrives past it.
//
// Checking on arrival matters as much as the deadline above: a keepalive every
// 30s keeps resetting the read deadline, so without this a parked turn is
// perfectly capable of never once reaching it.
func (s *SSEStream) noteStallProgressLocked(data []byte) error {
	if s.stallAt.IsZero() {
		return nil
	}
	if s.opt.ContentFree == nil || !s.opt.ContentFree(data) {
		s.stallAt = time.Now().Add(s.opt.StallTimeout)
		return nil
	}
	if !time.Now().Before(s.stallAt) {
		return ErrStalled
	}
	return nil
}

// appendSSEEvent renders one frame as an SSE event. The event line is emitted
// whenever the frame declares a type, because the HTTP backend emits one and
// downstream Codex clients read it; a frame with no type degrades to a bare
// data line rather than inventing an event name.
func appendSSEEvent(dst []byte, typ string, payload []byte) []byte {
	if typ != "" {
		dst = append(dst, "event: "...)
		dst = append(dst, typ...)
		dst = append(dst, '\n')
	}
	dst = append(dst, "data: "...)
	dst = append(dst, payload...)
	dst = append(dst, '\n', '\n')
	return dst
}
