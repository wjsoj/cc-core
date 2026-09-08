package codexws

import (
	"encoding/json"
	"errors"
	"io"
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

// SSEStreamOptions configures one turn's worth of adaptation.
type SSEStreamOptions struct {
	// ReadTimeout bounds the wait for each individual frame. It is a safety
	// net, not a turn budget: the backend parks a queued turn and heartbeats
	// with `keepalive` frames roughly every 30s, so anything under about a
	// minute will cut off turns that were merely waiting for capacity. Zero
	// disables the deadline, which leaves a silently-dead socket able to hang
	// the request until the client gives up.
	ReadTimeout time.Duration
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
}

// NewSSEStream wraps conn for the duration of one turn.
func NewSSEStream(conn Conn, opt SSEStreamOptions) *SSEStream {
	return &SSEStream{conn: conn, opt: opt}
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
// as nil — a clean terminal event is not an error.
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
		if s.opt.ReadTimeout > 0 {
			if err := s.conn.SetReadDeadline(time.Now().Add(s.opt.ReadTimeout)); err != nil {
				return err
			}
		}
		mt, data, err := s.conn.ReadMessage()
		if err != nil {
			return err
		}
		if mt != TextMessage || len(data) == 0 {
			// Binary and control frames carry nothing the SSE pipeline can
			// read. Skipping rather than erroring keeps an unrecognised future
			// frame type from breaking a turn that is otherwise fine.
			continue
		}
		s.frames++
		typ := eventType(data)
		if terminalEventTypes[typ] {
			s.terminal = true
			s.done = true
		}
		s.pending = appendSSEEvent(s.pending, typ, data)
		return nil
	}
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
