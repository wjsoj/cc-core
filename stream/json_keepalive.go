package stream

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// DefaultJSONKeepaliveInterval sits well under the 60s idle timeout common to
// HTTP clients and intermediaries — the timeout image generation kept hitting.
const DefaultJSONKeepaliveInterval = 10 * time.Second

// JSONKeepalive keeps a non-streaming JSON response alive through a long
// silent wait upstream.
//
// A non-streaming reply is assembled first and sent second, so the connection
// is idle for the whole upstream turn. That is harmless for text, which lands
// in seconds, and fatal for image generation, which runs 30–120s: the client's
// idle timeout fires at 60s and the user sees a disconnect. Start commits a
// 200 with a JSON content type and writes one space per Interval; JSON permits
// leading whitespace, so every decoder skips it.
//
// Committing gives up the status code: after Start, a failure can only be
// reported in the body (Fail). Callers start it once a refusal is no longer
// likely — when upstream has begun generating, or after a fixed grace period
// longer than a refusal takes to arrive.
//
// Safe for concurrent use: Start may run from a timer goroutine while the
// caller is still reading upstream. Deliver and Fail stop the heartbeat and
// wait for it before writing, so the caller owns the writer from then on.
type JSONKeepalive struct {
	ctx      context.Context
	w        http.ResponseWriter
	Interval time.Duration

	mu      sync.Mutex
	started bool
	stopped bool
	stop    chan struct{}
	done    chan struct{}
}

// NewJSONKeepalive binds a keepalive to one response. ctx ends the heartbeat
// when the client goes away.
func NewJSONKeepalive(ctx context.Context, w http.ResponseWriter) *JSONKeepalive {
	return &JSONKeepalive{ctx: ctx, w: w, Interval: DefaultJSONKeepaliveInterval}
}

// Start commits the response and begins the heartbeat. commit runs once,
// under the lock and before the status is written, for the caller to set
// headers or mark the attempt committed. Idempotent; a no-op after Stop.
func (k *JSONKeepalive) Start(commit func()) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.started || k.stopped {
		return
	}
	k.started = true
	if commit != nil {
		commit()
	}
	k.w.Header().Set("Content-Type", "application/json")
	k.w.WriteHeader(http.StatusOK)
	// A body byte now, not just the status: a compressing proxy in front
	// (Caddy's encode) holds the headers until the first body write, so a bare
	// WriteHeader+Flush reaches nobody until the first tick.
	_, _ = k.w.Write([]byte(" "))
	k.flush()
	k.stop, k.done = make(chan struct{}), make(chan struct{})
	go k.run()
}

func (k *JSONKeepalive) flush() {
	if f, ok := k.w.(http.Flusher); ok {
		f.Flush()
	}
}

func (k *JSONKeepalive) run() {
	defer close(k.done)
	t := time.NewTicker(k.Interval)
	defer t.Stop()
	for {
		select {
		case <-k.stop:
			return
		case <-k.ctx.Done():
			return
		case <-t.C:
			k.mu.Lock()
			if !k.stopped {
				_, _ = k.w.Write([]byte(" "))
				k.flush()
			}
			k.mu.Unlock()
		}
	}
}

// Committed reports whether the status line has gone out.
func (k *JSONKeepalive) Committed() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.started
}

// Stop ends the heartbeat (waiting for it) and prevents a later Start, then
// reports whether the response had been committed. Idempotent.
func (k *JSONKeepalive) Stop() bool {
	k.mu.Lock()
	if k.stopped {
		started := k.started
		k.mu.Unlock()
		return started
	}
	k.stopped = true
	started := k.started
	k.mu.Unlock()
	if started {
		close(k.stop)
		<-k.done
	}
	return started
}

// Deliver writes the final body. Uncommitted, it is an ordinary 200 JSON reply
// with setHeaders applied first.
func (k *JSONKeepalive) Deliver(body []byte, setHeaders func()) {
	if !k.Stop() {
		if setHeaders != nil {
			setHeaders()
		}
		k.w.Header().Set("Content-Type", "application/json")
		k.w.WriteHeader(http.StatusOK)
	}
	_, _ = k.w.Write(body)
}

// Fail reports an error after the 200 is committed, as an OpenAI-shaped error
// object in the body. Only meaningful once Committed; the status cannot change.
func (k *JSONKeepalive) Fail(code, message string) {
	k.Stop()
	body, _ := json.Marshal(map[string]any{"error": map[string]any{
		"message": message, "type": "server_error", "code": code,
	}})
	_, _ = k.w.Write(body)
}
