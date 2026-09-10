package stream

import (
	"errors"
	"io"
	"sync"
	"time"
)

// RelayResult reports the outcome of a Relay so the caller can choose between a
// transparent retry (nothing reached the client yet — WroteAny is false) and a
// logged give-up (bytes already committed downstream — uninterruptible).
type RelayResult struct {
	SawTerminal bool // a terminal event was observed (Next reported terminal=true)
	// WroteAny reports whether any CONTENT reached the client — the question a
	// failover decision turns on. Keepalive bytes do not set it.
	WroteAny bool
	// HeadersSent reports whether ANY byte went out, keepalive included, so the
	// HTTP status and headers are no longer the caller's to choose. With
	// PreOutputKeepalive on, a late failure must be surfaced in band.
	HeadersSent bool
	Bytes       int64 // bytes written downstream (diagnostics)
	Err         error // underlying read error when the stream broke early; nil on clean terminal
}

// RelayOptions configures Relay. Next supplies framing + per-chunk transform
// (model rewrite, usage accumulation, terminal detection); Relay owns the
// resilience machinery (lazy header commit, keepalive, write serialization).
type RelayOptions struct {
	// Next pulls the next chunk to emit. It returns:
	//   out      — bytes to write downstream (nil/empty = nothing to write this call),
	//   terminal — whether this chunk is the stream's terminal event,
	//   err      — io.EOF at clean end of stream, or a read error.
	// The caller owns framing (e.g. an SSEScanner or a raw line reader), the
	// per-chunk rewrite, and usage accounting inside this closure. Relay never
	// inspects payload contents.
	Next func() (out []byte, terminal bool, err error)

	// Commit is invoked exactly once, under the write lock, immediately before
	// the first byte is written downstream. Use it to commit response headers
	// lazily so a break before any output can be retried by the caller. May be
	// nil (e.g. when headers were already committed upstream).
	Commit func()

	// KeepaliveIdle: after this much downstream silence (measured only once the
	// stream has started — i.e. after the first real byte, so the pre-first-byte
	// window stays write-free and therefore retryable), KeepalivePayload is
	// written to keep intermediaries from cutting the connection. Zero disables
	// keepalive.
	KeepaliveIdle time.Duration

	// KeepalivePayload is the raw bytes emitted as a keepalive (e.g. an SSE
	// comment ":\n\n" or a synthetic ping event). Required when KeepaliveIdle>0.
	KeepalivePayload []byte

	// PreOutputKeepalive starts the keepalive BEFORE the first real byte.
	//
	// Off by default, and the default is the conservative one: a caller that
	// buffers a preamble to keep a failover available gets a completely
	// write-free window, so a rollback is invisible to the client and the HTTP
	// status is still ours to choose.
	//
	// The cost of that window is silence, and under an upstream capacity storm
	// the silence is long. Measured against production: a bare direct call is
	// told "server_is_overloaded" 1.9 seconds in and can back off on its own,
	// while the same turn through a failing-over proxy leaves the socket silent
	// for tens of seconds — indistinguishable, from the client's side, from a
	// hang. Turning this on trades the HTTP status for a live connection: the
	// caller must surface a late failure as an in-band error instead.
	//
	// Failover itself is NOT foreclosed. Keepalive bytes do not set WroteAny —
	// only real content does — so "has anything the client can use gone out?"
	// still answers correctly.
	PreOutputKeepalive bool
}

// Relay copies a stream to w (flushing via flush after each write, if non-nil),
// applying lazy header commit + keepalive + terminal/EOF tracking. It is the
// shared core behind the Anthropic and Codex SSE relays in the proxy apps.
//
// A clean end with no terminal event observed is reported as
// Err == io.ErrUnexpectedEOF (the stream was truncated). A clean end after a
// terminal event reports Err == nil.
func Relay(w io.Writer, flush func(), opt RelayOptions) RelayResult {
	var res RelayResult
	var mu sync.Mutex
	committed := false
	lastWrite := time.Now()

	// Two different questions, kept apart:
	//   committed  — have any bytes (keepalive included) gone out, so the HTTP
	//                status and headers are no longer ours to choose?
	//   WroteAny   — has any CONTENT gone out, so a failover would be visible?
	// They were one flag while the keepalive could not run before the first real
	// byte. PreOutputKeepalive separates them.
	write := func(b []byte, isContent bool) {
		mu.Lock()
		defer mu.Unlock()
		if !committed {
			if opt.Commit != nil {
				opt.Commit()
			}
			committed = true
			res.HeadersSent = true
		}
		if isContent {
			res.WroteAny = true
		}
		n, _ := w.Write(b)
		res.Bytes += int64(n)
		if flush != nil {
			flush()
		}
		lastWrite = time.Now()
	}

	if opt.KeepaliveIdle > 0 && len(opt.KeepalivePayload) > 0 {
		done := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			t := time.NewTicker(opt.KeepaliveIdle / 5)
			defer t.Stop()
			for {
				select {
				case <-done:
					return
				case <-t.C:
					mu.Lock()
					idle := time.Since(lastWrite)
					active := committed || opt.PreOutputKeepalive
					mu.Unlock()
					if active && idle >= opt.KeepaliveIdle {
						write(opt.KeepalivePayload, false)
					}
				}
			}
		}()
		// LIFO: stop the goroutine and wait for it to exit before returning, so
		// no keepalive write races the caller's resp.Body.Close().
		defer wg.Wait()
		defer close(done)
	}

	for {
		out, terminal, err := opt.Next()
		if len(out) > 0 {
			write(out, true)
		}
		if terminal {
			res.SawTerminal = true
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				res.Err = err
			} else if !res.SawTerminal {
				res.Err = io.ErrUnexpectedEOF
			}
			return res
		}
	}
}
