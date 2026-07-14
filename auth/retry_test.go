package auth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

func TestIsTransientNetErr(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"reset-by-peer", errors.New("read tcp 10.0.0.1:1->2.2.2.2:443: read: connection reset by peer"), true},
		{"utls-handshake-reset", errors.New("utls handshake chatgpt.com: read tcp ...: read: connection reset by peer"), true},
		{"h2-protocol-error", errors.New(`stream error: stream ID 23; PROTOCOL_ERROR; received from peer`), true},
		{"h2-refused-stream", errors.New("stream error: stream ID 5; REFUSED_STREAM; received from peer"), true},
		{"goaway", errors.New("http2: server sent GOAWAY and closed the connection"), true},
		{"h2-client-conn-unusable", errors.New("http2: client conn not usable"), true},
		{"h2-no-cached-conn", errors.New("http2: no cached connection was available"), true},
		// Verbatim from prod (2026-07-14): a dead pooled conn failed every
		// in-flight stream at once, and because this string was not classified
		// transient, each one landed a MarkFailure and took the codex pool dark.
		{"h2-client-conn-lost", errors.New(`Post "https://chatgpt.com/backend-api/codex/responses": http2: client connection lost`), true},
		{"broken-pipe", errors.New("write tcp: broken pipe"), true},
		{"eof-sentinel", io.EOF, true},
		{"unexpected-eof", errors.New("unexpected EOF"), true},
		{"http-403", errors.New("got 403 forbidden"), false},
		{"context-canceled", context.Canceled, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := IsTransientNetErr(c.err); got != c.want {
				t.Fatalf("IsTransientNetErr(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}

// stubRT fails the first failN RoundTrips with the given error, then succeeds.
// It records how many times the (rewound) body read back the expected payload.
type stubRT struct {
	failN     int32
	err       error
	calls     int32
	bodyReads []string
}

func (s *stubRT) RoundTrip(req *http.Request) (*http.Response, error) {
	atomic.AddInt32(&s.calls, 1)
	if req.Body != nil {
		b, _ := io.ReadAll(req.Body)
		_ = req.Body.Close()
		s.bodyReads = append(s.bodyReads, string(b))
	}
	if atomic.LoadInt32(&s.failN) > 0 {
		atomic.AddInt32(&s.failN, -1)
		return nil, s.err
	}
	return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
}

func TestRetryRoundTripper_ReplaysTransientWithRewind(t *testing.T) {
	stub := &stubRT{failN: 2, err: errors.New("PROTOCOL_ERROR; received from peer")}
	rt := &retryRoundTripper{base: stub}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://x/y", strings.NewReader("payload"))

	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if stub.calls != 3 {
		t.Fatalf("calls = %d, want 3 (1 + 2 retries)", stub.calls)
	}
	for i, b := range stub.bodyReads {
		if b != "payload" {
			t.Fatalf("attempt %d read body %q, want %q (GetBody rewind failed)", i, b, "payload")
		}
	}
}

func TestRetryRoundTripper_NoRetryOnNonTransient(t *testing.T) {
	stub := &stubRT{failN: 5, err: errors.New("403 forbidden")}
	rt := &retryRoundTripper{base: stub}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://x/y", strings.NewReader("p"))
	if _, err := rt.RoundTrip(req); err == nil {
		t.Fatal("want error")
	}
	if stub.calls != 1 {
		t.Fatalf("calls = %d, want 1 (no retry on non-transient)", stub.calls)
	}
}

func TestRetryRoundTripper_StopsOnCanceledContext(t *testing.T) {
	stub := &stubRT{failN: 5, err: errors.New("connection reset by peer")}
	rt := &retryRoundTripper{base: stub}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already canceled — backoff sleep must bail immediately
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://x/y", strings.NewReader("p"))
	if _, err := rt.RoundTrip(req); err == nil {
		t.Fatal("want error")
	}
	// First call happens, then the loop sees ctx.Err() and stops before sleeping.
	if stub.calls != 1 {
		t.Fatalf("calls = %d, want 1 (canceled ctx must stop retries)", stub.calls)
	}
}
