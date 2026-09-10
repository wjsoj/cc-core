package stream

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

// chunk source helper: returns the queued chunks then a terminal error.
func chunkNext(chunks [][]byte, terminalAt int, endErr error) func() ([]byte, bool, error) {
	i := 0
	return func() ([]byte, bool, error) {
		if i >= len(chunks) {
			return nil, false, endErr
		}
		c := chunks[i]
		terminal := i == terminalAt
		i++
		return c, terminal, nil
	}
}

func TestRelayNoCommitBeforeFirstByte(t *testing.T) {
	var buf bytes.Buffer
	committed := false
	res := Relay(&buf, nil, RelayOptions{
		Commit: func() { committed = true },
		Next:   func() ([]byte, bool, error) { return nil, false, errors.New("connection reset by peer") },
	})
	if committed {
		t.Error("commit must not run when the stream breaks before any byte")
	}
	if res.WroteAny {
		t.Error("WroteAny must be false")
	}
	if res.SawTerminal {
		t.Error("SawTerminal must be false")
	}
	if res.Err == nil {
		t.Error("Err must be set so the caller can retry")
	}
	if buf.Len() != 0 {
		t.Errorf("nothing should be written, got %q", buf.String())
	}
}

func TestRelayCleanTerminal(t *testing.T) {
	var buf bytes.Buffer
	commits := 0
	res := Relay(&buf, nil, RelayOptions{
		Commit: func() { commits++ },
		Next:   chunkNext([][]byte{[]byte("a"), []byte("b")}, 1, io.EOF),
	})
	if !res.SawTerminal {
		t.Error("SawTerminal must be true")
	}
	if res.Err != nil {
		t.Errorf("clean terminal must report Err=nil, got %v", res.Err)
	}
	if commits != 1 {
		t.Errorf("commit must run exactly once, got %d", commits)
	}
	if !res.WroteAny || res.Bytes != 2 {
		t.Errorf("expected WroteAny + 2 bytes, got wroteAny=%v bytes=%d", res.WroteAny, res.Bytes)
	}
	if buf.String() != "ab" {
		t.Errorf("got %q", buf.String())
	}
}

func TestRelayTruncatedAfterFirstByte(t *testing.T) {
	var buf bytes.Buffer
	res := Relay(&buf, nil, RelayOptions{
		Next: chunkNext([][]byte{[]byte("partial")}, -1, io.EOF), // no terminal
	})
	if res.SawTerminal {
		t.Error("SawTerminal must be false on a truncated stream")
	}
	if !res.WroteAny {
		t.Error("WroteAny must be true (partial bytes were written)")
	}
	if !errors.Is(res.Err, io.ErrUnexpectedEOF) {
		t.Errorf("truncation must report ErrUnexpectedEOF, got %v", res.Err)
	}
	if buf.String() != "partial" {
		t.Errorf("got %q", buf.String())
	}
}

// A slow stream with a long gap before the terminal event should emit at least
// one keepalive payload, and only after the first real byte.
func TestRelayKeepalive(t *testing.T) {
	var mu sync.Mutex
	var buf bytes.Buffer
	step := make(chan struct{})
	calls := 0
	next := func() ([]byte, bool, error) {
		calls++
		switch calls {
		case 1:
			return []byte("first"), false, nil
		case 2:
			<-step // block ~here so the keepalive ticker fires during the gap
			return []byte("last"), true, nil
		default:
			return nil, false, io.EOF
		}
	}
	done := make(chan RelayResult, 1)
	go func() {
		done <- Relay(syncWriter{&mu, &buf}, nil, RelayOptions{
			KeepaliveIdle:    20 * time.Millisecond,
			KeepalivePayload: []byte("PING"),
			Next:             next,
		})
	}()
	time.Sleep(120 * time.Millisecond) // let several keepalive ticks fire
	mu.Lock()
	mid := buf.String()
	mu.Unlock()
	close(step)
	res := <-done

	if !res.SawTerminal {
		t.Error("SawTerminal must be true")
	}
	if !bytes.HasPrefix([]byte(mid), []byte("first")) {
		t.Errorf("first real byte must precede keepalive, got %q", mid)
	}
	if !bytes.Contains([]byte(mid), []byte("PING")) {
		t.Errorf("expected at least one keepalive PING during the gap, got %q", mid)
	}
}

// syncWriter serializes Write under the same mutex the test reads buf with, so
// the race detector stays happy while we peek mid-stream.
type syncWriter struct {
	mu  *sync.Mutex
	buf *bytes.Buffer
}

func (w syncWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

// The real assertion, run without blocking: keepalives write bytes and commit
// the headers, but leave WroteAny false so the caller can still roll back.
func TestKeepaliveBytesCommitHeadersButNotContent(t *testing.T) {
	var buf bytes.Buffer
	first := true
	res := Relay(&buf, nil, RelayOptions{
		KeepaliveIdle:      10 * time.Millisecond,
		KeepalivePayload:   []byte(":\n\n"),
		PreOutputKeepalive: true,
		Next: func() ([]byte, bool, error) {
			if first {
				first = false
				time.Sleep(60 * time.Millisecond) // let the keepalive fire
				return nil, false, nil
			}
			return nil, false, io.EOF
		},
	})

	if res.Bytes == 0 {
		t.Fatal("no keepalive was written; the connection would have looked hung")
	}
	if !res.HeadersSent {
		t.Error("HeadersSent is false after bytes went out; the caller would try to set a status it no longer owns")
	}
	if res.WroteAny {
		t.Error("a keepalive set WroteAny — the caller would think content reached the client and refuse to fail over")
	}
	// Several may have fired; every one of them must be a bare SSE comment and
	// nothing else, or something the client would try to parse has leaked out.
	got := buf.String()
	if n := strings.Count(got, ":\n\n"); n == 0 || strings.ReplaceAll(got, ":\n\n", "") != "" {
		t.Errorf("wrote %q, want only SSE comment keepalives", got)
	}
}

// Default off: a caller that has not opted in keeps the completely write-free
// window it was written against.
func TestKeepaliveStaysOffBeforeTheFirstByteByDefault(t *testing.T) {
	var buf bytes.Buffer
	first := true
	res := Relay(&buf, nil, RelayOptions{
		KeepaliveIdle:    10 * time.Millisecond,
		KeepalivePayload: []byte(":\n\n"),
		Next: func() ([]byte, bool, error) {
			if first {
				first = false
				time.Sleep(60 * time.Millisecond)
				return nil, false, nil
			}
			return nil, false, io.EOF
		},
	})
	if res.Bytes != 0 || res.HeadersSent {
		t.Fatalf("wrote %d bytes before any content with PreOutputKeepalive off: %q", res.Bytes, buf.String())
	}
}

// Real content still sets both.
func TestContentSetsBothFlags(t *testing.T) {
	var buf bytes.Buffer
	first := true
	res := Relay(&buf, nil, RelayOptions{
		Next: func() ([]byte, bool, error) {
			if first {
				first = false
				return []byte("data: hi\n\n"), false, nil
			}
			return nil, false, io.EOF
		},
	})
	if !res.WroteAny || !res.HeadersSent {
		t.Fatalf("content left WroteAny=%v HeadersSent=%v", res.WroteAny, res.HeadersSent)
	}
}
