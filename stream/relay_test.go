package stream

import (
	"bytes"
	"errors"
	"io"
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
