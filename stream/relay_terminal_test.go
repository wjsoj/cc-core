package stream

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestRelayStopOnTerminalDoesNotReadAgain(t *testing.T) {
	var out bytes.Buffer
	calls := 0
	frame := []byte("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
	result := Relay(&out, nil, RelayOptions{
		StopOnTerminal: true,
		Next: func() ([]byte, bool, error) {
			calls++
			if calls > 1 {
				t.Fatal("Next called after complete terminal frame")
			}
			return frame, true, nil
		},
	})
	if !result.SawTerminal || result.Err != nil || !bytes.Equal(out.Bytes(), frame) || result.Bytes != int64(len(frame)) {
		t.Fatalf("terminal frame/result not preserved: %+v, %q", result, out.String())
	}
}

func TestRelayDefaultDrainsAfterTerminal(t *testing.T) {
	var out bytes.Buffer
	result := Relay(&out, nil, RelayOptions{
		Next: chunkNext([][]byte{[]byte("terminal"), []byte("trailer")}, 0, io.EOF),
	})
	if !result.SawTerminal || result.Err != nil || out.String() != "terminaltrailer" {
		t.Fatalf("default drain changed: %+v, %q", result, out.String())
	}
}

func TestRelayStopOnTerminalPreservesReadErrors(t *testing.T) {
	for _, terminal := range []bool{false, true} {
		t.Run(map[bool]string{false: "truncated", true: "terminal_read_error"}[terminal], func(t *testing.T) {
			want := io.ErrUnexpectedEOF
			end := error(io.EOF)
			if terminal {
				end = errors.New("read failed")
				want = end
			}
			var out bytes.Buffer
			result := Relay(&out, nil, RelayOptions{
				StopOnTerminal: true,
				Next:           func() ([]byte, bool, error) { return []byte("partial"), terminal, end },
			})
			if !errors.Is(result.Err, want) || out.String() != "partial" {
				t.Fatalf("read error lost: %+v", result)
			}
		})
	}
}
