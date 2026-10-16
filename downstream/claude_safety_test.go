package downstream

import (
	"bytes"
	"strings"
	"testing"

	"github.com/wjsoj/cc-core/stream"
)

func TestClaudeSafetyVerdictsRemainOpaque(t *testing.T) {
	// Synthetic upstream verdicts include denial, approval, missing/unsupported,
	// and unavailable results. The relay must not invent a verdict in any case.
	for _, status := range []string{
		`{"type":"available","tool_uses":{"toolu_original":{"type":"evaluated","outcome":"flagged","explanation":"synthetic denial"}}}`,
		`{"type":"available","tool_uses":{"toolu_original":{"type":"evaluated","outcome":"not_flagged"}}}`,
		`{"type":"available","tool_uses":{"toolu_original":{"type":"skipped"}}}`,
		`{"type":"unsupported"}`,
		`{"type":"unavailable","reason":"timeout"}`,
		`{"type":"future_status","unknown":{"keep":true}}`,
		"",
	} {
		results := ""
		if status != "" {
			results = `,"safeguard_results":[{"type":"dangerous_tool_use","status":` + status + `}]`
		}
		body := []byte(`{"type":"message","content":[],"future":{"keep":true}` + results + `}`)
		if out, changed := ScrubErrorPayload(body); changed || !bytes.Equal(out, body) {
			t.Fatal("JSON verdict changed")
		}
		wire := "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"" + results + "}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
		scanner := stream.NewSSEScanner(strings.NewReader(wire), 0)
		var output bytes.Buffer
		for scanner.Scan() {
			line := scanner.Line()
			if out, changed := ScrubSSELine(scanner.Event(), line); changed {
				line = out
			}
			output.Write(line)
		}
		if err := scanner.Err(); err != nil {
			t.Fatal(err)
		}
		if output.String() != wire {
			t.Fatal("SSE verdict or framing changed")
		}
	}
}
