package downstream

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestScrubErrorPayload(t *testing.T) {
	t.Run("drops the upstream request id", func(t *testing.T) {
		in := `{"type":"error","error":{"type":"rate_limit_error","message":"limit"},"request_id":"req_011CdoZnTHdYogjzJ6Wuzf6Y"}`
		out, changed := ScrubErrorPayload([]byte(in))
		if !changed {
			t.Fatal("expected a change")
		}
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(out, &obj); err != nil {
			t.Fatal(err)
		}
		if _, ok := obj["request_id"]; ok {
			t.Error("request_id survived")
		}
		// The parts a client switches on are untouched.
		if string(obj["type"]) != `"error"` {
			t.Errorf("type = %s", obj["type"])
		}
		var inner struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		}
		if err := json.Unmarshal(obj["error"], &inner); err != nil {
			t.Fatal(err)
		}
		if inner.Type != "rate_limit_error" || inner.Message != "limit" {
			t.Errorf("error object was altered: %+v", inner)
		}
	})

	t.Run("redacts identity inside the message", func(t *testing.T) {
		in := `{"type":"error","error":{"type":"permission_error",` +
			`"message":"Organization bf62f90e-ff9c-4d95-a554-17835658b5ef is disabled (req_011CdoZnTHdYogjzJ6Wuzf6Y)"}}`
		out, changed := ScrubErrorPayload([]byte(in))
		if !changed {
			t.Fatal("expected a change")
		}
		got := string(out)
		if strings.Contains(got, "bf62f90e-ff9c-4d95-a554-17835658b5ef") {
			t.Error("organization UUID survived in the message")
		}
		if strings.Contains(got, "req_011CdoZnTHdYogjzJ6Wuzf6Y") {
			t.Error("request id survived in the message")
		}
		if !strings.Contains(got, "is disabled") {
			t.Errorf("the actionable part of the message was lost: %s", got)
		}
		if !strings.Contains(got, `"permission_error"`) {
			t.Errorf("error type was altered: %s", got)
		}
	})

	t.Run("clean payloads are returned untouched", func(t *testing.T) {
		in := `{"type":"error","error":{"type":"invalid_request_error","message":"bad model"}}`
		out, changed := ScrubErrorPayload([]byte(in))
		if changed {
			t.Errorf("clean payload reported as changed: %s", out)
		}
		if string(out) != in {
			t.Errorf("clean payload was rewritten: %s", out)
		}
	})

	t.Run("non-object bodies pass through", func(t *testing.T) {
		// An upstream that answered with HTML or a truncated body is a problem
		// to surface, not to silently turn into something else.
		for _, in := range []string{
			`<html>502 Bad Gateway</html>`,
			`[1,2,3]`,
			`{"type":"error"`,
			``,
			`   `,
		} {
			out, changed := ScrubErrorPayload([]byte(in))
			if changed || string(out) != in {
				t.Errorf("input %q was rewritten to %q", in, out)
			}
		}
	})
}

func TestScrubSSELine(t *testing.T) {
	t.Run("scrubs an error event and keeps the framing", func(t *testing.T) {
		line := []byte("data: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"x\"},\"request_id\":\"req_0123456789\"}\n")
		out, changed := ScrubSSELine("error", line)
		if !changed {
			t.Fatal("expected a change")
		}
		if !strings.HasPrefix(string(out), "data: ") {
			t.Errorf("data prefix and spacing were lost: %q", out)
		}
		if !strings.HasSuffix(string(out), "\n") {
			t.Errorf("trailing newline was lost: %q", out)
		}
		if strings.Contains(string(out), "req_0123456789") {
			t.Errorf("request id survived: %q", out)
		}
	})

	t.Run("leaves every other event alone", func(t *testing.T) {
		// The hot path: thousands of these per response, and none can carry a
		// request id. They must not even be parsed.
		line := []byte("data: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"req_0123456789\"}}\n")
		for _, event := range []string{"content_block_delta", "message_start", "message_delta", "ping", ""} {
			out, changed := ScrubSSELine(event, line)
			if changed || string(out) != string(line) {
				t.Errorf("event %q was rewritten: %q", event, out)
			}
		}
	})

	t.Run("non-data lines are untouched", func(t *testing.T) {
		for _, raw := range []string{"event: error\n", "\n", ": comment\n"} {
			out, changed := ScrubSSELine("error", []byte(raw))
			if changed || string(out) != raw {
				t.Errorf("line %q was rewritten to %q", raw, out)
			}
		}
	})

	t.Run("a clean error event is not rewritten", func(t *testing.T) {
		line := []byte("data: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"overloaded\"}}\n")
		out, changed := ScrubSSELine("error", line)
		if changed || string(out) != string(line) {
			t.Errorf("clean error event was rewritten: %q", out)
		}
	})

	t.Run("handles CRLF and a missing space", func(t *testing.T) {
		line := []byte("data:{\"type\":\"error\",\"error\":{\"type\":\"e\",\"message\":\"m\"},\"request_id\":\"req_0123456789\"}\r\n")
		out, changed := ScrubSSELine("error", line)
		if !changed {
			t.Fatal("expected a change")
		}
		if !strings.HasPrefix(string(out), "data:{") {
			t.Errorf("spacing was invented: %q", out)
		}
		if !strings.HasSuffix(string(out), "\r\n") {
			t.Errorf("CRLF was lost: %q", out)
		}
	})
}

// Whatever comes out must still parse, or the client sees a broken stream
// instead of the error it was supposed to read.
func TestScrubbedOutputStaysValidJSON(t *testing.T) {
	for _, in := range []string{
		`{"type":"error","error":{"type":"e","message":"req_0123456789"},"request_id":"req_0123456789"}`,
		`{"request_id":"req_0123456789"}`,
		`{"error":{"message":"bf62f90e-ff9c-4d95-a554-17835658b5ef"}}`,
		`{"error":{"message":123},"request_id":"req_0123456789"}`,
		`{"error":"not-an-object","request_id":"req_0123456789"}`,
	} {
		out, _ := ScrubErrorPayload([]byte(in))
		if !json.Valid(out) {
			t.Errorf("input %s produced invalid JSON %s", in, out)
		}
		if strings.Contains(string(out), "req_0123456789") {
			t.Errorf("input %s leaked a request id: %s", in, out)
		}
	}
}
