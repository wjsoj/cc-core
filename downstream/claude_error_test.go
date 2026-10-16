package downstream

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestClaudeSafeguardsUnsupported(t *testing.T) {
	cases := []struct {
		message string
		want    bool
	}{
		{"safeguards is not supported by this model", true},
		{"Unsupported parameter: safeguards", true},
		{"Unknown field 'safeguards'", true},
		{"safeguards: Extra inputs are not permitted", true},
		{"Unsupported beta header: dangerous-tool-use-2026-09-03", true},
		{"dangerous-tool-use-2026-09-03 is not supported", true},
		{"safeguards must be an array", false},
		{"safeguards.type is not supported", false},
		{"safeguards unknown status", false},
		{"safeguards unsupported type", false},
		{"Unsupported parameter: temperature; safeguards validation failed", false},
		{"safeguards classifier timeout", false},
		{"safeguards result missing", false},
		{"safeguards denied this tool", false},
		{"safeguards could not be evaluated", false},
		{"safeguards requires dangerous-tool-use-2026-09-03", false},
	}
	for _, tc := range cases {
		t.Run(tc.message, func(t *testing.T) {
			body, _ := json.Marshal(map[string]any{"error": map[string]string{"type": "invalid_request_error", "message": tc.message}})
			if got := IsClaudeSafeguardsUnsupported(400, body); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
			for _, status := range []int{200, 401, 403, 422, 429, 500, 503} {
				if IsClaudeSafeguardsUnsupported(status, body) {
					t.Fatalf("matched status %d", status)
				}
			}
		})
	}
	for _, kind := range []string{"authentication_error", "permission_error", "api_error"} {
		body, _ := json.Marshal(map[string]any{"error": map[string]string{"type": kind, "message": "safeguards is not supported"}})
		if IsClaudeSafeguardsUnsupported(400, body) {
			t.Fatalf("matched %s", kind)
		}
	}
}

func TestScrubHTTPErrorPayloadSafeguardsDoesNotExposeUpstream(t *testing.T) {
	body := []byte(`{"type":"error","request_id":"secret-request","credential":"sk-secret","url":"https://private.example","error":{"type":"invalid_request_error","message":"safeguards is not supported; sk-secret https://private.example acct-private","extra":"secret-extra"}}`)
	got, changed := ScrubHTTPErrorPayload(400, body)
	if !changed {
		t.Fatal("not sanitized")
	}
	var parsed struct {
		Type  string `json:"type"`
		Error struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(got, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Type != "error" || parsed.Error.Type != ClaudeSafeguardsUnsupportedType || parsed.Error.Message != ClaudeSafeguardsUnsupportedMessage {
		t.Fatalf("unexpected payload: %s", got)
	}
	for _, secret := range []string{"secret", "private", "credential", "extra", "request_id"} {
		if strings.Contains(string(got), secret) {
			t.Fatalf("leaked %s", secret)
		}
	}
	ordinary := []byte(`{"error":{"type":"invalid_request_error","message":"safeguards must be an array"}}`)
	preserved, changed := ScrubHTTPErrorPayload(400, ordinary)
	if changed || string(preserved) != string(ordinary) {
		t.Fatal("ordinary validation changed")
	}
}
