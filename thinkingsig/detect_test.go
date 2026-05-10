package thinkingsig

import "testing"

func TestIsSignatureError(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"canonical signature 400", `{"type":"error","error":{"type":"invalid_request_error","message":"messages.5.content.0: Invalid ` + "`signature`" + ` in ` + "`thinking`" + ` block"}}`, true},
		{"plain prose match", `Invalid signature in thinking block`, true},
		{"expected thinking variant", `{"error":{"message":"Expected ` + "`thinking`" + ` or ` + "`redacted_thinking`" + `, but found ` + "`text`" + `"}}`, true},
		{"unrelated 400", `{"error":{"message":"messages: tool_use_id not found"}}`, false},
		{"empty", "", false},
		{"only signature word", `{"error":{"message":"bad request signature header"}}`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := IsSignatureError([]byte(c.body))
			if got != c.want {
				t.Errorf("body=%q: got %v want %v", c.body, got, c.want)
			}
		})
	}
}
