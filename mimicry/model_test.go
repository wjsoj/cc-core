package mimicry

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRewriteModelFieldPreservingBytes(t *testing.T) {
	// Key order is the point: a map round-trip would sort these alphabetically.
	const body = `{"model":"claude-opus-5","messages":[{"role":"user","content":"hi"}],"system":[],"max_tokens":1,"stream":true}`

	got, err := RewriteModelFieldPreservingBytes([]byte(body), "vendor/claude-opus-5")
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(body, `"claude-opus-5"`, `"vendor/claude-opus-5"`, 1)
	if string(got) != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestRewriteModelFieldPreservingBytesUnicodeAndNoop(t *testing.T) {
	const body = `{"model":"claude-opus-4-6","messages":[]}`
	got, err := RewriteModelFieldPreservingBytes([]byte(body), "[0.16]稳定喵/claude-opus-4-6")
	if err != nil {
		t.Fatal(err)
	}
	var obj struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(got, &obj); err != nil {
		t.Fatal(err)
	}
	if obj.Model != "[0.16]稳定喵/claude-opus-4-6" {
		t.Errorf("model = %q", obj.Model)
	}

	same, err := RewriteModelFieldPreservingBytes([]byte(body), "claude-opus-4-6")
	if err != nil {
		t.Fatal(err)
	}
	if string(same) != body {
		t.Errorf("no-op rewrite changed the body: %s", same)
	}
}

func TestRewriteModelFieldPreservingBytesRejectsBadInput(t *testing.T) {
	cases := map[string]string{
		"missing":      `{"messages":[]}`,
		"duplicate":    `{"model":"a","model":"b"}`,
		"not a string": `{"model":123}`,
		"not json":     `nope`,
		"not object":   `[{"model":"a"}]`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := RewriteModelFieldPreservingBytes([]byte(body), "x"); err == nil {
				t.Error("expected an error")
			}
		})
	}
	if _, err := RewriteModelFieldPreservingBytes([]byte(`{"model":"a"}`), ""); err == nil {
		t.Error("expected an error for an empty upstream model")
	}
}
