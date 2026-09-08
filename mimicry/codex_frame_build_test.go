package mimicry

import (
	"encoding/json"
	"strings"
	"testing"
)

// The frame's top-level key order is part of the captured shape, and `type`
// leads it. A re-encode would sort the keys; this asserts the splice does not.
func TestNewCodexResponseCreateFramePutsTypeFirstAndKeepsOrder(t *testing.T) {
	body := []byte(`{"model":"gpt-5.6-codex","input":[{"role":"user"}],"store":false,"stream":true,"prompt_cache_key":"pck"}`)
	got, err := NewCodexResponseCreateFrame(body)
	if err != nil {
		t.Fatalf("NewCodexResponseCreateFrame: %v", err)
	}
	want := `{"type":"response.create","model":"gpt-5.6-codex","input":[{"role":"user"}],"store":false,"stream":true,"prompt_cache_key":"pck"}`
	if string(got) != want {
		t.Fatalf("frame mismatch:\n got %s\nwant %s", got, want)
	}
	if !json.Valid(got) {
		t.Fatal("spliced frame is not valid JSON")
	}
}

func TestNewCodexResponseCreateFrameIsIdempotent(t *testing.T) {
	once, err := NewCodexResponseCreateFrame([]byte(`{"model":"m"}`))
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	twice, err := NewCodexResponseCreateFrame(once)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if string(once) != string(twice) {
		t.Fatalf("not idempotent:\n once %s\ntwice %s", once, twice)
	}
}

// Silently re-typing a frame the caller meant as something else would turn a
// control message into a billable turn.
func TestNewCodexResponseCreateFrameRefusesOtherTypes(t *testing.T) {
	_, err := NewCodexResponseCreateFrame([]byte(`{"type":"response.cancel","id":"resp_1"}`))
	if err == nil {
		t.Fatal("accepted a response.cancel frame")
	}
	if !strings.Contains(err.Error(), "response.cancel") {
		t.Fatalf("error does not name the offending type: %v", err)
	}
}

func TestNewCodexResponseCreateFrameRejectsNonObjects(t *testing.T) {
	for _, in := range []string{``, `   `, `[]`, `"str"`, `{`} {
		if _, err := NewCodexResponseCreateFrame([]byte(in)); err == nil {
			t.Errorf("accepted non-object body %q", in)
		}
	}
}

// The empty object has no following member, so the splice must not leave a
// dangling comma.
func TestNewCodexResponseCreateFrameEmptyObject(t *testing.T) {
	got, err := NewCodexResponseCreateFrame([]byte(`{}`))
	if err != nil {
		t.Fatalf("NewCodexResponseCreateFrame: %v", err)
	}
	if string(got) != `{"type":"response.create"}` {
		t.Fatalf("got %s", got)
	}
	if !json.Valid(got) {
		t.Fatal("invalid JSON")
	}
}

// The builder leaves client_metadata to RewriteCodexClientFrame, which is what
// the two are meant to be used as: a pair.
func TestResponseCreateFrameThenRewriteBindsIdentity(t *testing.T) {
	frame, err := NewCodexResponseCreateFrame([]byte(`{"model":"m","prompt_cache_key":"client-chosen"}`))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	id := CodexFrameIdentity{AccountKey: "acct-1", SessionID: "01890a5d-ac96-774b-bcce-b302099a8057"}
	out, err := RewriteCodexClientFrame(frame, id)
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatalf("rewritten frame is not JSON: %v", err)
	}
	if decoded["client_metadata"] == nil {
		t.Fatal("rewrite did not synthesize client_metadata")
	}
	if got := decoded["prompt_cache_key"]; got == "client-chosen" {
		t.Fatal("client-chosen prompt_cache_key survived the rewrite")
	}
}
