package mimicry

import (
	"encoding/json"
	"strings"
	"testing"
)

// The frame is rendered in the CAPTURED key order, not the caller's and not
// alphabetical. The input here is deliberately alphabetical, which is what
// SanitizeCodexRequestBody's map round-trip actually hands us in production.
func TestNewCodexResponseCreateFrameUsesCapturedKeyOrder(t *testing.T) {
	body := []byte(`{"include":["reasoning.encrypted_content"],"input":[{"role":"user"}],` +
		`"model":"gpt-5.6-codex","parallel_tool_calls":false,"prompt_cache_key":"pck",` +
		`"reasoning":{"effort":"medium"},"store":false,"stream":true,"text":{"verbosity":"low"},` +
		`"tool_choice":"auto"}`)
	got, err := NewCodexResponseCreateFrame(body)
	if err != nil {
		t.Fatalf("NewCodexResponseCreateFrame: %v", err)
	}
	want := `{"type":"response.create","model":"gpt-5.6-codex","input":[{"role":"user"}],` +
		`"tool_choice":"auto","parallel_tool_calls":false,"reasoning":{"effort":"medium"},` +
		`"store":false,"stream":true,"include":["reasoning.encrypted_content"],` +
		`"prompt_cache_key":"pck","text":{"verbosity":"low"}}`
	if string(got) != want {
		t.Fatalf("frame mismatch:\n got %s\nwant %s", got, want)
	}
	if !json.Valid(got) {
		t.Fatal("rendered frame is not valid JSON")
	}
}

// previous_response_id sits directly after model on a continuation
// (crack/codexapp0.147.0/rows/18), not wherever the caller happened to put it.
func TestNewCodexResponseCreateFramePlacesPreviousResponseID(t *testing.T) {
	body := []byte(`{"input":[],"model":"m","previous_response_id":"resp_1","stream":true}`)
	got, err := NewCodexResponseCreateFrame(body)
	if err != nil {
		t.Fatalf("NewCodexResponseCreateFrame: %v", err)
	}
	want := `{"type":"response.create","model":"m","previous_response_id":"resp_1","input":[],"stream":true}`
	if string(got) != want {
		t.Fatalf("frame mismatch:\n got %s\nwant %s", got, want)
	}
}

// A field the captures do not name must survive — dropping it would change the
// request — but it goes after the known keys so it cannot disturb their order.
func TestNewCodexResponseCreateFrameKeepsUnknownFieldsLast(t *testing.T) {
	body := []byte(`{"model":"m","zzz_future":1,"aaa_future":2,"input":[]}`)
	got, err := NewCodexResponseCreateFrame(body)
	if err != nil {
		t.Fatalf("NewCodexResponseCreateFrame: %v", err)
	}
	want := `{"type":"response.create","model":"m","input":[],"aaa_future":2,"zzz_future":1}`
	if string(got) != want {
		t.Fatalf("frame mismatch:\n got %s\nwant %s", got, want)
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
