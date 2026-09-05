package mimicry

import (
	"encoding/json"
	"testing"

	"github.com/wjsoj/cc-core/apicompat"
)

func TestFastChatSanitizeAndRoutingAgree(t *testing.T) {
	body, err := apicompat.ChatCompletionsToResponses([]byte(`{"model":"gpt-5.5","service_tier":" FAST ","messages":[{"role":"user","content":"hello"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	body, _, err = SanitizeCodexRequestBody(body, "/v1/responses")
	if err != nil {
		t.Fatal(err)
	}
	model, tier := CodexModelAndTier(body)
	if tier != "priority" || CodexRoutingHint(model, tier) != "model=gpt-5.5;tier=priority" {
		t.Fatalf("body/header disagree: %s, %s", body, CodexRoutingHint(model, tier))
	}
	// Compact's existing whitelist removes the tier; billing must use that
	// final body and must not charge Fast for the original request's intent.
	compact, _, err := SanitizeCodexRequestBody(body, "/v1/responses/compact")
	if err != nil {
		t.Fatal(err)
	}
	if _, tier = CodexModelAndTier(compact); tier != "" {
		t.Fatal("compact unexpectedly retained tier")
	}
}
func TestFastWSRebindingKeepsCanonicalTier(t *testing.T) {
	out, err := RewriteCodexClientFrame([]byte(`{"type":"response.create","model":"gpt-5.5","service_tier":"fast","input":[]}`), testIdentity())
	if err != nil {
		t.Fatal(err)
	}
	var frame struct {
		Tier string `json:"service_tier"`
	}
	if err := json.Unmarshal(out, &frame); err != nil {
		t.Fatal(err)
	}
	if frame.Tier != "priority" {
		t.Fatalf("frame %s", out)
	}
	keys := topLevelKeyOrder(t, string(out))
	if len(keys) < 4 || keys[0] != "type" || keys[1] != "model" || keys[2] != "service_tier" || keys[3] != "input" {
		t.Fatalf("order %v", keys)
	}
}
