package auth

import (
	"encoding/json"
	"testing"

	"github.com/wjsoj/cc-core/mimicry"
)

// TestCodexUsageDecodeRateLimitReachedTypeShapes pins the fix for the
// production decode failure:
//
//	wham/usage decode: json: cannot unmarshal object into Go struct field
//	CodexUsageInfo.rate_limit_reached_type of type string
//
// The wham/usage backend returns rate_limit_reached_type as a bare string,
// as null, OR (newer) as an object. All three must decode without error now
// that the field is json.RawMessage.
func TestCodexUsageDecodeRateLimitReachedTypeShapes(t *testing.T) {
	cases := map[string]string{
		"null":   `{"plan_type":"pro","rate_limit_reached_type":null}`,
		"string": `{"plan_type":"pro","rate_limit_reached_type":"primary"}`,
		"object": `{"plan_type":"pro","rate_limit_reached_type":{"type":"primary","resets_at":1780135186}}`,
		"absent": `{"plan_type":"pro"}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			var info CodexUsageInfo
			if err := json.Unmarshal([]byte(body), &info); err != nil {
				t.Fatalf("decode %s shape failed: %v", name, err)
			}
			if info.PlanType != "pro" {
				t.Fatalf("plan_type not decoded: %q", info.PlanType)
			}
		})
	}
}

// The quota probe must present the SAME client as everything else that
// credential does.
//
// It used to pin the codex-tui constant, so a deployment whose default is
// Codex Desktop probed its own quota as a second client — one
// chatgpt-account-id appearing as two clients, on a probe that runs on a timer
// for every credential. That is the join applyCodexRefreshGrantHeaders refuses
// to hand over on the token endpoint, given away for free here.
func TestQuotaProbePresentsTheSameClientAsEverythingElse(t *testing.T) {
	for _, accountID := range []string{"", "acct-a", "acct-b", "acct-c"} {
		want := mimicry.CodexProfileFor(accountID).UserAgent
		if got := mimicry.CodexUsageUserAgent(accountID); got != want {
			t.Errorf("account %q: probe UA = %q, want the credential's own %q", accountID, got, want)
		}
	}
}
