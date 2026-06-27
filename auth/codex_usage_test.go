package auth

import (
	"encoding/json"
	"testing"
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
