package auth

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExplicitAPIKeyPausePolicy(t *testing.T) {
	a := &Auth{Kind: KindAPIKey, ExplicitFailuresOnly: true}
	for _, tc := range []struct {
		name   string
		status int
		body   string
		pause  bool
	}{
		{"missing model", 503, `{"error":{"code":"model_not_found","message":"No available channel for model"}}`, false},
		{"overloaded", 503, `{"error":{"code":"server_is_overloaded"}}`, false},
		{"unknown gateway", 502, `Bad Gateway`, false},
		{"transport", 0, ``, false},
		{"WAF", 403, `error code: 1010`, false},
		{"key revoked", 401, ``, true},
		{"payment", 402, ``, true},
		{"rate limit", 429, ``, true},
		{"balance code", 403, `{"code":"INSUFFICIENT_BALANCE"}`, true},
		{"balance message", 403, `{"error":{"type":"new_api_error","message":"预扣费额度失败, 用户剩余额度不足"}}`, true},
		{"authentication payload", 500, `{"error":{"code":"invalid_api_key"}}`, true},
		{"unrelated field", 503, `{"input":"insufficient balance","error":{"code":"model_not_found"}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := a.ShouldPauseForAPIKeyError(tc.status, []byte(tc.body)); got != tc.pause {
				t.Fatalf("pause=%v want %v", got, tc.pause)
			}
		})
	}
	a.SetExplicitFailuresOnly(false)
	if !a.ShouldPauseForAPIKeyError(503, nil) {
		t.Fatal("legacy policy changed")
	}
	a.Kind = KindOAuth
	a.SetExplicitFailuresOnly(true)
	if !a.ShouldPauseForAPIKeyError(503, nil) {
		t.Fatal("OAuth policy changed")
	}
}

func TestExplicitAPIKeyPausePolicyPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.json")
	raw := []byte(`{"type":"openai_api_key","api_key":"test","explicit_failures_only":true}`)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	a, err := ParseFile(path, raw)
	if err != nil {
		t.Fatal(err)
	}
	if !a.Snapshot().ExplicitFailuresOnly {
		t.Fatal("policy not parsed")
	}
	for _, want := range []bool{true, false} {
		a.SetExplicitFailuresOnly(want)
		if err := a.Persist(); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		again, err := ParseFile(path, data)
		if err != nil {
			t.Fatal(err)
		}
		if again.Snapshot().ExplicitFailuresOnly != want {
			t.Fatalf("policy did not persist: want %v", want)
		}
	}
}
