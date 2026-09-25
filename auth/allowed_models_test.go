package auth

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestAPIKeyAllowedModelsPersistsAndFiltersBeforeRewrite(t *testing.T) {
	a := mustAPIKey(t, t.TempDir(), "allowed", ProviderOpenAI)
	a.SetAllowedModels([]string{" gpt-6-sol ", "gpt-6-sol", ""})
	a.SetModelMap(map[string]string{"gpt-6-sol": "vendor-sol", "gpt-6-luna": "vendor-sol"})
	if got, ok := a.ResolveUpstreamModel("gpt-6-sol"); !ok || got != "vendor-sol" {
		t.Fatalf("rewrite: %q %v", got, ok)
	}
	if a.AcceptsModel("gpt-6-luna") {
		t.Fatal("unlisted model accepted")
	}
	if _, ok := a.ResolveUpstreamModel("gpt-6-luna"); ok {
		t.Fatal("rewrite bypassed restriction")
	}
	snapshot := a.Snapshot()
	snapshot.AllowedModels[0] = "gpt-6-luna"
	if !a.AcceptsModel("gpt-6-sol") {
		t.Fatal("snapshot mutated live allowlist")
	}
	if err := a.Persist(); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(a.FilePath)
	reloaded, err := ParseFile(a.FilePath, data)
	if err != nil || len(reloaded.AllowedModels) != 1 || reloaded.AcceptsModel("gpt-6-luna") {
		t.Fatalf("reload: %v", err)
	}
	reloaded.SetAllowedModels(nil)
	if err := reloaded.Persist(); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(a.FilePath)
	reloaded, err = ParseFile(a.FilePath, data)
	if err != nil || !reloaded.AcceptsModel("anything") {
		t.Fatalf("clear did not restore unrestricted routing: %v", err)
	}
}

func TestAllowedModelsNeverRestrictsOAuth(t *testing.T) {
	a := &Auth{Kind: KindOAuth, AllowedModels: []string{"other"}}
	a.SetAllowedModels([]string{"gpt-6-sol"})
	if !a.AcceptsModel("gpt-6-astra") {
		t.Fatal("OAuth restricted")
	}
	if _, ok := a.ResolveUpstreamModel("gpt-6-astra"); !ok {
		t.Fatal("OAuth rewrite restricted")
	}
}

func TestAPIKeyAllowedModelsCannotBeBypassedByLastResort(t *testing.T) {
	a := &Auth{ID: "restricted", Kind: KindAPIKey, Provider: ProviderOpenAI, AllowedModels: []string{"gpt-6-sol"}}
	a.MarkQuotaExceeded(time.Now().Add(time.Hour))
	p := NewPool(nil, []*Auth{a}, time.Minute, false, "")
	opts := AcquireOptions{AllowAPIKeyFallback: true, APIKeyOnly: true, APIKeyRoundRobin: true}
	if got := p.AcquireWithOptions(context.Background(), ProviderOpenAI, "client", "", "gpt-6-luna", "s", opts); got != nil {
		t.Fatal("last resort bypassed allowlist")
	}
	if got := p.AcquireWithOptions(context.Background(), ProviderOpenAI, "client", "", "gpt-6-sol", "s", opts); got != a {
		t.Fatal("accepted model lost existing last-resort behavior")
	}
}

func TestAPIKeyRoundRobinPerModelRetainsPriorityAndBoundaries(t *testing.T) {
	a := &Auth{ID: "a", Kind: KindAPIKey, Provider: ProviderOpenAI, AllowedModels: []string{"astra", "sol"}}
	b := &Auth{ID: "b", Kind: KindAPIKey, Provider: ProviderOpenAI, AllowedModels: []string{"astra"}}
	backup := &Auth{ID: "backup", Kind: KindAPIKey, Provider: ProviderOpenAI, Order: 10}
	private := &Auth{ID: "private", Kind: KindAPIKey, Provider: ProviderOpenAI, Group: "private", Order: -1}
	p := NewPool(nil, []*Auth{a, b, backup, private}, time.Minute, false, "")
	opts := AcquireOptions{AllowAPIKeyFallback: true, APIKeyOnly: true, APIKeyRoundRobin: true}
	pick := func(model string) *Auth {
		return p.AcquireWithOptions(context.Background(), ProviderOpenAI, "client", "", model, "s", opts)
	}
	if pick("astra") != a || pick("astra") != b || pick("sol") != a || pick("astra") != a {
		t.Fatal("per-model balancing or group filtering failed")
	}
	a.SetDisabled(true)
	if pick("astra") != b {
		t.Fatal("selected disabled key or backup ahead of healthy primary")
	}
	b.MarkQuotaExceeded(time.Now().Add(time.Hour))
	if pick("astra") != backup {
		t.Fatal("paused primary selected ahead of healthy backup")
	}
	backup.SetDisabled(true)
	if got := pick("sol"); got != nil {
		t.Fatalf("unsupported or disabled key selected: %s", got.ID)
	}
}

func TestParseRejectsMalformedAllowedModels(t *testing.T) {
	for _, raw := range []string{`{"type":"apikey","api_key":"test","allowed_models":"gpt-6-sol"}`, `{"type":"apikey","api_key":"test","allowed_models":[123]}`} {
		if _, err := ParseFile("test.json", []byte(raw)); err == nil {
			t.Fatal("malformed restriction silently became unrestricted")
		}
	}
}
