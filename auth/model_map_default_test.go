package auth

import (
	"os"
	"path/filepath"
	"testing"
)

// TestOAuthModelMapDefault covers the Claude-OAuth default model map: it is
// injected when the credential file has no model_map key, persists across
// save/reload, and an explicitly-cleared (empty) map disables it (no re-inject).
func TestOAuthModelMapDefault(t *testing.T) {
	dir := t.TempDir()

	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	load := func(p string) *Auth {
		data, _ := os.ReadFile(p)
		a, err := ParseFile(p, data)
		if err != nil {
			t.Fatalf("parse %s: %v", p, err)
		}
		return a
	}

	// 1. Claude OAuth, no model_map → defaults injected.
	p := write("claude-oauth.json", `{"type":"claude","access_token":"sk-ant-oat01-x","refresh_token":"r"}`)
	a := load(p)
	if a.Kind != KindOAuth || NormalizeProvider(a.Provider) != ProviderAnthropic {
		t.Fatalf("expected claude OAuth, got kind=%v provider=%s", a.Kind, a.Provider)
	}
	if got, _ := a.ResolveUpstreamModel("claude-opus-4-7"); got != "claude-opus-4-8" {
		t.Errorf("opus-4-7 should default-map to opus-4-8, got %q", got)
	}
	if got, _ := a.ResolveUpstreamModel("claude-opus-4-6"); got != "claude-opus-4-8" {
		t.Errorf("opus-4-6 should default-map to opus-4-8, got %q", got)
	}
	if got, _ := a.ResolveUpstreamModel("claude-sonnet-4-6"); got != "claude-sonnet-4-6" {
		t.Errorf("unlisted model must pass through, got %q", got)
	}

	// 2. Clear the map + persist → reload keeps it cleared (no re-inject).
	a.SetModelMap(map[string]string{})
	if err := a.Persist(); err != nil {
		t.Fatalf("persist: %v", err)
	}
	b := load(p)
	if got, _ := b.ResolveUpstreamModel("claude-opus-4-7"); got != "claude-opus-4-7" {
		t.Errorf("cleared map must NOT re-inject default; opus-4-7 got %q", got)
	}

	// 3. Codex (OpenAI) OAuth gets no Claude defaults.
	pc := write("codex-oauth.json", `{"type":"codex","access_token":"x","refresh_token":"r","id_token":"y"}`)
	c := load(pc)
	if got, _ := c.ResolveUpstreamModel("claude-opus-4-7"); got != "claude-opus-4-7" {
		t.Errorf("codex OAuth must not get Claude defaults, got %q", got)
	}
}
