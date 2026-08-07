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
	// Every retired Opus / Sonnet generation folds onto the current one,
	// including dated variants (via prefix fallback) and [1m]-labelled names
	// (label re-attached to the rewrite).
	for _, tc := range []struct{ in, want string }{
		{"claude-opus-4-8", "claude-opus-5"},
		{"claude-opus-4-7", "claude-opus-5"},
		{"claude-opus-4-6", "claude-opus-5"},
		{"claude-opus-4-1", "claude-opus-5"},
		{"claude-opus-4", "claude-opus-5"},
		{"claude-3-opus-20240229", "claude-opus-5"},
		{"claude-opus-4-8-20260315", "claude-opus-5"},
		{"claude-opus-4-8[1m]", "claude-opus-5[1m]"},
		{"claude-sonnet-4-6", "claude-sonnet-5"},
		{"claude-sonnet-4-5", "claude-sonnet-5"},
		{"claude-sonnet-4-5-20250929", "claude-sonnet-5"},
		{"claude-3-5-sonnet-20241022", "claude-sonnet-5"},
		{"claude-sonnet-4-6[1m]", "claude-sonnet-5[1m]"},
		// Already current → unchanged (no self-mapping, no double-suffix).
		{"claude-opus-5", "claude-opus-5"},
		{"claude-sonnet-5", "claude-sonnet-5"},
		{"claude-opus-5[1m]", "claude-opus-5[1m]"},
		// Out of scope by design: fable is API-key-only premium, haiku is a
		// separate price tier that mimicry treats differently.
		{"claude-fable-5", "claude-fable-5"},
		{"claude-fable-5[1m]", "claude-fable-5[1m]"},
		{"claude-haiku-4-5", "claude-haiku-4-5"},
		{"claude-haiku-4-5-20251001", "claude-haiku-4-5-20251001"},
		// Unrelated providers/names never match a Claude prefix.
		{"gpt-5.3-codex", "gpt-5.3-codex"},
	} {
		if got, ok := a.ResolveUpstreamModel(tc.in); !ok || got != tc.want {
			t.Errorf("ResolveUpstreamModel(%q) = (%q,%v), want (%q,true)", tc.in, got, ok, tc.want)
		}
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
