package auth

import (
	"os"
	"path/filepath"
	"testing"
)

// TestStripThinkingPersistence covers the round-trip: an API-key credential
// file loads with strip_thinking=false, MarkStripThinking flips + persists it,
// and a fresh parse of the file reads it back true. Mirrors the aws2 relay
// scenario where the proxy auto-flags the credential after a signature recovery.
func TestStripThinkingPersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "apikey-aws2.json")
	if err := os.WriteFile(path, []byte(`{"type":"apikey","provider":"anthropic","label":"aws2","api_key":"sk-test","base_url":"https://relay.example"}`), 0600); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(path)
	a, err := ParseFile(path, data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if a.StripThinkingEnabled() {
		t.Fatal("fresh credential should not have strip_thinking set")
	}

	if err := a.MarkStripThinking(); err != nil {
		t.Fatalf("MarkStripThinking: %v", err)
	}
	if !a.StripThinkingEnabled() {
		t.Fatal("StripThinkingEnabled should be true after MarkStripThinking")
	}

	// Idempotent — second call must not error and must not churn.
	if err := a.MarkStripThinking(); err != nil {
		t.Fatalf("second MarkStripThinking: %v", err)
	}

	// Reload from disk: the flag must have persisted, and unrelated fields kept.
	data2, _ := os.ReadFile(path)
	b, err := ParseFile(path, data2)
	if err != nil {
		t.Fatalf("reparse: %v", err)
	}
	if !b.StripThinkingEnabled() {
		t.Fatal("strip_thinking did not persist to the credential file")
	}
	if b.BaseURL != "https://relay.example" || b.Label != "aws2" {
		t.Fatalf("unrelated fields lost on save: base=%q label=%q", b.BaseURL, b.Label)
	}
}
