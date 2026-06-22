package auth

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// mustAPIKey builds a minimal file-backed API-key Auth for tests. The backing
// file lets Persist() exercise the real saveAuth/parseFile round-trip.
func mustAPIKey(t *testing.T, dir, id, provider string) *Auth {
	t.Helper()
	path := filepath.Join(dir, id+".json")
	seed := map[string]any{"type": "apikey", "api_key": "sk-" + id, "provider": provider}
	data, _ := json.Marshal(seed)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("seed %s: %v", path, err)
	}
	return &Auth{
		ID:          id + ".json",
		Kind:        KindAPIKey,
		Provider:    provider,
		AccessToken: "sk-" + id,
		FilePath:    path,
	}
}

// acquireAPIKeyID is a small helper: acquire once for a fresh session and
// return the chosen auth ID (or "" if none). Releases so the active counter
// stays clean.
func acquireAPIKeyID(p *Pool, session string) string {
	a := p.Acquire(context.Background(), "anthropic", "tok", "", "", session)
	if a == nil {
		return ""
	}
	p.Release("anthropic", "tok", session)
	return a.ID
}

// TestAPIKeyAcquireFollowsOrder verifies the pool returns the lowest-Order
// (highest-priority) viable API key first, regardless of insertion order.
func TestAPIKeyAcquireFollowsOrder(t *testing.T) {
	dir := t.TempDir()
	// Insert in a deliberately non-priority order: c, a, b.
	c := mustAPIKey(t, dir, "c", "anthropic")
	c.Order = 3
	a := mustAPIKey(t, dir, "a", "anthropic")
	a.Order = 1
	b := mustAPIKey(t, dir, "b", "anthropic")
	b.Order = 2
	p := NewPool(nil, []*Auth{c, a, b}, time.Minute, false, "")

	if got := acquireAPIKeyID(p, "s1"); got != "a.json" {
		t.Fatalf("expected highest-priority a.json first, got %q", got)
	}

	// With a.json disabled, the next priority (b.json) takes over.
	a.SetDisabled(true)
	if got := acquireAPIKeyID(p, "s2"); got != "b.json" {
		t.Fatalf("expected b.json after a disabled, got %q", got)
	}
}

// TestAPIKeyDefaultOrderPreservesLoadOrder verifies all-default (Order 0) keys
// keep their load order through the stable sort.
func TestAPIKeyDefaultOrderPreservesLoadOrder(t *testing.T) {
	dir := t.TempDir()
	first := mustAPIKey(t, dir, "first", "anthropic")
	second := mustAPIKey(t, dir, "second", "anthropic")
	p := NewPool(nil, []*Auth{first, second}, time.Minute, false, "")
	if got := acquireAPIKeyID(p, "s1"); got != "first.json" {
		t.Fatalf("default-order keys should keep load order; got %q", got)
	}
}

// TestReorderAPIKeysPersists verifies ReorderAPIKeys updates both the in-memory
// selection order and the on-disk "order" field (round-tripped via parseFile).
func TestReorderAPIKeysPersists(t *testing.T) {
	dir := t.TempDir()
	a := mustAPIKey(t, dir, "a", "anthropic")
	b := mustAPIKey(t, dir, "b", "anthropic")
	cc := mustAPIKey(t, dir, "cc", "anthropic")
	p := NewPool(nil, []*Auth{a, b, cc}, time.Minute, false, "")

	// Promote cc to the front, then b, then a.
	if err := p.ReorderAPIKeys([]string{"cc.json", "b.json", "a.json"}); err != nil {
		t.Fatalf("ReorderAPIKeys: %v", err)
	}
	if got := acquireAPIKeyID(p, "s1"); got != "cc.json" {
		t.Fatalf("after reorder expected cc.json first, got %q", got)
	}

	// The order must survive a reload from disk.
	data, err := os.ReadFile(cc.FilePath)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	reloaded, err := parseFile(cc.FilePath, data)
	if err != nil {
		t.Fatalf("parseFile: %v", err)
	}
	if reloaded.Order != 0 {
		t.Fatalf("cc.json should be Order 0 (front), got %d", reloaded.Order)
	}
	// a.json was demoted to index 2.
	aData, _ := os.ReadFile(a.FilePath)
	aReloaded, _ := parseFile(a.FilePath, aData)
	if aReloaded.Order != 2 {
		t.Fatalf("a.json should be Order 2 after reorder, got %d", aReloaded.Order)
	}
}

// TestReorderAPIKeysUnlistedKeepRelativeOrder verifies keys omitted from the
// reorder list sort after listed ones while keeping their prior order.
func TestReorderAPIKeysUnlistedKeepRelativeOrder(t *testing.T) {
	dir := t.TempDir()
	a := mustAPIKey(t, dir, "a", "anthropic")
	b := mustAPIKey(t, dir, "b", "anthropic")
	cc := mustAPIKey(t, dir, "cc", "anthropic")
	p := NewPool(nil, []*Auth{a, b, cc}, time.Minute, false, "")

	// Only rank b explicitly; a and cc are unlisted.
	if err := p.ReorderAPIKeys([]string{"b.json"}); err != nil {
		t.Fatalf("ReorderAPIKeys: %v", err)
	}
	if got := acquireAPIKeyID(p, "s1"); got != "b.json" {
		t.Fatalf("explicitly-ranked b.json should be first, got %q", got)
	}
	// Disable b: a (load order before cc) should be next among unlisted.
	b.SetDisabled(true)
	if got := acquireAPIKeyID(p, "s2"); got != "a.json" {
		t.Fatalf("unlisted keys should keep load order (a before cc), got %q", got)
	}
}
