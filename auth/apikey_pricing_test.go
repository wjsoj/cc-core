package auth

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// TestAcquireAPIKeyFallbackGate verifies the AllowAPIKeyFallback option gates
// whether an API key is used when no OAuth credential is available, and that
// the legacy Acquire wrapper keeps the old always-fall-back behaviour.
func TestAcquireAPIKeyFallbackGate(t *testing.T) {
	dir := t.TempDir()
	k := mustAPIKey(t, dir, "k", "anthropic")
	// Pool with no OAuth and a single API key: the only path to a credential
	// is the API-key fallback, so the gate is decisive.
	p := NewPool(nil, []*Auth{k}, time.Minute, false, "")

	// Fallback disabled → nothing to serve → nil.
	if a := p.AcquireWithOptions(context.Background(), "anthropic", "tok", "", "", "s1", AcquireOptions{AllowAPIKeyFallback: false}); a != nil {
		t.Fatalf("fallback disabled should return nil, got %q", a.ID)
	}

	// Fallback enabled → the API key is served.
	a := p.AcquireWithOptions(context.Background(), "anthropic", "tok", "", "", "s2", AcquireOptions{AllowAPIKeyFallback: true})
	if a == nil || a.ID != "k.json" {
		t.Fatalf("fallback enabled should serve k.json, got %v", a)
	}
	p.Release("anthropic", "tok", "s2")

	// The back-compat Acquire wrapper must still fall back (allow=true).
	if a := p.Acquire(context.Background(), "anthropic", "tok", "", "", "s3"); a == nil || a.ID != "k.json" {
		t.Fatalf("plain Acquire should keep legacy fallback, got %v", a)
	}
}

// TestPriceMultiplierPersists round-trips the per-key billing override through
// saveAuth/parseFile, and asserts the default 0 is NOT written to disk (so old
// files and unranked keys stay clean — same discipline as Order).
func TestPriceMultiplierPersists(t *testing.T) {
	dir := t.TempDir()
	k := mustAPIKey(t, dir, "k", "anthropic")

	k.SetPriceMultiplier(1.25)
	if err := k.Persist(); err != nil {
		t.Fatalf("persist: %v", err)
	}
	data, err := os.ReadFile(k.FilePath)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	reloaded, err := parseFile(k.FilePath, data)
	if err != nil {
		t.Fatalf("parseFile: %v", err)
	}
	if reloaded.PriceMultiplier != 1.25 {
		t.Fatalf("price_multiplier round-trip: got %v want 1.25", reloaded.PriceMultiplier)
	}

	// Clearing back to 0 must remove the key from the file entirely.
	k.SetPriceMultiplier(0)
	if err := k.Persist(); err != nil {
		t.Fatalf("persist clear: %v", err)
	}
	raw, _ := os.ReadFile(k.FilePath)
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := m["price_multiplier"]; ok {
		t.Fatalf("price_multiplier 0 must not be persisted, file has it")
	}
	reloaded2, _ := parseFile(k.FilePath, raw)
	if reloaded2.PriceMultiplier != 0 {
		t.Fatalf("cleared multiplier should reload as 0, got %v", reloaded2.PriceMultiplier)
	}
}
