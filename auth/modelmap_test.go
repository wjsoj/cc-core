package auth

import "testing"

// ModelMap is a pure rewrite table: it rewrites listed models and passes
// everything else through unchanged. It must NOT act as an allow-list.
func TestModelMapRewriteOnly(t *testing.T) {
	a := &Auth{
		ID:   "relay",
		Kind: KindAPIKey,
		ModelMap: map[string]string{
			"claude-haiku-4-5-20251001": "claude-haiku-4-5", // rewrite
			"claude-sonnet-4-6":         "",                 // explicit pass-through
		},
	}

	// Listed-with-value → rewritten.
	if up, ok := a.ResolveUpstreamModel("claude-haiku-4-5-20251001"); !ok || up != "claude-haiku-4-5" {
		t.Fatalf("haiku rewrite: got (%q,%v) want (claude-haiku-4-5,true)", up, ok)
	}
	// Mapped to "" → pass through unchanged.
	if up, ok := a.ResolveUpstreamModel("claude-sonnet-4-6"); !ok || up != "claude-sonnet-4-6" {
		t.Fatalf("sonnet passthrough: got (%q,%v)", up, ok)
	}
	// Unlisted → pass through unchanged (NOT rejected — this is the key
	// difference from the old allow-list behavior).
	if up, ok := a.ResolveUpstreamModel("claude-opus-4-8"); !ok || up != "claude-opus-4-8" {
		t.Fatalf("unlisted opus must pass through: got (%q,%v)", up, ok)
	}

	// AcceptsModel never filters.
	for _, m := range []string{"claude-opus-4-8", "claude-haiku-4-5-20251001", "anything-else"} {
		if !a.AcceptsModel(m) {
			t.Fatalf("AcceptsModel(%q) = false; model_map must not filter", m)
		}
	}
}
