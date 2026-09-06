package auth

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The manifest logic is checked against the captured upstream payload rather
// than a hand-written fixture. A hand-written one would encode what we believe
// the shape to be, which is the belief that produced a /v1/models answering a
// Codex client with the plain OpenAI list in the first place.
const capturedModelsRow = "../crack/codexv0.153.4/rows/01-get-codex-models.json"

func loadCapturedManifest(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.FromSlash(capturedModelsRow))
	if err != nil {
		t.Skipf("capture row unavailable (%v)", err)
	}
	var row struct {
		ResBody json.RawMessage `json:"res_body"`
	}
	if err := json.Unmarshal(b, &row); err != nil {
		t.Fatalf("capture row is not valid JSON: %v", err)
	}
	return row.ResBody
}

func slugSet(t *testing.T, raw []byte) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, s := range CodexManifestSlugs(raw) {
		out[s] = true
	}
	return out
}

// TestCodexModelsRequest pins the discriminator. Presence of client_version is
// the signal, not its value — CLIProxyAPI keys on presence alone and its own
// tests exercise a bare `?client_version`, so an empty value must still route
// to the manifest.
func TestCodexModelsRequest(t *testing.T) {
	for _, tc := range []struct {
		name  string
		query map[string][]string
		want  string
		ok    bool
	}{
		{"absent", map[string][]string{}, "", false},
		{"other params only", map[string][]string{"limit": {"10"}}, "", false},
		{"present with value", map[string][]string{"client_version": {"0.153.4"}}, "0.153.4", true},
		{"present but empty", map[string][]string{"client_version": {""}}, "", true},
		{"present with no value at all", map[string][]string{"client_version": nil}, "", true},
		{"whitespace trimmed", map[string][]string{"client_version": {"  0.150.0 "}}, "0.150.0", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := CodexModelsRequest(tc.query)
			if ok != tc.ok || got != tc.want {
				t.Errorf("= (%q, %v), want (%q, %v)", got, ok, tc.want, tc.ok)
			}
		})
	}
}

// The whole point of the feature: a current client must be offered gpt-6-astra.
func TestFilterCodexManifestKeepsAstraForCurrentClient(t *testing.T) {
	raw := loadCapturedManifest(t)
	if !slugSet(t, raw)["gpt-6-astra"] {
		t.Fatal("the capture itself has no gpt-6-astra — wrong fixture")
	}
	got := slugSet(t, FilterCodexManifest(raw, "0.153.4"))
	if !got["gpt-6-astra"] {
		t.Error("gpt-6-astra was filtered out for a 0.153.4 client")
	}
	if !got["gpt-5.6-sol"] {
		t.Error("gpt-5.6-sol was filtered out for a 0.153.4 client")
	}
}

// The regression that started this: an OLDER client must still be offered
// gpt-6-astra. minimal_client_version gates the vendor's own client rollout,
// not what a relay may serve — the model name is a string in the Responses body
// and an older CLI uses it through this gateway fine. Enforcing the floor hid
// astra from essentially every real customer within a day of launch, since a
// floor set days ago excludes every build older than days.
func TestFilterCodexManifestKeepsAstraForOlderClients(t *testing.T) {
	raw := loadCapturedManifest(t)
	full := len(CodexManifestSlugs(raw))
	for _, cv := range []string{"0.147.0", "0.144.0", "0.98.0"} {
		got := slugSet(t, FilterCodexManifest(raw, cv))
		if !got["gpt-6-astra"] {
			t.Errorf("client %s was not offered gpt-6-astra", cv)
		}
		if n := len(got); n != full {
			t.Errorf("client %s got %d of %d models — the model set must not shrink", cv, n, full)
		}
	}
}

// The floor is still REPORTED, just never acted on: the client may do whatever
// it likes with it, and dropping the field would be its own lie.
func TestFilterCodexManifestStillReportsTheFloor(t *testing.T) {
	raw := FilterCodexManifest(loadCapturedManifest(t), "0.147.0")
	var payload struct {
		Models []struct {
			Slug  string `json:"slug"`
			Floor string `json:"minimal_client_version"`
		} `json:"models"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	for _, m := range payload.Models {
		if m.Slug == "gpt-6-astra" && m.Floor != "0.153.0" {
			t.Errorf("astra's minimal_client_version = %q, want it passed through as 0.153.0", m.Floor)
		}
	}
}

// An unknown or absent client version must not be used as a reason to withhold
// models — the client did not tell us, and an empty picker is the worse failure.
func TestFilterCodexManifestPassesThroughWhenVersionUnknown(t *testing.T) {
	raw := loadCapturedManifest(t)
	full := len(CodexManifestSlugs(raw))
	for _, v := range []string{"", "   ", "not-a-version"} {
		if got := len(CodexManifestSlugs(FilterCodexManifest(raw, v))); got != full {
			t.Errorf("client_version %q dropped models: %d of %d", v, got, full)
		}
	}
}

// A pre-0.144 client does not understand xhigh/max/ultra and refuses to render
// a model that advertises one, so those levels are trimmed rather than passed.
func TestFilterCodexManifestTrimsExtendedReasoningForOldClients(t *testing.T) {
	raw := FilterCodexManifest(loadCapturedManifest(t), "0.140.0")
	var payload struct {
		Models []struct {
			Slug   string `json:"slug"`
			Levels []struct {
				Effort string `json:"effort"`
			} `json:"supported_reasoning_levels"`
			Default string `json:"default_reasoning_level"`
		} `json:"models"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Models) == 0 {
		t.Fatal("everything was filtered out")
	}
	for _, m := range payload.Models {
		for _, l := range m.Levels {
			if codexExtendedReasoningLevels[l.Effort] {
				t.Errorf("%s still advertises %q to a 0.140.0 client", m.Slug, l.Effort)
			}
		}
		if codexExtendedReasoningLevels[m.Default] {
			t.Errorf("%s defaults to %q, which a 0.140.0 client cannot select", m.Slug, m.Default)
		}
	}
}

// Malformed input must degrade to passthrough. Serving the upstream bytes
// unchanged is always better than serving nothing.
func TestFilterCodexManifestPassesThroughGarbage(t *testing.T) {
	for _, raw := range [][]byte{[]byte("not json"), []byte(`{"models":"nope"}`), []byte(`[]`), nil} {
		if got := FilterCodexManifest(raw, "0.153.4"); string(got) != string(raw) {
			t.Errorf("input %q was rewritten to %q", raw, got)
		}
	}
}

// The synthesized fallback has to produce the manifest SHAPE, not the OpenAI
// list — it exists for deployments with no OAuth credential to borrow, and a
// wrong shape there is the exact bug this whole change fixes.
func TestSynthesizeCodexModelsManifestShape(t *testing.T) {
	raw := SynthesizeCodexModelsManifest([]string{"gpt-6-astra", "gpt-5.6-sol", "gpt-5.5"}, "0.153.4")
	var payload struct {
		Models []map[string]any `json:"models"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}
	if len(payload.Models) != 3 {
		t.Fatalf("got %d models, want 3", len(payload.Models))
	}
	first := payload.Models[0]
	if first["slug"] != "gpt-6-astra" {
		t.Errorf("wire order not preserved: leads with %v", first["slug"])
	}
	if first["display_name"] != "GPT-6-Astra" {
		t.Errorf("display_name = %v", first["display_name"])
	}
	// priority follows slice order so a client that sorts agrees with one that
	// does not.
	if p, _ := first["priority"].(float64); p != 1 {
		t.Errorf("priority = %v, want 1", first["priority"])
	}
	for _, key := range []string{
		"minimal_client_version", "context_window", "max_context_window",
		"supported_reasoning_levels", "default_reasoning_level", "supported_in_api",
	} {
		if _, ok := first[key]; !ok {
			t.Errorf("synthesized entry is missing %q", key)
		}
	}
}

// The fallback must agree with the proxied path: report the floor, never
// enforce it. A deployment that falls back is exactly the one least able to
// explain why a model vanished.
func TestSynthesizeCodexModelsManifestDoesNotEnforceFloor(t *testing.T) {
	models := []string{"gpt-6-astra", "gpt-5.6-sol"}
	for _, cv := range []string{"0.147.0", "0.153.4", ""} {
		if s := slugSet(t, SynthesizeCodexModelsManifest(models, cv)); !s["gpt-6-astra"] {
			t.Errorf("astra missing from the synthesized manifest for client %q", cv)
		}
	}
}

// An unrecognised slug must still be emitted — a model added to
// CodexModelCatalog without a spec entry here should degrade to defaults, never
// vanish from the picker.
func TestSynthesizeCodexModelsManifestKeepsUnknownSlugs(t *testing.T) {
	raw := SynthesizeCodexModelsManifest([]string{"gpt-7-nova"}, "0.153.4")
	if !slugSet(t, raw)["gpt-7-nova"] {
		t.Fatal("an unknown slug was dropped instead of defaulted")
	}
	if !strings.Contains(string(raw), "GPT-7-Nova") {
		t.Errorf("display name was not derived: %s", raw)
	}
}

// Cache: one fetch per version per TTL, and a failing refresh must never empty
// a picker that was working.
func TestCodexManifestCache(t *testing.T) {
	c := &CodexManifestCache{TTL: time.Hour}
	calls := 0
	fetch := func() ([]byte, error) { calls++; return []byte(`{"models":[]}`), nil }

	for i := 0; i < 3; i++ {
		if _, err := c.Get("0.153.4", fetch); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Errorf("fetched %d times within the TTL, want 1", calls)
	}
	// A different version is a different entry.
	if _, err := c.Get("0.147.0", fetch); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Errorf("a new version did not trigger its own fetch (calls=%d)", calls)
	}

	// Stale beats empty: a failing refresh returns the cached body AND the
	// error, so the caller can log without breaking the client.
	c.entries["0.153.4"].fetchedAt = time.Now().Add(-2 * time.Hour)
	body, err := c.Get("0.153.4", func() ([]byte, error) { return nil, errors.New("upstream down") })
	if err == nil {
		t.Error("a failed refresh should report its error")
	}
	if string(body) != `{"models":[]}` {
		t.Errorf("stale body not served on refresh failure: %q", body)
	}

	// With nothing cached, a failure is a failure.
	if _, err := (&CodexManifestCache{}).Get("x", func() ([]byte, error) { return nil, errors.New("boom") }); err == nil {
		t.Error("cold-cache failure should propagate")
	}
}

// A cold-cache failure must be remembered briefly. Without this, a credential
// whose refresh token upstream has invalidated makes every picker refresh
// re-attempt a doomed token refresh — 34 attempts in 30 minutes against one
// dead credential, in production.
func TestCodexManifestCacheNegativeCaching(t *testing.T) {
	c := &CodexManifestCache{TTL: time.Hour}
	calls := 0
	failing := func() ([]byte, error) { calls++; return nil, errors.New("refresh_token_invalidated") }

	for i := 0; i < 5; i++ {
		if _, err := c.Get("0.153.4", failing); err == nil {
			t.Fatal("expected the failure to propagate")
		}
	}
	if calls != 1 {
		t.Errorf("a dead credential was retried %d times, want 1 within the failure TTL", calls)
	}

	// Once the failure TTL lapses, it tries again — a credential that comes
	// back healthy must be picked up.
	c.entries["0.153.4"].failedAt = time.Now().Add(-2 * codexManifestFailureTTL)
	if _, err := c.Get("0.153.4", func() ([]byte, error) { return []byte(`{"models":[]}`), nil }); err != nil {
		t.Fatalf("recovery after the failure TTL: %v", err)
	}
	if _, err := c.Get("0.153.4", failing); err != nil {
		t.Fatal("a healthy body should now be cached and served")
	}
}

func TestCompareCodexVersions(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
		ok   bool
	}{
		{"0.153.4", "0.153.0", 1, true},
		{"0.153.0", "0.153.0", 0, true},
		{"0.147.0", "0.153.0", -1, true},
		{"0.153", "0.153.0", 0, true},
		// Desktop reports a pre-release suffix; it must stay parseable.
		{"0.147.0-alpha.6.6", "0.147.0", 0, true},
		{"garbage", "0.1.0", 0, false},
		{"", "0.1.0", 0, false},
	} {
		got, ok := compareCodexVersions(tc.a, tc.b)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Errorf("compare(%q,%q) = (%d,%v), want (%d,%v)", tc.a, tc.b, got, ok, tc.want, tc.ok)
		}
	}
}
