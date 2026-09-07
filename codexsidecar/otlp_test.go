package codexsidecar

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/wjsoj/cc-core/auth"
	"github.com/wjsoj/cc-core/mimicry"
)

func resourceAttrs(t *testing.T, body map[string]any) map[string]string {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		ResourceMetrics []struct {
			Resource struct {
				Attributes []struct {
					Key   string `json:"key"`
					Value struct {
						StringValue string `json:"stringValue"`
					} `json:"value"`
				} `json:"attributes"`
			} `json:"resource"`
		} `json:"resourceMetrics"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, a := range parsed.ResourceMetrics[0].Resource.Attributes {
		out[a.Key] = a.Value.StringValue
	}
	return out
}

// TestOTLPAttributesVaryPerAccount is the second load-bearing test.
//
// The OTLP resource block carries host identity. One identical blob for every
// credential correlates every credential the proxy holds into a single
// machine, which is the exact failure auth.HostProfile exists to defuse on the
// Anthropic side. Across a spread of accounts the (os, os_version) pair must
// take more than one value — and it must be STABLE for a given account, or the
// same "machine" changes distro between exports.
func TestOTLPAttributesVaryPerAccount(t *testing.T) {
	seen := map[string]int{}
	for i := 0; i < 64; i++ {
		a := newOAuthAuth(string(rune('a'+i%26)) + string(rune('a'+i/26)))
		reg := newMetricRegistry(time.Now())
		recordStartupMetrics(reg, a.AccountKey())
		body := buildOTLPBody(osAttrsFor(a), reg.drain(time.Now()), time.Now())
		attrs := resourceAttrs(t, body)
		seen[attrs["os"]+"/"+attrs["os_version"]]++
	}
	if len(seen) < 3 {
		t.Fatalf("only %d distinct host identities across 64 accounts: %v", len(seen), seen)
	}

	// Stability: the same account must report the same host every time.
	a := newOAuthAuth("stable")
	first := osAttrsFor(a)
	for i := 0; i < 20; i++ {
		if got := osAttrsFor(a); got != first {
			t.Fatalf("host identity drifted for one account: %+v then %+v", first, got)
		}
	}
}

// TestOTLPAttributesFollowHostProfile — the variation is not an independent
// second source of truth; it is derived from the SAME auth.HostProfile the
// Anthropic sidecar reports, so a given account presents one machine to both
// backends.
func TestOTLPAttributesFollowHostProfile(t *testing.T) {
	for distro, want := range osAttrsPool {
		a := newOAuthAuth("hp-" + distro)
		a.HostProfile = auth.HostProfile{DistroID: distro, Kernel: "6.0.0-test", Terminal: "konsole", Shell: "zsh"}
		if got := osAttrsFor(a); got != want {
			t.Errorf("distro %s: got %+v, want %+v", distro, got, want)
		}
	}
	// Every distro auth.ProfileFor can pick must be covered, or some accounts
	// silently fall back to the captured Arch pair and re-correlate.
	for i := 0; i < 500; i++ {
		hp := auth.ProfileFor(string(rune(i%128)) + "-key")
		if _, ok := osAttrsPool[hp.DistroID]; !ok {
			t.Fatalf("auth.HostProfile can produce distro %q with no OTLP mapping", hp.DistroID)
		}
	}
}

// TestInstallationIDIsPerAccountAndStable — installation_id must be one value
// per upstream account (one account is one installation) and must not vary by
// client token.
func TestInstallationIDIsPerAccountAndStable(t *testing.T) {
	a := newOAuthAuth("inst-1")
	b := newOAuthAuth("inst-2")
	if installationIDFor(a) == installationIDFor(b) {
		t.Fatal("two accounts share one installation_id")
	}
	first := installationIDFor(a)
	for i := 0; i < 5; i++ {
		if installationIDFor(a) != first {
			t.Fatal("installation_id is not stable across calls")
		}
	}
	// Nothing about it may depend on the downstream client token: one account
	// is one installation, not one per downstream user.
	if installationIDFor(newOAuthAuth("inst-1")) != first {
		t.Fatal("installation_id is not derived from the account alone")
	}
	if installationIDFor(a) != mimicry.CodexInstallationIDFor(a.AccountKey()) {
		t.Fatal("installation_id diverged from mimicry's derivation")
	}
	if !isUUID(installationIDFor(a)) {
		t.Fatalf("installation_id %q is not a UUID", installationIDFor(a))
	}
}

// TestOTLPEnvelopeShape pins the parts of the envelope the capture fixes:
// resource attribute set and order, scope, delta temporality, monotonic sums,
// and the two histogram bucket ladders.
func TestOTLPEnvelopeShape(t *testing.T) {
	a := newOAuthAuth("shape")
	reg := newMetricRegistry(time.Now())
	recordStartupMetrics(reg, a.AccountKey())
	reg.observeMs("codex.mcp.tools.list.duration_ms", []attr{{"cache", "miss"}}, 898*time.Millisecond)
	raw, err := json.Marshal(buildOTLPBody(osAttrsFor(a), reg.drain(time.Now()), time.Now()))
	if err != nil {
		t.Fatal(err)
	}

	var parsed struct {
		ResourceMetrics []struct {
			Resource struct {
				Attributes []struct {
					Key string `json:"key"`
				} `json:"attributes"`
			} `json:"resource"`
			SchemaURL    string `json:"schemaUrl"`
			ScopeMetrics []struct {
				Scope struct {
					Name string `json:"name"`
				} `json:"scope"`
				Metrics []struct {
					Name string `json:"name"`
					Sum  *struct {
						AggregationTemporality int  `json:"aggregationTemporality"`
						IsMonotonic            bool `json:"isMonotonic"`
						DataPoints             []struct {
							AsInt int64 `json:"asInt"`
						} `json:"dataPoints"`
					} `json:"sum"`
					Histogram *struct {
						AggregationTemporality int `json:"aggregationTemporality"`
						DataPoints             []struct {
							Count          int       `json:"count"`
							BucketCounts   []int     `json:"bucketCounts"`
							ExplicitBounds []float64 `json:"explicitBounds"`
						} `json:"dataPoints"`
					} `json:"histogram"`
				} `json:"metrics"`
			} `json:"scopeMetrics"`
		} `json:"resourceMetrics"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	rm := parsed.ResourceMetrics[0]

	wantOrder := []string{
		"telemetry.sdk.name", "service.name", "telemetry.sdk.version", "os",
		"telemetry.sdk.language", "os_version", "env", "service.version",
	}
	if len(rm.Resource.Attributes) != len(wantOrder) {
		t.Fatalf("resource attributes: got %d, want %d", len(rm.Resource.Attributes), len(wantOrder))
	}
	for i, k := range wantOrder {
		if rm.Resource.Attributes[i].Key != k {
			t.Errorf("resource attribute %d: got %s, want %s", i, rm.Resource.Attributes[i].Key, k)
		}
	}
	if rm.ScopeMetrics[0].Scope.Name != otlpScopeName {
		t.Errorf("scope name %q", rm.ScopeMetrics[0].Scope.Name)
	}

	var sawStart, sawHistogram bool
	for _, m := range rm.ScopeMetrics[0].Metrics {
		if m.Sum != nil {
			if m.Sum.AggregationTemporality != 1 || !m.Sum.IsMonotonic {
				t.Errorf("%s: temporality=%d monotonic=%v, want 1/true", m.Name, m.Sum.AggregationTemporality, m.Sum.IsMonotonic)
			}
			if m.Name == "codex.process.start" {
				sawStart = true
				if m.Sum.DataPoints[0].AsInt != 1 {
					t.Errorf("codex.process.start = %d, want 1", m.Sum.DataPoints[0].AsInt)
				}
			}
		}
		if m.Histogram != nil {
			sawHistogram = true
			if m.Histogram.AggregationTemporality != 1 {
				t.Errorf("%s: histogram temporality=%d, want 1", m.Name, m.Histogram.AggregationTemporality)
			}
			for _, dp := range m.Histogram.DataPoints {
				if len(dp.BucketCounts) != len(dp.ExplicitBounds)+1 {
					t.Errorf("%s: %d buckets for %d bounds", m.Name, len(dp.BucketCounts), len(dp.ExplicitBounds))
				}
				total := 0
				for _, c := range dp.BucketCounts {
					total += c
				}
				if total != dp.Count {
					t.Errorf("%s: bucket counts sum to %d, count=%d", m.Name, total, dp.Count)
				}
			}
		}
	}
	if !sawStart {
		t.Error("codex.process.start missing")
	}
	if !sawHistogram {
		t.Error("no histogram metric emitted")
	}
}

// TestHistogramBoundsMatchCapture pins the two ladders verbatim.
func TestHistogramBoundsMatchCapture(t *testing.T) {
	wantMs := []float64{
		0, 5, 10, 25, 50, 75, 100, 250, 500, 750, 1000, 1250, 1500, 1750, 2000,
		2250, 2500, 3000, 3500, 4000, 4500, 5000, 6000, 7000, 7500, 8000, 9000,
		10000, 12000, 15000, 20000, 30000, 60000, 120000,
	}
	if len(durationMsBounds) != len(wantMs) {
		t.Fatalf("duration bounds: %d, want %d", len(durationMsBounds), len(wantMs))
	}
	for i := range wantMs {
		if durationMsBounds[i] != wantMs[i] {
			t.Errorf("duration bound %d: %v, want %v", i, durationMsBounds[i], wantMs[i])
		}
	}
	wantBytes := []float64{1048576, 10485760, 104857600, 1073741824, 10737418240, 107374182400, 1099511627776}
	if len(byteBounds) != len(wantBytes) {
		t.Fatalf("byte bounds: %d, want %d", len(byteBounds), len(wantBytes))
	}
	for i := range wantBytes {
		if byteBounds[i] != wantBytes[i] {
			t.Errorf("byte bound %d: %v, want %v", i, byteBounds[i], wantBytes[i])
		}
	}
}

// TestRegistryDrainIsDelta — temporality 1 means each export reports only what
// happened since the last one. Re-sending cumulative totals every 60s would be
// internally wrong in a way a backend can spot.
func TestRegistryDrainIsDelta(t *testing.T) {
	reg := newMetricRegistry(time.Now())
	reg.addCount("codex.process.start", []attr{{"originator", otlpOriginator}}, 1)
	reg.observeMs("codex.mcp.tools.list.duration_ms", nil, time.Second)
	if got := len(reg.drain(time.Now())); got != 2 {
		t.Fatalf("first drain returned %d series, want 2", got)
	}
	if got := len(reg.drain(time.Now())); got != 0 {
		t.Fatalf("second drain returned %d series, want 0 (delta temporality)", got)
	}
	reg.addCount("codex.process.start", []attr{{"originator", otlpOriginator}}, 1)
	if got := len(reg.drain(time.Now())); got != 1 {
		t.Fatalf("third drain returned %d series, want 1", got)
	}
}

// TestStartupMetricsVaryPerAccount — the synthetic local footprint (sqlite
// init durations, codex_home sizes) is anchored on the account for the same
// reason the host attributes are: identical local metrics across every
// credential is itself an "all one machine" signal.
func TestStartupMetricsVaryPerAccount(t *testing.T) {
	sizeOf := func(key string) float64 {
		reg := newMetricRegistry(time.Now())
		recordStartupMetrics(reg, key)
		for _, s := range reg.drain(time.Now()) {
			if s.name != "codex.app_server.codex_home.size_bytes" {
				continue
			}
			for _, a := range s.attrs {
				if a.Key == "directory" && a.Value == "codex_home" {
					return s.samples[0]
				}
			}
		}
		t.Fatalf("codex_home size not recorded for %s", key)
		return 0
	}
	seen := map[float64]bool{}
	for i := 0; i < 20; i++ {
		seen[sizeOf(string(rune('a'+i))+"-account")] = true
	}
	if len(seen) < 15 {
		t.Fatalf("only %d distinct codex_home sizes across 20 accounts", len(seen))
	}
	if sizeOf("repeat") != sizeOf("repeat") {
		t.Fatal("codex_home size is not stable for one account")
	}
}
