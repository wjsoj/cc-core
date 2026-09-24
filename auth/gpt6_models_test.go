package auth

import (
	"encoding/json"
	"slices"
	"testing"
)

func TestGPT6PlanAvailability(t *testing.T) {
	for _, plan := range []string{CodexPlanFree, CodexPlanPlus, CodexPlanPro, CodexPlanTeam, "unknown"} {
		models := CodexModelsForPlan(plan)
		if !slices.Contains(models, "gpt-6-luna") {
			t.Errorf("Luna missing from %s", plan)
		}
		if got := slices.Contains(models, "gpt-6-sol"); got != (plan != CodexPlanFree) {
			t.Errorf("Sol availability on %s = %v", plan, got)
		}
	}
}

func TestGPT6ManifestCapabilitiesAndClientCompatibility(t *testing.T) {
	for _, version := range []string{"0.155.0", "0.153.4", "0.140.0"} {
		var manifest struct {
			Models []struct {
				Slug       string `json:"slug"`
				Floor      string `json:"minimal_client_version"`
				Context    int    `json:"context_window"`
				MaxContext int    `json:"max_context_window"`
				Lite       bool   `json:"use_responses_lite"`
				Default    string `json:"default_reasoning_level"`
				Levels     []struct {
					Effort string `json:"effort"`
				} `json:"supported_reasoning_levels"`
			} `json:"models"`
		}
		raw := SynthesizeCodexModelsManifest([]string{"gpt-6-sol", "gpt-6-luna"}, version)
		if err := json.Unmarshal(raw, &manifest); err != nil {
			t.Fatal(err)
		}
		if len(manifest.Models) != 2 {
			t.Fatalf("models lost for %s", version)
		}
		for _, m := range manifest.Models {
			if m.Floor != "0.155.0" || m.Context != 272000 || m.MaxContext != 872000 || !m.Lite || m.Default != "medium" {
				t.Fatalf("wrong capabilities: %+v", m)
			}
			levels := []string{}
			for _, l := range m.Levels {
				levels = append(levels, l.Effort)
			}
			want := []string{"low", "medium", "high"}
			if version != "0.140.0" {
				want = append(want, "xhigh", "max")
				if m.Slug == "gpt-6-sol" {
					want = append(want, "ultra")
				}
			}
			if !slices.Equal(levels, want) {
				t.Errorf("%s on %s: %v want %v", m.Slug, version, levels, want)
			}
		}
	}
}

func TestGPT6UpstreamCatalogVersionFloor(t *testing.T) {
	for _, v := range []string{"", "invalid", "0.140.0", "0.153.4", "0.155.0"} {
		if got := codexManifestFetchVersion(v); got != "0.155.0" {
			t.Errorf("version %q -> %q", v, got)
		}
	}
	if got := codexManifestFetchVersion("0.156.0"); got != "0.156.0" {
		t.Fatal(got)
	}
}
