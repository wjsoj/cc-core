package auth

import "testing"

// The catalog had no test at all until gpt-6-astra was added, which is how it
// drifted: it still lists gpt-5.2 / gpt-5.3-codex / gpt-5.4, none of which the
// live 0.153.4 Pro catalog returns. These tests do not try to pin the whole map
// — that would just re-encode the drift — they pin the properties a bad edit
// actually breaks.

// TestCodexCatalogListsAstraOnEveryPlan pins the plan placement taken from the
// 2026-09-05 capture's per-model available_in_plans, which lists free, plus,
// pro, team, go and business for gpt-6-astra
// (crack/codexv0.153.4/rows/01-get-codex-models.json).
func TestCodexCatalogListsAstraOnEveryPlan(t *testing.T) {
	for _, plan := range []string{CodexPlanFree, CodexPlanPlus, CodexPlanPro, CodexPlanTeam} {
		models := CodexModelCatalog[plan]
		if len(models) == 0 {
			t.Fatalf("plan %q has no models", plan)
		}
		if models[0] != "gpt-6-astra" {
			t.Errorf("plan %q leads with %q, want gpt-6-astra — it is priority 1 upstream "+
				"and both forks emit /v1/models in slice order", plan, models[0])
		}
	}
}

// TestCodexCatalogWithholdsHiddenModels guards the deliberate omission. Both
// slugs are served to a Pro account and are supported_in_api, but both are
// visibility "hide" upstream, so listing them in a customer-facing /v1/models
// advertises a model no genuine Codex client offers.
func TestCodexCatalogWithholdsHiddenModels(t *testing.T) {
	for _, hidden := range []string{"gpt-reserve", "codex-auto-review"} {
		for plan, models := range CodexModelCatalog {
			for _, m := range models {
				if m == hidden {
					t.Errorf("plan %q lists %q, which is visibility \"hide\" upstream", plan, hidden)
				}
			}
		}
	}
}

// TestCodexModelsForPlanFallsBackToPro pins the availability-over-restriction
// rule an unknown plan_type claim relies on.
func TestCodexModelsForPlanFallsBackToPro(t *testing.T) {
	got := CodexModelsForPlan("some-plan-that-does-not-exist")
	want := CodexModelCatalog[CodexPlanPro]
	if len(got) != len(want) {
		t.Fatalf("unknown plan returned %d models, want the Pro list's %d", len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("unknown plan returned %v, want the Pro list %v", got, want)
		}
	}
}
