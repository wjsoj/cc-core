package auth

// CodexModelCatalog enumerates the OAuth-exposable models per Codex
// subscription tier. Source: CLIProxyAPI's registry models.json (the
// codex-free / codex-plus / codex-pro / codex-team top-level keys).
// Kept as a flat Go map so the admin UI can reflect the same list
// without loading the upstream JSON.
//
// When a subscriber's plan can't be identified (unknown value in
// id_token's chatgpt_plan_type) the caller should fall back to the
// Pro list — matches CLIProxyAPI's default, i.e. favor availability
// over restriction.
//
// Verified against a live codex-tui/0.135.0 Pro session (crack/codex/SPEC.md,
// 2026-05-30): default model gpt-5.5, plus the metered gpt-5.3-codex-spark —
// both already present in the Pro/Plus lists.
//
// The gpt-5.6-{sol,terra,luna} family was added tracking codex-tui 0.144.1's
// client catalog (mirrors sub2api's openai DefaultModels — the three tiers ARE
// the model variants, there is no -high/-codex sub-variant). They follow gpt-5.5's
// tier placement: exposed on plus/pro/team, withheld from free.
var CodexModelCatalog = map[string][]string{
	CodexPlanFree: {
		"gpt-5.2",
		"gpt-5.3-codex",
		"gpt-5.4",
		"gpt-5.4-mini",
	},
	CodexPlanPlus: {
		"gpt-5.2",
		"gpt-5.3-codex",
		"gpt-5.3-codex-spark",
		"gpt-5.4",
		"gpt-5.4-mini",
		"gpt-5.5",
		"gpt-5.6-sol",
		"gpt-5.6-terra",
		"gpt-5.6-luna",
	},
	CodexPlanPro: {
		"gpt-5.2",
		"gpt-5.3-codex",
		"gpt-5.3-codex-spark",
		"gpt-5.4",
		"gpt-5.4-mini",
		"gpt-5.5",
		"gpt-5.6-sol",
		"gpt-5.6-terra",
		"gpt-5.6-luna",
	},
	CodexPlanTeam: {
		"gpt-5.2",
		"gpt-5.3-codex",
		"gpt-5.4",
		"gpt-5.4-mini",
		"gpt-5.5",
		"gpt-5.6-sol",
		"gpt-5.6-terra",
		"gpt-5.6-luna",
	},
}

// CodexModelsForPlan returns the model list a Codex OAuth credential with
// the given plan_type claim is entitled to. Empty or unknown plans fall
// back to Pro (least restrictive) for the same reason CLIProxyAPI does:
// clients should see the full catalog when we can't prove a restriction.
func CodexModelsForPlan(planType string) []string {
	if list, ok := CodexModelCatalog[NormalizeCodexPlan(planType)]; ok {
		return list
	}
	return CodexModelCatalog[CodexPlanPro]
}
