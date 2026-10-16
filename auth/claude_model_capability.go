package auth

// ClaudeModelUnsupported reports a statically known capability mismatch, not
// current availability. It is suitable for a local Anthropic 404 before retry
// scheduling. It never probes, rewrites models, or treats cooldown/quota/health
// as evidence that a model does not exist.
//
// Groups follow Acquire/AcquireMulti: named client groups plus public and new.
// OAuth has no authoritative model allowlist, and an empty API-key allowlist is
// unrestricted, so either keeps the answer unknown (false). An empty eligible
// fleet also stays unknown: deployment/permission outages should remain 503.
// Explicit ModelMap values are rewrites, not capability declarations; the exact
// client-facing AllowedModels gate remains authoritative just as in AcceptsModel.
func ClaudeModelUnsupported(statuses []Status, clientGroups []string, model string) bool {
	if model == "" || model == "unknown" {
		return false
	}
	groups := map[string]bool{"": true, "new": true}
	for _, group := range clientGroups {
		groups[NormalizeGroup(group)] = true
	}
	known := false
	for _, status := range statuses {
		a := status.Auth
		if NormalizeProvider(a.Provider) != ProviderAnthropic || a.Disabled || !groups[NormalizeGroup(a.Group)] {
			continue
		}
		if a.Kind != KindAPIKey || len(a.AllowedModels) == 0 {
			return false
		}
		known = true
		for _, allowed := range a.AllowedModels {
			if allowed == model {
				return false
			}
		}
	}
	return known
}
