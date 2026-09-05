// Package servicetier keeps OpenAI request normalization and billing tier
// resolution consistent across HTTP, WebSocket, and pricing callers.
package servicetier

import "strings"

const (
	Priority = "priority"
	Flex     = "flex"
)

// Normalize accepts the wire tiers and the client alias fast. Unknown values
// resolve to empty; callers must not infer a paid tier from an unknown value.
func Normalize(value string) string {
	switch value = strings.ToLower(strings.TrimSpace(value)); value {
	case "fast":
		return Priority
	case Priority, Flex, "auto", "default", "scale":
		return value
	default:
		return ""
	}
}

// Resolution separates the final OUTBOUND request tier from the upstream's
// observation and the tier actually billed. Never pass the original inbound
// tier after a gateway policy has removed or replaced it.
type Resolution struct {
	Requested  string
	Observed   string
	Billing    string
	Downgraded bool
}

// ResolveOpenAI follows Sub2API's credential-aware contract: an API response
// may lower the bill, never raise it. Codex OAuth commonly reports default
// even for a Fast turn, so that particular observation is not authoritative.
// Missing or unknown observations preserve the outbound request tier.
func ResolveOpenAI(requested, observed string, codexOAuth bool) Resolution {
	r := Resolution{Requested: Normalize(requested), Observed: Normalize(observed)}
	r.Billing = r.Requested
	if r.Observed == "" || (codexOAuth && r.Observed == "default") {
		return r
	}
	if rank(r.Observed) < rank(r.Requested) {
		r.Billing, r.Downgraded = r.Observed, true
	}
	return r
}

func rank(tier string) int {
	switch tier {
	case Priority:
		return 2
	case Flex:
		return 0
	default:
		return 1
	}
}
