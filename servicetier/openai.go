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
// may lower the bill, never raise it. Missing or unknown observations preserve
// the outbound request tier.
//
// codexOAuth marks a ChatGPT SUBSCRIPTION credential, and on that path the tier
// never changes the bill at all — Billing is left empty so the caller applies
// no multiplier.
//
// That is not a trust judgement about the observation, it is what the money
// does. Fast (né priority) and Flex are OpenAI **API price-page** tiers: they
// exist because an API key can buy faster or cheaper service, at 2x and 0.5x
// the standard rate. A ChatGPT Plus/Pro subscription buys neither — the plan
// price is flat, priority routing is part of what the plan already includes,
// and the upstream bills us exactly the same for a turn that asked for Fast as
// for one that did not. Charging 2x there invents an upstream cost that was
// never incurred and, because billed_usd is derived from it, takes the invented
// amount out of the customer's wallet.
//
// This used to read `codexOAuth && observed == "default"` as a reason to KEEP
// the requested priority — the reasoning being that Codex OAuth reports
// "default" even for a Fast turn, so the observation is not authoritative.
// Production disagreed on both halves. Over the seven hours after the tier
// billing shipped, 1567 subscription turns were billed at 2x on that branch:
// the upstream reported "default" 1565 times and "auto" 70 times and "priority"
// zero times, and within a single client token the priority turns ran at 19.06
// tok/s against 22.79 for the same model with no tier — slower, not faster. The
// branch was charging a premium for an upgrade the upstream neither
// acknowledged nor delivered nor charged us for.
//
// Requested and Observed are still reported, because they are real and the
// request log and the routing hint both want them. Only the bill is unaffected.
func ResolveOpenAI(requested, observed string, codexOAuth bool) Resolution {
	r := Resolution{Requested: Normalize(requested), Observed: Normalize(observed)}
	if codexOAuth {
		// Subscription: no tier premium or discount exists to apply.
		return r
	}
	r.Billing = r.Requested
	if r.Observed == "" {
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
