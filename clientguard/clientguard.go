// Package clientguard is a shared ingress filter that rejects requests
// originating from non-interactive SDK / scripting clients (raw Anthropic /
// OpenAI SDKs, LiteLLM, python-requests, curl, …) while letting the official
// interactive client family through (Claude Code CLI, Claude Code IDE/Web,
// Claude Desktop, Cursor, and any other normal product client).
//
// It is a **blocklist**, not an allowlist: anything whose User-Agent doesn't
// match a known abuse fragment is allowed. This deliberately errs on the
// permissive side so that legitimate clients we have no fingerprint for
// (Claude Desktop, Cursor, future surfaces) keep working without per-client
// rules. The trade-off is that the filter only stops *low-effort* abuse — a
// determined caller can spoof any User-Agent — so it is an access-policy
// layer, not a security boundary.
//
// Both CPA-Claude and hypitoken consume this package so the two relays share
// one definition of "blocked client".
package clientguard

import (
	"net/http"
	"strings"
)

// DefaultBlockedUASubstrings are User-Agent fragments (matched case-insensitively
// as substrings) that unambiguously identify non-interactive SDK / scripting
// clients. None of these appear in the User-Agent of the official interactive
// client family:
//
//   - Claude Code CLI    → "claude-cli/<v> (external, cli)"
//   - Claude Code IDE/Web → "claude-code/<v>"
//   - Claude Desktop      → Electron/app UA (no SDK fragment)
//   - Cursor              → app UA (no SDK fragment)
//
// JS-runtime fragments ("axios/", "node-fetch") are deliberately NOT included:
// Electron apps (Cursor, Claude Desktop) may surface them, and the false-positive
// risk outweighs the benefit. Operators can add them per-deployment via extra
// substrings (see New) if they observe such abuse.
var DefaultBlockedUASubstrings = []string{
	// Python ecosystem
	"python-requests/",
	"python-httpx/",
	"python-urllib",
	"urllib3/",
	"aiohttp/",
	"scrapy/",

	// Vendor SDK defaults (raw SDK callers; the official clients override the
	// UA, so these only appear from direct SDK use). Stainless-generated SDKs
	// send "<Title>/<Runtime> <ver>", e.g. "Anthropic/Python 0.40.0" or
	// "OpenAI/NodeJS 4.x" — matched here in their lowercased "<title>/<runtime>"
	// form. LiteLLM identifies itself in the UA regardless of backend.
	"anthropic/python",
	"anthropic/js",
	"openai/python",
	"openai/nodejs",
	"openai-python/",
	"litellm",

	// Generic HTTP clients / CLIs / API tools
	"curl/",
	"wget/",
	"go-http-client/",
	"okhttp/",
	"java/",
	"apache-httpclient/",
	"postmanruntime/",
	"insomnia/",
	"httpie/",
	"apifox/",
	"restsharp/",
	"guzzlehttp/",
}

// Guard inspects inbound requests and decides whether the client is blocked.
// The zero value is not usable; construct with New or NewDefault.
type Guard struct {
	// substrings are lowercased UA fragments; a request is blocked when its
	// (lowercased) User-Agent contains any of them.
	substrings []string
	// blockEmptyUA rejects requests with no User-Agent header. No legitimate
	// interactive client omits it; an empty UA is a strong abuse signal.
	blockEmptyUA bool
}

// Decision is the outcome of inspecting one request.
type Decision struct {
	// Blocked is true when the request should be rejected.
	Blocked bool
	// Reason is a human-readable explanation, surfaced in the 403 body and logs.
	Reason string
	// Matched is the blocklist fragment that triggered the block (empty when the
	// block was due to a missing User-Agent), useful for telemetry.
	Matched string
}

// New builds a Guard from the default blocklist plus any extra UA fragments
// the operator wants to add (e.g. "axios/", "node-fetch"). Extra fragments are
// matched the same way (case-insensitive substring). blockEmptyUA controls
// whether a missing User-Agent is rejected.
func New(extra []string, blockEmptyUA bool) *Guard {
	subs := make([]string, 0, len(DefaultBlockedUASubstrings)+len(extra))
	for _, s := range DefaultBlockedUASubstrings {
		subs = append(subs, strings.ToLower(strings.TrimSpace(s)))
	}
	for _, s := range extra {
		if s = strings.ToLower(strings.TrimSpace(s)); s != "" {
			subs = append(subs, s)
		}
	}
	return &Guard{substrings: subs, blockEmptyUA: blockEmptyUA}
}

// NewDefault builds a Guard with the default blocklist and empty-UA rejection on.
func NewDefault() *Guard {
	return New(nil, true)
}

// Inspect examines the request headers and returns a Decision. It only reads
// the User-Agent — the blocklist is a UA filter by design.
func (g *Guard) Inspect(h http.Header) Decision {
	return g.InspectUA(h.Get("User-Agent"))
}

// InspectUA is Inspect for callers that already hold the User-Agent string.
func (g *Guard) InspectUA(ua string) Decision {
	ua = strings.TrimSpace(ua)
	if ua == "" {
		if g.blockEmptyUA {
			return Decision{Blocked: true, Reason: "missing User-Agent header"}
		}
		return Decision{}
	}
	lower := strings.ToLower(ua)
	for _, frag := range g.substrings {
		if strings.Contains(lower, frag) {
			return Decision{
				Blocked: true,
				Reason:  "client user-agent " + ua + " is a blocked SDK/scripting client (matched " + frag + ")",
				Matched: frag,
			}
		}
	}
	return Decision{}
}
