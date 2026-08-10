// Package downstream decides what a reverse proxy is willing to send back to
// the client it serves.
//
// Every other package here shapes what we send UPSTREAM so it looks like a real
// client. This one is the opposite direction: the response we return should look
// like an ordinary Anthropic-compatible gateway, not like a transparent pipe
// from our credential pool.
//
// The concrete problem: forwarding upstream response headers verbatim hands the
// downstream user our pool's operational state. A single 200 from
// api.anthropic.com carries twelve `anthropic-ratelimit-unified-*` headers —
// the serving account's subscription tier, its 5h and 7d utilisation, its
// overage status, and the exact unix timestamps its windows reset — plus
// `anthropic-organization-id`, `anthropic-workspace-id`, the upstream
// `request-id`, and Cloudflare's `cf-ray` (see crack/cc2224/rows/13). None of
// that is the caller's, and together it is enough to fingerprint and probe the
// pool.
//
// The captured third-party gateway returns none of it — only content-type,
// cache-control, vary, content-encoding and its own correlators — and real
// Claude Code works against it unchanged (crack/thirdparty/SPEC.md §4). So an
// allowlist is known-safe behaviour, not a guess.
//
// # Ordering
//
// Scrubbing must happen AFTER the proxy has read the rate-limit headers for its
// own scheduling (cooldowns, quota marking) and BEFORE the headers are copied
// to the client. Both forks already parse then write, so the natural call site
// is the response-writing helper itself.
//
// Scrub the UPSTREAM header map, never the client-facing one: the proxy sets
// headers of its own on the way out, and an allowlist applied to the
// destination would delete those too.
package downstream

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// allowedResponseHeaders is the complete set forwarded downstream, canonicalised.
//
// Deliberately an allowlist. A denylist would need editing every time Anthropic
// adds a header, and the failure mode of forgetting is silent disclosure —
// exactly how `anthropic-workspace-id` reached clients unnoticed until the
// 2026-08 capture put a name to it.
var allowedResponseHeaders = map[string]bool{
	// The client cannot parse the body without it.
	"Content-Type": true,
	// SSE correctness: real streams are no-cache and intermediaries honour it.
	"Cache-Control": true,
	// The one piece of rate-limit information the caller legitimately needs.
	"Retry-After": true,
	// Present on both captured paths; caching intermediaries need it.
	"Vary": true,
	// Only survives when we did NOT decode the body. stream.Decompress deletes
	// it for gzip/br; an encoding it passes through (zstd, deflate) still needs
	// to be declared or the client cannot read the bytes.
	"Content-Encoding": true,
}

// Headers dropped for reasons worth keeping straight, since a future reader
// will be tempted to re-add some of them:
//
//	anthropic-ratelimit-unified-*   our account's quota state, 12 headers
//	anthropic-organization-id       our org UUID
//	anthropic-workspace-id          our workspace UUID
//	request-id                      upstream correlator for OUR request
//	traceresponse                   upstream trace correlator
//	cf-ray / cf-cache-status        Cloudflare correlators; also say "Anthropic"
//	server / server-timing          upstream infrastructure and its latency
//	strict-transport-security       our edge's call to make, not Anthropic's
//	content-security-policy         meaningless on an API response we relay
//	x-robots-tag                    likewise
//	date                            net/http writes its own
//	content-length                  net/http computes it; the upstream value is
//	                                wrong whenever the body was decompressed or
//	                                rewritten

// HeaderAllowed reports whether name is forwarded to the downstream client.
func HeaderAllowed(name string) bool {
	return allowedResponseHeaders[http.CanonicalHeaderKey(name)]
}

// retryAfterCap bounds a synthesized Retry-After.
//
// An exhausted 5h window would otherwise produce a delay of up to five hours,
// which both publishes the exact boundary of our pool's window and is a worse
// client experience than retrying sooner and being told again. One hour is the
// longest wait worth handing out.
const retryAfterCap = time.Hour

// retryAfterGranularity rounds a synthesized delay up, so the value cannot be
// used to reconstruct the precise reset timestamp it came from.
const retryAfterGranularity = time.Minute

// unifiedResetHeaders are the reset timestamps a synthesized Retry-After may be
// derived from, in order of preference: the representative one first, then the
// shorter window, then the longer.
var unifiedResetHeaders = []string{
	"Anthropic-Ratelimit-Unified-Reset",
	"Anthropic-Ratelimit-Unified-5h-Reset",
	"Anthropic-Ratelimit-Unified-7d-Reset",
}

// ScrubUpstreamHeaders rewrites h in place into the set we return downstream.
//
// It first preserves the caller's ability to back off — deriving Retry-After
// from the unified reset timestamps when upstream sent none — and only then
// applies the allowlist. Doing it in that order is the whole point of having one
// function rather than two: the information Retry-After is derived from is
// deleted moments later.
//
// now is injected so callers can test the derivation; pass time.Now().
func ScrubUpstreamHeaders(h http.Header, now time.Time) {
	if h == nil {
		return
	}
	ensureRetryAfter(h, now)
	for name := range h {
		if !HeaderAllowed(name) {
			h.Del(name)
		}
	}
}

// CopyResponseHeaders scrubs a copy of src and adds the survivors to dst,
// leaving whatever dst already carries in place.
//
// This is the entry point response-writing helpers should use. It removes the
// two ways of getting this wrong: scrubbing dst (which would delete the proxy's
// own headers, set before the upstream response is written) and mutating src
// (which the caller may still need — the retry loop re-reads a withheld
// response's rate-limit headers).
func CopyResponseHeaders(dst, src http.Header, now time.Time) {
	if dst == nil || src == nil {
		return
	}
	scrubbed := make(http.Header, len(src))
	for name, values := range src {
		scrubbed[name] = values
	}
	ScrubUpstreamHeaders(scrubbed, now)
	for name, values := range scrubbed {
		for _, value := range values {
			dst.Add(name, value)
		}
	}
}

func ensureRetryAfter(h http.Header, now time.Time) {
	if strings.TrimSpace(h.Get("Retry-After")) != "" {
		return
	}
	reset, ok := earliestUnifiedReset(h, now)
	if !ok {
		return
	}
	delay := reset.Sub(now)
	if delay <= 0 {
		return
	}
	if delay > retryAfterCap {
		delay = retryAfterCap
	}
	// Round up: a client that waits slightly too long is correct, one that
	// retries slightly too early is not.
	delay = delay.Round(retryAfterGranularity)
	if delay < retryAfterGranularity {
		delay = retryAfterGranularity
	}
	h.Set("Retry-After", strconv.Itoa(int(delay.Seconds())))
}

// earliestUnifiedReset returns the soonest future reset among the unified
// headers. Soonest rather than representative: handing the client the longest
// window when a shorter one frees up first would keep it waiting for nothing.
func earliestUnifiedReset(h http.Header, now time.Time) (time.Time, bool) {
	var best time.Time
	found := false
	for _, name := range unifiedResetHeaders {
		raw := strings.TrimSpace(h.Get(name))
		if raw == "" {
			continue
		}
		seconds, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			continue
		}
		reset := time.Unix(seconds, 0)
		if !reset.After(now) {
			continue
		}
		if !found || reset.Before(best) {
			best = reset
			found = true
		}
	}
	return best, found
}
