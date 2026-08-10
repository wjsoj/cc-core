package downstream

import (
	"net/http"
	"sort"
	"strconv"
	"testing"
	"time"
)

// capturedOAuthResponseHeaders is the header set a real /v1/messages answer from
// api.anthropic.com carries, taken from crack/cc2224/rows/13-v1_messages.json.
// It is the thing this package exists to filter, so the test filters the real
// article rather than a hand-picked subset.
func capturedOAuthResponseHeaders() http.Header {
	h := http.Header{}
	for name, value := range map[string]string{
		"Date":                                                "Fri, 07 Aug 2026 14:43:45 GMT",
		"Content-Type":                                        "text/event-stream; charset=utf-8",
		"Transfer-Encoding":                                   "chunked",
		"Connection":                                          "keep-alive",
		"Cache-Control":                                       "no-cache",
		"Anthropic-Ratelimit-Unified-Status":                  "allowed",
		"Anthropic-Ratelimit-Unified-5h-Status":               "allowed",
		"Anthropic-Ratelimit-Unified-5h-Reset":                "1786123800",
		"Anthropic-Ratelimit-Unified-5h-Utilization":          "0.0",
		"Anthropic-Ratelimit-Unified-7d-Status":               "allowed",
		"Anthropic-Ratelimit-Unified-7d-Reset":                "1786651200",
		"Anthropic-Ratelimit-Unified-7d-Utilization":          "0.06",
		"Anthropic-Ratelimit-Unified-Representative-Claim":    "five_hour",
		"Anthropic-Ratelimit-Unified-Fallback-Percentage":     "0.5",
		"Anthropic-Ratelimit-Unified-Reset":                   "1786123800",
		"Anthropic-Ratelimit-Unified-Overage-Disabled-Reason": "org_level_disabled",
		"Anthropic-Ratelimit-Unified-Overage-Status":          "rejected",
		"Request-Id":                                          "req_011CdoZnTHdYogjzJ6Wuzf6Y",
		"Strict-Transport-Security":                           "max-age=31536000; includeSubDomains; preload",
		"Anthropic-Organization-Id":                           "bf62f90e-ff9c-4d95-a554-17835658b5ef",
		"Anthropic-Workspace-Id":                              "wrkspc_01Mx5eXmqPciXqAJUQDyHRAQ",
		"Traceresponse":                                       "00-6422b82ca8c0f2e0d01a7f43c496ccfa-4c990306f999f2e4-01",
		"Server":                                              "cloudflare",
		"Content-Encoding":                                    "gzip",
		"Vary":                                                "Accept-Encoding",
		"Server-Timing":                                       "x-originResponse;dur=1113",
		"Cf-Cache-Status":                                     "DYNAMIC",
		"X-Robots-Tag":                                        "none",
		"Content-Security-Policy":                             "default-src 'none'; frame-ancestors 'none'",
		"Cf-Ray":                                              "a2770e297a19f3ec-LAX",
	} {
		h.Set(name, value)
	}
	return h
}

func headerNames(h http.Header) []string {
	names := make([]string, 0, len(h))
	for name := range h {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// The headline case: a real captured 200 keeps only the protocol headers.
func TestScrubUpstreamHeadersOnCapturedResponse(t *testing.T) {
	h := capturedOAuthResponseHeaders()
	ScrubUpstreamHeaders(h, time.Unix(1786123000, 0))

	want := []string{"Cache-Control", "Content-Encoding", "Content-Type", "Retry-After", "Vary"}
	got := headerNames(h)
	// Retry-After is synthesized here because the captured response carries
	// future reset timestamps; see the dedicated tests below.
	if len(got) != len(want) {
		t.Fatalf("survivors = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("survivors = %v, want %v", got, want)
		}
	}
}

// Every one of these has a name and a reason. Enumerated individually so a
// future edit that re-admits one fails with the specific header in the message.
func TestScrubbedHeadersAreGoneIndividually(t *testing.T) {
	mustGo := []string{
		"Anthropic-Ratelimit-Unified-Status",
		"Anthropic-Ratelimit-Unified-5h-Reset",
		"Anthropic-Ratelimit-Unified-5h-Utilization",
		"Anthropic-Ratelimit-Unified-7d-Utilization",
		"Anthropic-Ratelimit-Unified-Overage-Status",
		"Anthropic-Ratelimit-Unified-Overage-Disabled-Reason",
		"Anthropic-Organization-Id",
		"Anthropic-Workspace-Id",
		"Request-Id",
		"Traceresponse",
		"Cf-Ray",
		"Cf-Cache-Status",
		"Server",
		"Server-Timing",
		"Strict-Transport-Security",
		"Content-Security-Policy",
		"X-Robots-Tag",
		"Date",
		"Transfer-Encoding",
		"Connection",
	}
	h := capturedOAuthResponseHeaders()
	h.Set("Content-Length", "1234")
	ScrubUpstreamHeaders(h, time.Unix(1786123000, 0))
	for _, name := range mustGo {
		if got := h.Get(name); got != "" {
			t.Errorf("%s survived scrubbing with %q", name, got)
		}
	}
	if got := h.Get("Content-Length"); got != "" {
		t.Errorf("Content-Length survived with %q; net/http computes its own", got)
	}
}

// An upstream Retry-After is authoritative and must not be replaced by a
// derived one.
func TestExistingRetryAfterWins(t *testing.T) {
	h := capturedOAuthResponseHeaders()
	h.Set("Retry-After", "42")
	ScrubUpstreamHeaders(h, time.Unix(1786123000, 0))
	if got := h.Get("Retry-After"); got != "42" {
		t.Errorf("Retry-After = %q, want the upstream value 42", got)
	}
}

func TestSynthesizedRetryAfter(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	cases := []struct {
		name    string
		headers map[string]string
		want    string
	}{
		{
			// 90s away rounds up to a whole minute.
			"rounds up to the minute",
			map[string]string{"Anthropic-Ratelimit-Unified-Reset": strconv.FormatInt(now.Unix()+90, 10)},
			"120",
		},
		{
			// A 5h window must not publish its exact boundary.
			"capped at an hour",
			map[string]string{"Anthropic-Ratelimit-Unified-Reset": strconv.FormatInt(now.Unix()+5*3600, 10)},
			"3600",
		},
		{
			// The soonest window is the useful one, not the representative one.
			"picks the earliest future reset",
			map[string]string{
				"Anthropic-Ratelimit-Unified-Reset":    strconv.FormatInt(now.Unix()+3000, 10),
				"Anthropic-Ratelimit-Unified-5h-Reset": strconv.FormatInt(now.Unix()+600, 10),
				"Anthropic-Ratelimit-Unified-7d-Reset": strconv.FormatInt(now.Unix()+90000, 10),
			},
			"600",
		},
		{
			// Sub-minute delays still need to be a usable positive value.
			"floors at one minute",
			map[string]string{"Anthropic-Ratelimit-Unified-Reset": strconv.FormatInt(now.Unix()+5, 10)},
			"60",
		},
		{
			"past resets are ignored",
			map[string]string{"Anthropic-Ratelimit-Unified-Reset": strconv.FormatInt(now.Unix()-10, 10)},
			"",
		},
		{
			"unparseable resets are ignored",
			map[string]string{"Anthropic-Ratelimit-Unified-Reset": "not-a-timestamp"},
			"",
		},
		{
			"no reset at all",
			map[string]string{"Content-Type": "application/json"},
			"",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			for name, value := range tc.headers {
				h.Set(name, value)
			}
			ScrubUpstreamHeaders(h, now)
			if got := h.Get("Retry-After"); got != tc.want {
				t.Errorf("Retry-After = %q, want %q", got, tc.want)
			}
		})
	}
}

// The gateway's own response is already the shape we aim for, so scrubbing it
// must be close to a no-op — evidence the allowlist is not over-tight.
// Values from crack/thirdparty/rows/01-v1_messages.json.
func TestScrubIsNearlyNoOpOnGatewayResponse(t *testing.T) {
	h := http.Header{}
	for name, value := range map[string]string{
		"Content-Type":     "text/event-stream; charset=utf-8",
		"Vary":             "Accept-Encoding",
		"Content-Encoding": "br",
		"Cache-Control":    "no-cache",
		"Trace-Id":         "06c7e7b6fd2281450554a2b58ad93fe4",
		"X-Mm-Request-Id":  "2022235502865813766_1786295478p7lyjp",
		"Server":           "TencentEdgeOne",
	} {
		h.Set(name, value)
	}
	ScrubUpstreamHeaders(h, time.Now())

	for _, name := range []string{"Content-Type", "Vary", "Content-Encoding", "Cache-Control"} {
		if h.Get(name) == "" {
			t.Errorf("%s was dropped; it is present on the gateway path we model", name)
		}
	}
	// Its correlators go the same way ours do — we are not in the business of
	// relaying anyone's request ids.
	for _, name := range []string{"Trace-Id", "X-Mm-Request-Id", "Server"} {
		if h.Get(name) != "" {
			t.Errorf("%s survived", name)
		}
	}
}

func TestScrubHandlesNilAndEmpty(t *testing.T) {
	ScrubUpstreamHeaders(nil, time.Now())
	h := http.Header{}
	ScrubUpstreamHeaders(h, time.Now())
	if len(h) != 0 {
		t.Errorf("empty header gained %v", headerNames(h))
	}
}

func TestHeaderAllowedIsCaseInsensitive(t *testing.T) {
	for _, name := range []string{"content-type", "Content-Type", "CONTENT-TYPE"} {
		if !HeaderAllowed(name) {
			t.Errorf("HeaderAllowed(%q) = false", name)
		}
	}
	if HeaderAllowed("anthropic-organization-id") {
		t.Error("organization id must never be allowed")
	}
}

// Multi-valued headers must be dropped completely, not just their first value.
func TestScrubDropsAllValuesOfAHeader(t *testing.T) {
	h := http.Header{}
	h.Add("Set-Cookie", "a=1")
	h.Add("Set-Cookie", "b=2")
	ScrubUpstreamHeaders(h, time.Now())
	if len(h.Values("Set-Cookie")) != 0 {
		t.Errorf("Set-Cookie values survived: %v", h.Values("Set-Cookie"))
	}
}

// The proxy sets headers of its own before the upstream response is written —
// scrubbing the destination would delete them. This is the mistake
// CopyResponseHeaders exists to make impossible.
func TestCopyResponseHeadersKeepsProxyOwnHeaders(t *testing.T) {
	dst := http.Header{}
	dst.Set("X-Provider-Restricted", "anthropic")
	dst.Set("Retry-After", "5")

	src := capturedOAuthResponseHeaders()
	CopyResponseHeaders(dst, src, time.Unix(1786123000, 0))

	if got := dst.Get("X-Provider-Restricted"); got != "anthropic" {
		t.Errorf("proxy header was dropped: %q", got)
	}
	if got := dst.Get("Anthropic-Organization-Id"); got != "" {
		t.Errorf("organization id reached the client: %q", got)
	}
	if got := dst.Get("Content-Type"); got == "" {
		t.Error("Content-Type was not copied")
	}
}

// The retry loop re-reads a withheld response's rate-limit headers after the
// point where a copy may already have happened, so src must survive intact.
func TestCopyResponseHeadersDoesNotMutateSource(t *testing.T) {
	src := capturedOAuthResponseHeaders()
	before := src.Get("Anthropic-Ratelimit-Unified-5h-Reset")

	CopyResponseHeaders(http.Header{}, src, time.Unix(1786123000, 0))

	if got := src.Get("Anthropic-Ratelimit-Unified-5h-Reset"); got != before {
		t.Errorf("source header map was mutated: %q -> %q", before, got)
	}
	if src.Get("Anthropic-Organization-Id") == "" {
		t.Error("source lost its organization id")
	}
}

func TestCopyResponseHeadersHandlesNil(t *testing.T) {
	CopyResponseHeaders(nil, capturedOAuthResponseHeaders(), time.Now())
	CopyResponseHeaders(http.Header{}, nil, time.Now())
}
