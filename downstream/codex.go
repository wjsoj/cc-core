package downstream

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// Codex response-direction scrubbing.
//
// The Anthropic side of this package works because everything worth hiding
// arrives as a RESPONSE HEADER, so one allowlist catches it. Codex leaks
// through two channels the header allowlist cannot reach:
//
//  1. The WebSocket upgrade. A 101 is not an ordinary response — a proxy that
//     relays it hands the client `cf-ray` (whose suffix is the Cloudflare
//     datacentre, i.e. where our egress actually sits), `set-cookie` with the
//     upstream's `__cf_bm` bot-management token, `x-models-etag` (a per-account
//     model-catalogue version that correlates two requests to one account), and
//     `x-openai-proxy-wasm`.
//
//  2. The event stream itself. Codex sends its rate-limit state as an in-band
//     `codex.rate_limits` FRAME, not as headers: the serving account's plan,
//     its 7-day utilisation, the exact unix timestamp its window resets, and
//     its credit balance. That is the same disclosure as Anthropic's twelve
//     `anthropic-ratelimit-unified-*` headers, arriving somewhere an allowlist
//     never looks. Two more frame types are pure upstream telemetry, and the
//     `response` object echoed on every lifecycle frame carries
//     `safety_identifier` — literally `user-<chatgpt_user_id>` of the account
//     we are serving from.
//
// Ground truth for all of it: crack/codexapp0.147.0/rows/10 (handshake) and
// rows/13 (one sample per server event type).

// allowedWSHandshakeHeaders is the complete set forwarded from an upstream
// WebSocket 101 to the downstream client. Only the four headers the WebSocket
// protocol itself needs survive.
//
// Deliberately an allowlist, for the same reason the HTTP one is: the failure
// mode of forgetting an entry in a denylist is silent disclosure.
var allowedWSHandshakeHeaders = map[string]bool{
	"Connection":               true, // "upgrade"
	"Upgrade":                  true, // "websocket"
	"Sec-Websocket-Accept":     true, // the challenge response; the client verifies it
	"Sec-Websocket-Extensions": true, // negotiated compression; framing depends on it
	"Sec-Websocket-Protocol":   true, // negotiated subprotocol, when one was offered
}

// Dropped from the 101, and why a future reader should not re-add them:
//
//	cf-ray                    CF edge id; its suffix is the datacentre code
//	                          (e.g. "-AMS"), which locates our egress
//	set-cookie                upstream __cf_bm bot-management state
//	x-models-etag             per-account model catalogue version; correlates
//	                          two requests to one upstream account
//	x-openai-proxy-wasm       upstream infrastructure version
//	cf-cache-status / server  infrastructure fingerprint; also names the vendor
//	report-to / nel           CF reporting endpoints with signed URLs
//	strict-transport-security our edge's call, not OpenAI's
//	referrer-policy           likewise
//	cross-origin-opener-policy, x-content-type-options   likewise
//	date                      net/http writes its own

// WSHandshakeHeaderAllowed reports whether name is forwarded from an upstream
// WebSocket 101 to the downstream client.
func WSHandshakeHeaderAllowed(name string) bool {
	return allowedWSHandshakeHeaders[http.CanonicalHeaderKey(name)]
}

// ScrubWSHandshakeHeaders rewrites an upstream 101's headers in place into the
// set we relay downstream.
//
// Unlike ScrubUpstreamHeaders there is nothing to derive first: a 101 carries
// no rate-limit information (Codex sends that in-band, see ScrubCodexEvent), so
// this is a plain allowlist pass.
func ScrubWSHandshakeHeaders(h http.Header) {
	if h == nil {
		return
	}
	for name := range h {
		if !WSHandshakeHeaderAllowed(name) {
			h.Del(name)
		}
	}
}

// CopyWSHandshakeHeaders scrubs a copy of src and adds the survivors to dst.
//
// Mirrors CopyResponseHeaders: never mutate src (the caller still needs the
// upstream response to classify a non-101 for credential health) and never
// scrub dst (it already holds headers the proxy set itself).
func CopyWSHandshakeHeaders(dst, src http.Header) {
	if dst == nil || src == nil {
		return
	}
	for name, values := range src {
		if !WSHandshakeHeaderAllowed(name) {
			continue
		}
		for _, value := range values {
			dst.Add(name, value)
		}
	}
}

// Codex event types that never reach the client intact.
const (
	// codexEventRateLimits carries the serving account's quota state. Rewritten,
	// not dropped: the client has a legitimate interest in knowing it is being
	// throttled, it just has no business knowing whose quota, how much is left,
	// or when the window rolls over.
	codexEventRateLimits = "codex.rate_limits"
	// codexEventResponseMetadata relays upstream response headers as a frame —
	// x-models-etag, the encrypted x-codex-turn-state, and the name of OpenAI's
	// internal safety-buffering model. Dropped whole; nothing in it is the
	// client's.
	codexEventResponseMetadata = "codex.response.metadata"
	// codexEventWebSocketTiming is OpenAI's internal performance telemetry:
	// engine instance ids ("gpt56sol-codex-a-c321"), queue depths, per-engine
	// cached/uncached prompt token counts. Zero client value, and it describes
	// upstream capacity. Dropped whole.
	codexEventWebSocketTiming = "responsesapi.websocket_timing"
)

// codexResponseObjectFields are deleted from the `response` object echoed on
// every response.created / .in_progress / .completed frame.
//
//	safety_identifier      "user-<chatgpt_user_id>" — the upstream account id
//	service_tier           which tier the serving account resolved to
//	prompt_cache_retention upstream cache policy for our account
//	prompt_cache_key       OUR upstream session id. Two downstream users served
//	                       from one credential would see the same value and
//	                       learn they share an account; it is also the handle a
//	                       caller would need to aim at someone else's upstream
//	                       prompt cache.
var codexResponseObjectFields = []string{
	"safety_identifier",
	"service_tier",
	"prompt_cache_retention",
	"prompt_cache_key",
}

// scrubbedRateLimits is what a codex.rate_limits frame becomes.
//
// `allowed` and `limit_reached` survive because a client that is being refused
// needs to know it is being refused. Everything else — plan_type, the
// primary/secondary window objects with used_percent and reset_at,
// code_review_rate_limits, additional_rate_limits, credits, promo — describes
// the pool, not the request.
//
// One field is SYNTHESIZED rather than dropped: a coarse
// `primary.reset_after_seconds`. Removing the timing outright would be a
// regression dressed as a fix — today the client gets an exact reset_at and can
// back off; scrubbed to bare booleans it would learn it is throttled with no
// idea for how long, and the rational response to that is an immediate retry,
// which turns one throttled credential into a hot loop against the pool. This
// mirrors what CopyResponseHeaders already does on the Anthropic side, where
// Retry-After is derived from the unified reset timestamps *before* they are
// deleted: round up so an early retry cannot happen, cap it so an exhausted
// long window does not publish its boundary.
type scrubbedRateLimits struct {
	Type       string `json:"type"`
	RateLimits struct {
		Allowed      bool                `json:"allowed"`
		LimitReached bool                `json:"limit_reached"`
		Primary      *scrubbedRateWindow `json:"primary,omitempty"`
	} `json:"rate_limits"`
}

type scrubbedRateWindow struct {
	ResetAfterSeconds int64 `json:"reset_after_seconds"`
}

// codexRetryFloorSeconds is the smallest backoff we will advertise. Matches
// retryAfterGranularity: a sub-minute value would round to zero and read as
// "retry now".
const codexRetryFloorSeconds = int64(retryAfterGranularity / time.Second)

// codexRetryCapSeconds bounds the advertised backoff for the same reason
// retryAfterCap does — an exhausted 7-day window would otherwise hand the
// client a delay that describes our window, not their request.
const codexRetryCapSeconds = int64(retryAfterCap / time.Second)

// coarsenCodexResetSeconds rounds a reset delay UP to the next minute and caps
// it, so the emitted value cannot be inverted back to the precise reset
// timestamp it came from. Non-positive input yields 0, meaning "say nothing".
func coarsenCodexResetSeconds(seconds int64) int64 {
	if seconds <= 0 {
		return 0
	}
	if seconds > codexRetryCapSeconds {
		return codexRetryCapSeconds
	}
	if rem := seconds % codexRetryFloorSeconds; rem != 0 {
		seconds += codexRetryFloorSeconds - rem
	}
	if seconds < codexRetryFloorSeconds {
		seconds = codexRetryFloorSeconds
	}
	return seconds
}

// ScrubCodexEvent rewrites one Codex event frame for the downstream client.
//
// It returns the frame to forward and whether to forward it at all; a false
// second return means the frame must be dropped entirely.
//
// Hot path first: the overwhelming majority of frames on a turn are
// `response.output_text.delta` / `response.custom_tool_call_input.delta` (495
// of 541 in the captured turn — 91%), and those must cost one substring scan,
// not a JSON parse. Frames that need no work are returned unchanged, sharing
// the caller's backing array.
func ScrubCodexEvent(frame []byte) ([]byte, bool) {
	if len(frame) == 0 {
		return frame, true
	}
	// A delta frame contains none of the markers below, so it exits here.
	switch {
	case bytes.Contains(frame, []byte(`"`+codexEventRateLimits+`"`)):
		if codexEventType(frame) == codexEventRateLimits {
			return scrubCodexRateLimits(frame)
		}
	case bytes.Contains(frame, []byte(`"`+codexEventResponseMetadata+`"`)):
		if codexEventType(frame) == codexEventResponseMetadata {
			return nil, false
		}
	case bytes.Contains(frame, []byte(`"`+codexEventWebSocketTiming+`"`)):
		if codexEventType(frame) == codexEventWebSocketTiming {
			return nil, false
		}
	}
	// The lifecycle frames are the only ones carrying a full `response` object.
	// Gate on the leaked field names themselves so a frame that happens to
	// mention "response" is not parsed for nothing.
	if containsAnyCodexResponseField(frame) {
		return scrubCodexResponseObject(frame)
	}
	return frame, true
}

// ScrubCodexSSELine is ScrubCodexEvent for the HTTP/SSE form of the same
// stream, where each event arrives as a "data: {...}" line.
//
// Non-data lines (event:, id:, retry:, comments, the blank separator) are
// returned untouched — they carry no payload. A "data: [DONE]" sentinel is
// likewise left alone.
func ScrubCodexSSELine(line []byte) ([]byte, bool) {
	const prefix = "data:"
	if !bytes.HasPrefix(line, []byte(prefix)) {
		return line, true
	}
	payload := line[len(prefix):]
	lead := len(payload) - len(bytes.TrimLeft(payload, " "))
	trimmed := payload[lead:]
	// Preserve a trailing newline exactly as received.
	tail := len(trimmed) - len(bytes.TrimRight(trimmed, "\r\n"))
	suffix := trimmed[len(trimmed)-tail:]
	body := trimmed[:len(trimmed)-tail]

	if len(body) == 0 || body[0] != '{' {
		return line, true
	}
	scrubbed, keep := ScrubCodexEvent(body)
	if !keep {
		return nil, false
	}
	if bytes.Equal(scrubbed, body) {
		return line, true
	}
	out := make([]byte, 0, len(prefix)+lead+len(scrubbed)+len(suffix))
	out = append(out, prefix...)
	out = append(out, payload[:lead]...)
	out = append(out, scrubbed...)
	out = append(out, suffix...)
	return out, true
}

// codexEventType extracts the frame's "type" value without a full parse. It
// exists so the substring gates above cannot be fooled by the type name
// appearing inside some other string (a tool argument, an error message).
//
// Whitespace is tolerated around the colon, and the key is matched only where a
// key can occur. The captured frames are compact, but this function is the ONLY
// thing standing between a rate-limit frame and the client: if upstream ever
// pretty-prints, or moves `type` off the first position, a stricter matcher
// would return "" and the frame would sail through un-scrubbed. Being lenient
// here fails toward scrubbing, which is the safe direction.
func codexEventType(frame []byte) string {
	for i := 0; i+6 < len(frame); i++ {
		if frame[i] != '"' || string(frame[i:i+6]) != `"type"` {
			continue
		}
		j := i + 6
		for j < len(frame) && isSpaceByte(frame[j]) {
			j++
		}
		if j >= len(frame) || frame[j] != ':' {
			continue
		}
		j++
		for j < len(frame) && isSpaceByte(frame[j]) {
			j++
		}
		if j >= len(frame) || frame[j] != '"' {
			continue
		}
		j++
		end := bytes.IndexByte(frame[j:], '"')
		if end < 0 {
			return ""
		}
		return string(frame[j : j+end])
	}
	return ""
}

func isSpaceByte(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

func containsAnyCodexResponseField(frame []byte) bool {
	for _, f := range codexResponseObjectFields {
		if bytes.Contains(frame, []byte(`"`+f+`"`)) {
			return true
		}
	}
	return false
}

func scrubCodexRateLimits(frame []byte) ([]byte, bool) {
	var in struct {
		RateLimits struct {
			Allowed      *bool `json:"allowed"`
			LimitReached *bool `json:"limit_reached"`
			Primary      *struct {
				ResetAfterSeconds *int64 `json:"reset_after_seconds"`
			} `json:"primary"`
			Secondary *struct {
				ResetAfterSeconds *int64 `json:"reset_after_seconds"`
			} `json:"secondary"`
		} `json:"rate_limits"`
	}
	if err := json.Unmarshal(frame, &in); err != nil {
		// Unparseable means we cannot prove it is safe. A rate-limit frame is
		// advisory, so dropping it degrades nothing; forwarding an unknown
		// shape could disclose the very fields this exists to remove.
		return nil, false
	}
	var out scrubbedRateLimits
	out.Type = codexEventRateLimits
	// Absent `allowed` is treated as allowed — matching the captured frame,
	// where a healthy account reports allowed:true / limit_reached:false.
	out.RateLimits.Allowed = in.RateLimits.Allowed == nil || *in.RateLimits.Allowed
	out.RateLimits.LimitReached = in.RateLimits.LimitReached != nil && *in.RateLimits.LimitReached

	// Advertise a backoff only when the client actually needs one. A healthy
	// account reports allowed:true / limit_reached:false with a reset ~7 days
	// out; echoing that would publish the window length for nothing.
	if !out.RateLimits.Allowed || out.RateLimits.LimitReached {
		// Soonest of the two windows, for the same reason earliestUnifiedReset
		// picks the soonest: telling the client to wait for the longer window
		// when a shorter one frees up first keeps it waiting for nothing.
		var soonest int64
		consider := func(v *int64) {
			if v == nil || *v <= 0 {
				return
			}
			if soonest == 0 || *v < soonest {
				soonest = *v
			}
		}
		if in.RateLimits.Primary != nil {
			consider(in.RateLimits.Primary.ResetAfterSeconds)
		}
		if in.RateLimits.Secondary != nil {
			consider(in.RateLimits.Secondary.ResetAfterSeconds)
		}
		if s := coarsenCodexResetSeconds(soonest); s > 0 {
			out.RateLimits.Primary = &scrubbedRateWindow{ResetAfterSeconds: s}
		}
	}

	encoded, err := json.Marshal(out)
	if err != nil {
		return nil, false
	}
	return encoded, true
}

// scrubCodexResponseObject deletes the leaking fields from the `response`
// object and re-encodes.
//
// This is the one place a map round-trip is unavoidable, and it does reorder
// the object's keys. That is acceptable HERE and nowhere else in cc-core: key
// order matters when we are imitating a client UPSTREAM, and this is the
// response we hand our own downstream caller. It runs on 3-4 frames per turn,
// not on the 91% that are deltas.
func scrubCodexResponseObject(frame []byte) ([]byte, bool) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(frame, &obj); err != nil {
		// Leave anything we cannot parse alone rather than dropping a frame the
		// client may need to make progress. The substring gate that got us here
		// is a heuristic; a parse failure most likely means it misfired.
		return frame, true
	}
	raw, ok := obj["response"]
	if !ok {
		return frame, true
	}
	var resp map[string]json.RawMessage
	if err := json.Unmarshal(raw, &resp); err != nil {
		return frame, true
	}
	changed := false
	for _, f := range codexResponseObjectFields {
		if _, present := resp[f]; present {
			delete(resp, f)
			changed = true
		}
	}
	if !changed {
		return frame, true
	}
	newResp, err := json.Marshal(resp)
	if err != nil {
		return frame, true
	}
	obj["response"] = newResp
	encoded, err := json.Marshal(obj)
	if err != nil {
		return frame, true
	}
	return encoded, true
}

// CodexEventDropped reports whether ScrubCodexEvent would drop a frame of this
// type outright, without doing the work. Useful for metrics and for callers
// that want to log what they withheld.
func CodexEventDropped(eventType string) bool {
	switch strings.TrimSpace(eventType) {
	case codexEventResponseMetadata, codexEventWebSocketTiming:
		return true
	}
	return false
}
