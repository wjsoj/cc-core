package downstream

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
)

// The captured 101 from crack/codexapp0.147.0/rows/10. Everything except the
// four WebSocket protocol headers must be withheld.
func TestScrubWSHandshakeHeaders(t *testing.T) {
	h := http.Header{}
	for name, value := range map[string]string{
		"Date":                       "Fri, 14 Aug 2026 16:30:05 GMT",
		"Connection":                 "upgrade",
		"Upgrade":                    "websocket",
		"Sec-Websocket-Accept":       "xD7gQxaN99J7wwURY+DAuZxBEiw=",
		"Sec-Websocket-Extensions":   "permessage-deflate",
		"Server":                     "cloudflare",
		"X-Models-Etag":              `W/"f978193f34ff002d2389e61fcc51c735"`,
		"X-Openai-Proxy-Wasm":        "v0.1",
		"Cf-Cache-Status":            "DYNAMIC",
		"Strict-Transport-Security":  "max-age=31536000",
		"X-Content-Type-Options":     "nosniff",
		"Set-Cookie":                 "__cf_bm=abc; HttpOnly",
		"Report-To":                  `{"group":"cf-nel"}`,
		"Nel":                        `{"report_to":"cf-nel"}`,
		"Referrer-Policy":            "strict-origin-when-cross-origin",
		"Cross-Origin-Opener-Policy": "same-origin-allow-popups",
		"Cf-Ray":                     "a2b157912d8fad9f-AMS",
	} {
		h.Set(name, value)
	}
	ScrubWSHandshakeHeaders(h)

	want := map[string]string{
		"Connection":               "upgrade",
		"Upgrade":                  "websocket",
		"Sec-Websocket-Accept":     "xD7gQxaN99J7wwURY+DAuZxBEiw=",
		"Sec-Websocket-Extensions": "permessage-deflate",
	}
	if len(h) != len(want) {
		t.Errorf("survivors = %v, want exactly %v", h, want)
	}
	for name, value := range want {
		if got := h.Get(name); got != value {
			t.Errorf("%s = %q, want %q", name, got, value)
		}
	}
	// The datacentre suffix is the single worst one: it locates our egress.
	if h.Get("Cf-Ray") != "" {
		t.Error("cf-ray must never reach the client — its suffix is the CF datacentre")
	}
	if h.Get("Set-Cookie") != "" {
		t.Error("set-cookie carries the upstream __cf_bm token")
	}
}

// CopyWSHandshakeHeaders must not mutate src (the caller still classifies a
// non-101 for credential health) and must not clear dst.
func TestCopyWSHandshakeHeadersLeavesSrcAndDstAlone(t *testing.T) {
	src := http.Header{}
	src.Set("Upgrade", "websocket")
	src.Set("Cf-Ray", "abc-AMS")

	dst := http.Header{}
	dst.Set("X-Proxy-Own-Header", "keep me")

	CopyWSHandshakeHeaders(dst, src)

	if src.Get("Cf-Ray") == "" {
		t.Error("src must not be mutated")
	}
	if dst.Get("X-Proxy-Own-Header") != "keep me" {
		t.Error("dst's own headers must survive")
	}
	if dst.Get("Upgrade") != "websocket" {
		t.Error("allowed header did not reach dst")
	}
	if dst.Get("Cf-Ray") != "" {
		t.Error("disallowed header reached dst")
	}
}

const capturedRateLimitsFrame = `{"type":"codex.rate_limits","plan_type":"plus",` +
	`"rate_limits":{"allowed":true,"limit_reached":false,` +
	`"primary":{"used_percent":0,"window_minutes":10080,"reset_after_seconds":604739,"reset_at":1787329759},` +
	`"secondary":null},"code_review_rate_limits":null,"additional_rate_limits":null,` +
	`"credits":{"has_credits":false,"unlimited":false,"balance":"0"},"promo":null}`

// This frame is Codex's equivalent of Anthropic's twelve unified rate-limit
// headers. It must survive only as allowed/limit_reached.
func TestScrubCodexEventRewritesRateLimits(t *testing.T) {
	got, keep := ScrubCodexEvent([]byte(capturedRateLimitsFrame))
	if !keep {
		t.Fatal("rate_limits must be rewritten, not dropped")
	}
	for _, leak := range []string{
		"plan_type", "used_percent", "reset_at", "reset_after_seconds",
		"window_minutes", "credits", "balance", "promo",
		"code_review_rate_limits", "additional_rate_limits", "primary", "secondary",
	} {
		if bytes.Contains(got, []byte(leak)) {
			t.Errorf("scrubbed frame still leaks %q: %s", leak, got)
		}
	}
	var out struct {
		Type       string `json:"type"`
		RateLimits struct {
			Allowed      bool `json:"allowed"`
			LimitReached bool `json:"limit_reached"`
		} `json:"rate_limits"`
	}
	if err := json.Unmarshal(got, &out); err != nil {
		t.Fatalf("scrubbed frame is not valid JSON: %v (%s)", err, got)
	}
	if out.Type != "codex.rate_limits" {
		t.Errorf("type = %q, want codex.rate_limits", out.Type)
	}
	if !out.RateLimits.Allowed || out.RateLimits.LimitReached {
		t.Errorf("allowed/limit_reached not preserved: %+v", out.RateLimits)
	}
}

// A throttled account must still be able to tell the client it is throttled.
func TestScrubCodexEventPreservesLimitReached(t *testing.T) {
	frame := `{"type":"codex.rate_limits","plan_type":"pro",` +
		`"rate_limits":{"allowed":false,"limit_reached":true,` +
		`"primary":{"used_percent":100,"reset_at":1787329759}}}`
	got, keep := ScrubCodexEvent([]byte(frame))
	if !keep {
		t.Fatal("frame must be forwarded")
	}
	var out struct {
		RateLimits struct {
			Allowed      bool `json:"allowed"`
			LimitReached bool `json:"limit_reached"`
		} `json:"rate_limits"`
	}
	if err := json.Unmarshal(got, &out); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if out.RateLimits.Allowed {
		t.Error("allowed=false must survive")
	}
	if !out.RateLimits.LimitReached {
		t.Error("limit_reached=true must survive")
	}
	if bytes.Contains(got, []byte("reset_at")) {
		t.Error("reset_at must not survive even when limited")
	}
}

// An unparseable rate-limit frame must fail closed: it is advisory, so dropping
// it costs nothing and forwarding an unknown shape could disclose the fields
// this function exists to remove.
func TestScrubCodexEventDropsUnparseableRateLimits(t *testing.T) {
	if _, keep := ScrubCodexEvent([]byte(`{"type":"codex.rate_limits", truncated`)); keep {
		t.Error("an unparseable rate_limits frame must be dropped, not forwarded")
	}
}

func TestScrubCodexEventDropsTelemetryFrames(t *testing.T) {
	for _, frame := range []string{
		`{"type":"codex.response.metadata","headers":{"x-models-etag":"W/\"abc\"","x-codex-turn-state":"gAAAAA"}}`,
		`{"type":"responsesapi.websocket_timing","timing_metrics":{"engine_ids":"gpt56sol-codex-a-c321","engine_queue_max_ms":1041.0}}`,
	} {
		if _, keep := ScrubCodexEvent([]byte(frame)); keep {
			t.Errorf("frame must be dropped: %s", frame)
		}
	}
}

// safety_identifier is literally "user-<chatgpt_user_id>" of the serving
// account — the single worst field in the stream.
func TestScrubCodexEventStripsResponseObjectFields(t *testing.T) {
	frame := `{"type":"response.created","sequence_number":0,"response":` +
		`{"id":"resp_abc","model":"gpt-5.6-sol","safety_identifier":"user-XYZ",` +
		`"service_tier":"default","prompt_cache_retention":"24h","store":false}}`
	got, keep := ScrubCodexEvent([]byte(frame))
	if !keep {
		t.Fatal("lifecycle frames must be forwarded, not dropped")
	}
	for _, leak := range []string{"safety_identifier", "user-XYZ", "service_tier", "prompt_cache_retention"} {
		if bytes.Contains(got, []byte(leak)) {
			t.Errorf("scrubbed frame still leaks %q: %s", leak, got)
		}
	}
	var out struct {
		Type     string `json:"type"`
		Response struct {
			ID    string `json:"id"`
			Model string `json:"model"`
			Store *bool  `json:"store"`
		} `json:"response"`
	}
	if err := json.Unmarshal(got, &out); err != nil {
		t.Fatalf("scrubbed frame is not valid JSON: %v (%s)", err, got)
	}
	if out.Type != "response.created" || out.Response.ID != "resp_abc" || out.Response.Model != "gpt-5.6-sol" {
		t.Errorf("legitimate fields were damaged: %s", got)
	}
	if out.Response.Store == nil || *out.Response.Store {
		t.Errorf("store field was damaged: %s", got)
	}
}

// The hot path: 91% of a turn's frames are deltas and must be returned
// untouched, sharing the caller's backing array.
func TestScrubCodexEventLeavesDeltaFramesUntouched(t *testing.T) {
	for _, frame := range []string{
		`{"type":"response.output_text.delta","delta":"hello","item_id":"msg_1","obfuscation":"xyz","sequence_number":42}`,
		`{"type":"response.custom_tool_call_input.delta","delta":".exec","item_id":"ctc_1","sequence_number":10}`,
		`{"type":"response.output_item.added","output_index":1,"item":{"id":"rs_1","type":"reasoning"}}`,
	} {
		got, keep := ScrubCodexEvent([]byte(frame))
		if !keep {
			t.Fatalf("delta frame must be forwarded: %s", frame)
		}
		if string(got) != frame {
			t.Errorf("delta frame was rewritten:\n got %s\nwant %s", got, frame)
		}
	}
}

// The substring gates must not be fooled by a type name appearing inside a
// tool argument or an assistant message.
func TestScrubCodexEventIgnoresTypeNameInPayload(t *testing.T) {
	frame := `{"type":"response.output_text.delta","delta":"the codex.rate_limits event is documented at","sequence_number":7}`
	got, keep := ScrubCodexEvent([]byte(frame))
	if !keep {
		t.Fatal("a delta frame merely mentioning an event name must not be dropped")
	}
	if string(got) != frame {
		t.Errorf("frame was rewritten: %s", got)
	}
}

func TestScrubCodexEventEmptyFrame(t *testing.T) {
	if got, keep := ScrubCodexEvent(nil); !keep || len(got) != 0 {
		t.Errorf("empty frame handling: got %q keep=%v", got, keep)
	}
}

func TestScrubCodexSSELine(t *testing.T) {
	t.Run("drops telemetry", func(t *testing.T) {
		line := []byte(`data: {"type":"responsesapi.websocket_timing","timing_metrics":{"engine_ids":"e"}}` + "\n")
		if _, keep := ScrubCodexSSELine(line); keep {
			t.Error("telemetry data line must be dropped")
		}
	})
	t.Run("rewrites rate limits and keeps framing", func(t *testing.T) {
		line := []byte("data: " + capturedRateLimitsFrame + "\n")
		got, keep := ScrubCodexSSELine(line)
		if !keep {
			t.Fatal("rate_limits line must be forwarded")
		}
		if !bytes.HasPrefix(got, []byte("data: ")) {
			t.Errorf("SSE prefix lost: %q", got)
		}
		if !bytes.HasSuffix(got, []byte("\n")) {
			t.Errorf("trailing newline lost: %q", got)
		}
		if bytes.Contains(got, []byte("reset_at")) {
			t.Errorf("line still leaks reset_at: %s", got)
		}
	})
	t.Run("passes non-data lines through", func(t *testing.T) {
		for _, line := range []string{
			"event: response.completed\n",
			": keepalive comment\n",
			"\n",
			"data: [DONE]\n",
			"id: 42\n",
		} {
			got, keep := ScrubCodexSSELine([]byte(line))
			if !keep || string(got) != line {
				t.Errorf("line %q was altered to %q (keep=%v)", line, got, keep)
			}
		}
	})
	t.Run("passes clean data lines through unchanged", func(t *testing.T) {
		line := `data: {"type":"response.output_text.delta","delta":"hi"}` + "\n"
		got, keep := ScrubCodexSSELine([]byte(line))
		if !keep || string(got) != line {
			t.Errorf("clean line altered: %q", got)
		}
	})
}

func TestCodexEventDropped(t *testing.T) {
	for _, tc := range []struct {
		event string
		want  bool
	}{
		{"codex.response.metadata", true},
		{"responsesapi.websocket_timing", true},
		{"  responsesapi.websocket_timing  ", true},
		{"codex.rate_limits", false}, // rewritten, not dropped
		{"response.output_text.delta", false},
		{"", false},
	} {
		if got := CodexEventDropped(tc.event); got != tc.want {
			t.Errorf("CodexEventDropped(%q) = %v, want %v", tc.event, got, tc.want)
		}
	}
}

// Guard against the Anthropic and Codex allowlists drifting into each other:
// they answer different questions and share no entries by accident.
func TestWSAllowlistIsSeparateFromHTTPAllowlist(t *testing.T) {
	for name := range allowedWSHandshakeHeaders {
		if allowedResponseHeaders[name] {
			t.Errorf("header %q is in both allowlists; verify that is intended", name)
		}
	}
	if WSHandshakeHeaderAllowed("Content-Type") {
		t.Error("a 101 has no body; Content-Type must not be relayed from it")
	}
	if HeaderAllowed("Sec-Websocket-Accept") {
		t.Error("the HTTP allowlist must not carry WebSocket handshake headers")
	}
}

// --- regressions from the adversarial review -------------------------------

// codexEventType is the only thing between a rate-limit frame and the client.
// A stricter matcher that returns "" on a pretty-printed or reordered frame
// would let it through un-scrubbed, so leniency here fails toward scrubbing.
func TestCodexEventTypeToleratesWhitespaceAndPosition(t *testing.T) {
	for _, tc := range []struct{ name, frame, want string }{
		{"compact", `{"type":"codex.rate_limits","rate_limits":{}}`, "codex.rate_limits"},
		{"space after colon", `{"type": "codex.rate_limits","rate_limits":{}}`, "codex.rate_limits"},
		{"space before colon", `{"type" : "codex.rate_limits"}`, "codex.rate_limits"},
		{"pretty printed", "{\n  \"type\": \"codex.rate_limits\",\n  \"rate_limits\": {}\n}", "codex.rate_limits"},
		{"type not first", `{"sequence_number":3,"type":"codex.rate_limits"}`, "codex.rate_limits"},
		{"absent", `{"sequence_number":3}`, ""},
	} {
		if got := codexEventType([]byte(tc.frame)); got != tc.want {
			t.Errorf("%s: codexEventType = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// The same leniency must not turn into a false positive that eats real output.
func TestCodexEventTypeIgnoresLookalikeKeys(t *testing.T) {
	for _, frame := range []string{
		`{"plan_type":"codex.rate_limits","type":"response.output_text.delta"}`,
		`{"type":"response.output_text.delta","delta":"\"type\":\"codex.rate_limits\""}`,
	} {
		if got := codexEventType([]byte(frame)); got != "response.output_text.delta" {
			t.Errorf("codexEventType = %q, want response.output_text.delta, for %s", got, frame)
		}
	}
}

// A pretty-printed rate-limit frame must still be scrubbed.
func TestScrubCodexEventScrubsPrettyPrintedRateLimits(t *testing.T) {
	frame := "{\n  \"type\": \"codex.rate_limits\",\n  \"plan_type\": \"pro\",\n" +
		"  \"rate_limits\": {\"allowed\": true, \"limit_reached\": false,\n" +
		"    \"primary\": {\"used_percent\": 42, \"reset_at\": 1787329759}}\n}"
	got, keep := ScrubCodexEvent([]byte(frame))
	if !keep {
		t.Fatal("frame must be forwarded")
	}
	for _, leak := range []string{"plan_type", "used_percent", "reset_at"} {
		if bytes.Contains(got, []byte(leak)) {
			t.Errorf("pretty-printed frame still leaks %q: %s", leak, got)
		}
	}
}

// A model that emits the literal text of a rate-limit frame must not have its
// output silently discarded — that would eat the assistant's answer.
func TestScrubCodexEventDoesNotEatModelOutput(t *testing.T) {
	for _, frame := range []string{
		`{"type":"response.output_text.delta","delta":"{\"type\":\"codex.rate_limits\"}","sequence_number":1}`,
		`{"type":"response.output_text.delta","delta":"codex.rate_limits","sequence_number":2}`,
		`{"type":"response.output_text.delta","delta":"responsesapi.websocket_timing","sequence_number":3}`,
	} {
		got, keep := ScrubCodexEvent([]byte(frame))
		if !keep {
			t.Errorf("model output was discarded: %s", frame)
			continue
		}
		if string(got) != frame {
			t.Errorf("model output was rewritten:\n got %s\nwant %s", got, frame)
		}
	}
}

// Scrubbing the timing to bare booleans would leave a throttled client with no
// idea how long to wait, and the rational response to that is an immediate
// retry — turning one throttled credential into a hot loop.
func TestScrubCodexRateLimitsKeepsCoarseBackoffWhenLimited(t *testing.T) {
	frame := `{"type":"codex.rate_limits","plan_type":"plus",` +
		`"rate_limits":{"allowed":false,"limit_reached":true,` +
		`"primary":{"used_percent":100,"reset_after_seconds":143,"reset_at":1787329759},` +
		`"secondary":{"used_percent":50,"reset_after_seconds":900}}}`
	got, keep := ScrubCodexEvent([]byte(frame))
	if !keep {
		t.Fatal("frame must be forwarded")
	}
	var out struct {
		RateLimits struct {
			LimitReached bool `json:"limit_reached"`
			Primary      *struct {
				ResetAfterSeconds int64 `json:"reset_after_seconds"`
			} `json:"primary"`
		} `json:"rate_limits"`
	}
	if err := json.Unmarshal(got, &out); err != nil {
		t.Fatalf("invalid JSON: %v (%s)", err, got)
	}
	if !out.RateLimits.LimitReached {
		t.Error("limit_reached must survive")
	}
	if out.RateLimits.Primary == nil {
		t.Fatalf("a limited client needs a backoff hint: %s", got)
	}
	// Soonest window (143s), rounded UP to the next minute so an early retry
	// cannot happen, and coarse enough not to reveal the exact reset.
	if out.RateLimits.Primary.ResetAfterSeconds != 180 {
		t.Errorf("reset_after_seconds = %d, want 180 (143s rounded up to the minute)",
			out.RateLimits.Primary.ResetAfterSeconds)
	}
	if bytes.Contains(got, []byte("reset_at")) || bytes.Contains(got, []byte("used_percent")) {
		t.Errorf("exact window state leaked: %s", got)
	}
}

// A healthy account reports a reset roughly a week out. Echoing that would
// publish the window length for no benefit.
func TestScrubCodexRateLimitsOmitsBackoffWhenHealthy(t *testing.T) {
	got, keep := ScrubCodexEvent([]byte(capturedRateLimitsFrame))
	if !keep {
		t.Fatal("frame must be forwarded")
	}
	if bytes.Contains(got, []byte("reset_after_seconds")) {
		t.Errorf("an unthrottled account must not advertise a backoff: %s", got)
	}
}

func TestCoarsenCodexResetSeconds(t *testing.T) {
	for _, tc := range []struct{ in, want int64 }{
		{0, 0},
		{-5, 0},
		{1, 60},
		{59, 60},
		{60, 60},
		{61, 120},
		{143, 180},
		{3600, 3600},
		{604739, 3600}, // an exhausted 7-day window is capped, not published
	} {
		if got := coarsenCodexResetSeconds(tc.in); got != tc.want {
			t.Errorf("coarsenCodexResetSeconds(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// prompt_cache_key is OUR upstream session id: two downstream users served from
// one credential would otherwise see the same value and learn they share an
// account.
func TestScrubCodexEventStripsPromptCacheKey(t *testing.T) {
	frame := `{"type":"response.completed","response":{"id":"resp_1",` +
		`"prompt_cache_key":"01a0034b-0000-7000-8000-000000000001",` +
		`"usage":{"input_tokens":22735,"input_tokens_details":{"cached_tokens":22272},` +
		`"output_tokens":106,"total_tokens":22841}}}`
	got, keep := ScrubCodexEvent([]byte(frame))
	if !keep {
		t.Fatal("frame must be forwarded")
	}
	if bytes.Contains(got, []byte("prompt_cache_key")) {
		t.Errorf("prompt_cache_key survived: %s", got)
	}
	// Billing must be untouched — and exact, not reformatted into a float.
	var out struct {
		Response struct {
			Usage struct {
				InputTokens  int64 `json:"input_tokens"`
				OutputTokens int64 `json:"output_tokens"`
				TotalTokens  int64 `json:"total_tokens"`
				Details      struct {
					CachedTokens int64 `json:"cached_tokens"`
				} `json:"input_tokens_details"`
			} `json:"usage"`
		} `json:"response"`
	}
	if err := json.Unmarshal(got, &out); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	u := out.Response.Usage
	if u.InputTokens != 22735 || u.OutputTokens != 106 || u.TotalTokens != 22841 || u.Details.CachedTokens != 22272 {
		t.Errorf("usage was damaged: %+v", u)
	}
	if bytes.Contains(got, []byte("e+")) || bytes.Contains(got, []byte("E+")) {
		t.Errorf("a token count was reformatted into scientific notation: %s", got)
	}
}
