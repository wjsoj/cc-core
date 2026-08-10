package codexerr

import (
	"encoding/json"
	"testing"
)

func TestClassify(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload string
		want    Class
	}{
		// Capacity shed — the frames that used to end the user's session.
		{"overloaded", `{"type":"error","error":{"code":"server_is_overloaded","message":"overloaded"}}`, ClassRetryable},
		{"slow_down", `{"type":"error","error":{"code":"slow_down","message":"slow down"}}`, ClassRetryable},
		{"rate limit", `{"type":"error","error":{"type":"rate_limit_error","code":"rate_limit_exceeded","message":"limited"}}`, ClassRetryable},
		{"quota", `{"type":"error","error":{"code":"insufficient_quota"}}`, ClassRetryable},
		{"usage not included", `{"type":"error","error":{"code":"usage_not_included"}}`, ClassRetryable},
		// The nested shape the terminal event uses.
		{"response.failed overloaded", `{"type":"response.failed","response":{"error":{"code":"server_is_overloaded"}}}`, ClassRetryable},
		{"response.failed policy", `{"type":"response.failed","response":{"error":{"code":"content_policy_violation"}}}`, ClassFatal},
		// The request's own fault — must reach the client untouched.
		{"content policy", `{"type":"error","error":{"type":"invalid_request_error","code":"content_policy_violation","message":"blocked"}}`, ClassFatal},
		{"invalid prompt", `{"type":"error","error":{"code":"invalid_prompt"}}`, ClassFatal},
		{"cyber policy", `{"type":"error","error":{"code":"cyber_policy"}}`, ClassFatal},
		// Unrecognised codes default to fatal — never swallow an unknown error.
		{"unknown code", `{"type":"error","error":{"code":"brand_new_thing"}}`, ClassFatal},
		{"error with no code", `{"type":"error","error":{"message":"just a message"}}`, ClassFatal},
		// Ordinary stream traffic.
		{"created", `{"type":"response.created","response":{"id":"resp_1"}}`, ClassNone},
		{"delta", `{"type":"response.output_text.delta","delta":"hi"}`, ClassNone},
		{"completed", `{"type":"response.completed","response":{"usage":{"input_tokens":5}}}`, ClassNone},
		{"garbage", `not json at all`, ClassNone},
		{"empty", ``, ClassNone},
		// A payload merely mentioning "error" in prose is not an error frame.
		{"prose mentioning error", `{"type":"response.output_text.delta","delta":"the \"error\" was mine"}`, ClassNone},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Classify([]byte(tc.payload)); got != tc.want {
				t.Errorf("Classify() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDemoteCapacityCode(t *testing.T) {
	// Only the two session-terminating codes get demoted, and only the code
	// changes — the message the user reads must survive verbatim.
	in := `{"type":"error","error":{"code":"server_is_overloaded","message":"we are overloaded"}}`
	out, changed := DemoteCapacityCode([]byte(in))
	if !changed {
		t.Fatal("server_is_overloaded should be demoted")
	}
	var got struct {
		Type  string `json:"type"`
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("demoted payload is not valid JSON: %v", err)
	}
	if got.Error.Code != DemotedCode {
		t.Errorf("code = %q, want %q", got.Error.Code, DemotedCode)
	}
	if got.Error.Message != "we are overloaded" {
		t.Errorf("message must survive verbatim, got %q", got.Error.Message)
	}
	if got.Type != "error" {
		t.Errorf("type must survive, got %q", got.Type)
	}

	// Nested response.failed shape.
	nested := `{"type":"response.failed","response":{"error":{"code":"slow_down","message":"easy"}}}`
	out2, changed2 := DemoteCapacityCode([]byte(nested))
	if !changed2 {
		t.Fatal("nested slow_down should be demoted")
	}
	if c, _ := code(out2); c != DemotedCode {
		t.Errorf("nested code = %q, want %q", c, DemotedCode)
	}

	// Everything else is returned byte-identical and reports no change — a
	// caller may forward the original without re-checking.
	for _, untouched := range []string{
		`{"type":"error","error":{"code":"rate_limit_exceeded","message":"limited"}}`,
		`{"type":"error","error":{"code":"content_policy_violation"}}`,
		`{"type":"response.completed","response":{}}`,
		`not json`,
	} {
		got, changed := DemoteCapacityCode([]byte(untouched))
		if changed {
			t.Errorf("DemoteCapacityCode(%s) reported a change", untouched)
		}
		if string(got) != untouched {
			t.Errorf("DemoteCapacityCode(%s) = %s, want it returned unchanged", untouched, got)
		}
	}
}

// The demoted code must land outside the CLI's session-ending set, otherwise
// the rewrite accomplishes nothing.
func TestDemotedCodeIsNotItselfCapacity(t *testing.T) {
	if capacityCodes[DemotedCode] {
		t.Fatalf("DemotedCode %q is itself a capacity code — the demotion is a no-op", DemotedCode)
	}
	if retryableCodes[DemotedCode] {
		t.Errorf("DemotedCode %q is in the retryable allowlist; a demoted frame would be re-withheld on a later pass", DemotedCode)
	}
}
