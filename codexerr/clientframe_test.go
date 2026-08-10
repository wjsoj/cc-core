package codexerr

import (
	"encoding/json"
	"strings"
	"testing"
)

// ClientFrame is what a relay with no failover left calls on every frame, so
// the two things it must never get wrong are: an ordinary frame is returned
// untouched, and a capacity frame keeps its message while losing only the code
// that ends the session.
func TestClientFrame(t *testing.T) {
	cases := []struct {
		name         string
		in           string
		wantShed     bool
		wantCapacity bool
		wantCode     string // "" means the frame must come back byte-identical
	}{
		{
			name:         "error event: overloaded is demoted",
			in:           `{"type":"error","error":{"type":"service_unavailable_error","code":"server_is_overloaded","message":"Our servers are currently overloaded. Please try again later."}}`,
			wantShed:     true,
			wantCapacity: true,
			wantCode:     DemotedCode,
		},
		{
			name:         "response.failed: slow_down is demoted",
			in:           `{"type":"response.failed","response":{"error":{"code":"slow_down","message":"Slow down."}}}`,
			wantShed:     true,
			wantCapacity: true,
			wantCode:     DemotedCode,
		},
		{
			name: "quota sheds but keeps its own code",
			// The CLI has a non-terminal arm for quota and reads its retry
			// delay off the original code; demoting would only hide why the
			// turn failed. Still a shed — that half IS account-scoped.
			in:           `{"type":"error","error":{"code":"insufficient_quota","message":"Out of credits."}}`,
			wantShed:     true,
			wantCapacity: false,
			wantCode:     "insufficient_quota",
		},
		{
			name:         "rate limit sheds but keeps its own code",
			in:           `{"type":"error","error":{"code":"rate_limit_exceeded","message":"Try again in 12s."}}`,
			wantShed:     true,
			wantCapacity: false,
			wantCode:     "rate_limit_exceeded",
		},
		{
			name:     "fatal frame is forwarded verbatim",
			in:       `{"type":"error","error":{"code":"invalid_prompt","message":"Blocked."}}`,
			wantShed: false,
		},
		{
			name:     "unrecognised code is fatal, forwarded verbatim",
			in:       `{"type":"error","error":{"code":"some_new_code","message":"?"}}`,
			wantShed: false,
		},
		{
			name:     "ordinary delta is untouched",
			in:       `{"type":"response.output_text.delta","delta":"hello"}`,
			wantShed: false,
		},
		{
			name:     "non-JSON is untouched",
			in:       `not json`,
			wantShed: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, shed, capacity := ClientFrame([]byte(tc.in))
			if shed != tc.wantShed {
				t.Fatalf("shed = %t, want %t", shed, tc.wantShed)
			}
			if capacity != tc.wantCapacity {
				t.Fatalf("capacity = %t, want %t", capacity, tc.wantCapacity)
			}
			if tc.wantCode == "" {
				if string(out) != tc.in {
					t.Fatalf("frame was rewritten:\n got %s\nwant %s", out, tc.in)
				}
				return
			}
			var got struct {
				Error *struct {
					Code    string `json:"code"`
					Message string `json:"message"`
					Type    string `json:"type"`
				} `json:"error"`
				Response *struct {
					Error *struct {
						Code    string `json:"code"`
						Message string `json:"message"`
						Type    string `json:"type"`
					} `json:"error"`
				} `json:"response"`
			}
			if err := json.Unmarshal(out, &got); err != nil {
				t.Fatalf("output is not valid JSON: %v (%s)", err, out)
			}
			e := got.Error
			if e == nil && got.Response != nil {
				e = got.Response.Error
			}
			if e == nil {
				t.Fatalf("the error object vanished from the frame: %s", out)
			}
			if e.Code != tc.wantCode {
				t.Fatalf("code = %q, want %q", e.Code, tc.wantCode)
			}
			// The message is the whole point of demoting rather than
			// withholding — the user still has to be able to read why.
			if e.Message == "" || !strings.Contains(tc.in, e.Message) {
				t.Fatalf("message was altered or dropped: %q (frame %s)", e.Message, out)
			}
		})
	}
}

// A demoted frame must not classify as retryable a second time: a relay that
// re-examines its own output would otherwise treat it as a fresh shed.
func TestClientFrameIsIdempotent(t *testing.T) {
	in := []byte(`{"type":"error","error":{"code":"server_is_overloaded","message":"busy"}}`)
	once, shed, capacity := ClientFrame(in)
	if !shed || !capacity {
		t.Fatalf("first pass: shed=%t capacity=%t, want both true", shed, capacity)
	}
	twice, shed, _ := ClientFrame(once)
	if shed {
		t.Errorf("second pass reported a shed on an already-demoted frame")
	}
	if string(twice) != string(once) {
		t.Errorf("second pass rewrote the frame again:\n got %s\nwant %s", twice, once)
	}
}
