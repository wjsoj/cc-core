package mimicry

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func monitorStageOneFixture(severity bool) []byte {
	var request map[string]any
	_ = json.Unmarshal(securityMonitorFixture(), &request)
	markers := claudeSecurityMonitorCurrentMarkers
	stop := "</block>"
	if severity {
		markers = claudeSecurityMonitorSeverityMarkers
		stop = "</severity>"
	}
	prompt := claudeSecurityMonitorPrefix + "\n" + strings.Join(markers, "\n") + strings.Repeat("\nSynthetic policy fixture.", 450)
	request["system"] = []any{map[string]any{"type": "text", "text": prompt, "cache_control": map[string]string{"type": "ephemeral", "ttl": "5m"}}}
	request["max_tokens"] = 64
	request["thinking"] = map[string]string{"type": "disabled"}
	request["stop_sequences"] = []string{stop}
	request["stream"] = false
	body, _ := json.MarshalIndent(request, "", " ")
	return body
}

func TestSecurityMonitorStageOneRecognition(t *testing.T) {
	for _, severity := range []bool{false, true} {
		body := monitorStageOneFixture(severity)
		if !IsClaudeSecurityMonitorStageOne(body) {
			t.Fatalf("stage one not recognized: severity=%v", severity)
		}
		for _, tc := range []struct {
			key   string
			value any
		}{
			{"max_tokens", 65}, {"thinking", map[string]string{"type": "enabled"}},
			{"stop_sequences", []string{"</other>"}}, {"stop_sequences", []string{"</block>", "</severity>"}},
			{"system", []any{map[string]string{"type": "text", "text": "ordinary security monitor"}}},
			{"stream", true}, {"messages", []any{}},
		} {
			var obj map[string]any
			_ = json.Unmarshal(body, &obj)
			obj[tc.key] = tc.value
			changed, _ := json.Marshal(obj)
			if IsClaudeSecurityMonitorStageOne(changed) {
				t.Fatalf("overbroad match for %s", tc.key)
			}
		}
	}
}

func TestSecurityMonitorSeverityPreparedIdentityOnly(t *testing.T) {
	body := monitorStageOneFixture(true)
	if ClassifyClaudeCodeRequest(body) != RequestClassGenuine {
		t.Fatal("severity monitor fell into generic synthesis")
	}
	prepared := mustTransform(t, body, testID(), GenuineRequestRewrite)
	if !prepared.AccountIdentityApplied() || prepared.BillingVerified() {
		t.Fatal("incorrect identity/billing state")
	}
	originalMD, _ := requireJSONObjectMemberSpan(body, "metadata")
	originalUID, _ := requireJSONObjectMemberSpan(body[originalMD.start:originalMD.end], "user_id")
	outMD, _ := requireJSONObjectMemberSpan(prepared.Body(), "metadata")
	outUID, _ := requireJSONObjectMemberSpan(prepared.Body()[outMD.start:outMD.end], "user_id")
	restored, err := applyByteReplacements(prepared.Body(), []byteReplacement{{start: outMD.start + outUID.start, end: outMD.start + outUID.end, value: body[originalMD.start+originalUID.start : originalMD.start+originalUID.end]}})
	if err != nil || !bytes.Equal(restored, body) {
		t.Fatal("severity system, max_tokens, thinking, stop_sequences or other bytes changed")
	}
	missing := bytes.Replace(body, []byte("Do NOT include a &lt;category&gt; tag when no BLOCK rule matches."), []byte("other"), 1)
	// json.Marshal escapes angle brackets as Unicode escapes.
	missing = bytes.Replace(missing, []byte(`Do NOT include a \u003ccategory\u003e tag when no BLOCK rule matches.`), []byte("other"), 1)
	if ClassifyClaudeCodeRequest(missing) != RequestClassGeneric {
		t.Fatal("incomplete severity profile matched")
	}
}

type monitorCloseReader struct {
	io.Reader
	closed bool
}

func (r *monitorCloseReader) Close() error { r.closed = true; return nil }

func TestCheckClaudeSecurityMonitorResponse(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		want       bool
	}{
		{"empty", `{"type":"message","stop_reason":"max_tokens","content":[]}`, true},
		{"empty-text", `{"type":"message","stop_reason":"max_tokens","content":[{"type":"text","text":"  "}]}`, true},
		{"thinking-only", `{"type":"message","stop_reason":"max_tokens","content":[{"type":"thinking","thinking":"synthetic"}]}`, true},
		{"allow", `{"type":"message","stop_reason":"stop_sequence","content":[{"type":"text","text":"<block>no"}]}`, false},
		{"deny", `{"type":"message","stop_reason":"max_tokens","content":[{"type":"text","text":"<block>yes"}]}`, false},
		{"severity", `{"type":"message","stop_reason":"stop_sequence","content":[{"type":"text","text":"<severity>0"}]}`, false},
		{"refusal", `{"type":"message","stop_reason":"max_tokens","content":[{"type":"refusal","refusal":"no"}]}`, false},
		{"refusal-stop", `{"type":"message","stop_reason":"refusal","content":[]}`, false},
		{"unknown", `{"type":"message","stop_reason":"max_tokens","content":[{"type":"future"}]}`, false},
		{"empty-endturn", `{"type":"message","stop_reason":"end_turn","content":[]}`, false},
		{"malformed", `{"type":"message","stop_reason":"max_tokens"}`, false},
		{"oversize", strings.Repeat(" ", claudeMonitorResponseLimit) + `{"type":"message","stop_reason":"max_tokens","content":[]}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := &monitorCloseReader{Reader: strings.NewReader(tc.body)}
			response := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: source}
			if got, readErr := CheckClaudeSecurityMonitorResponse(monitorStageOneFixture(true), response); readErr != nil || got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
			restored, err := io.ReadAll(response.Body)
			if err != nil || string(restored) != tc.body {
				t.Fatal("response bytes lost by bounded peek")
			}
			_ = response.Body.Close()
			if !source.closed {
				t.Fatal("original response body not closed")
			}
		})
	}
	response := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"type":"message","stop_reason":"max_tokens","content":[]}`))}
	if invalid, err := CheckClaudeSecurityMonitorResponse([]byte(`{"max_tokens":64,"messages":[]}`), response); invalid || err != nil {
		t.Fatal("ordinary request changed")
	}
}

type monitorReadFailure struct{}

func (monitorReadFailure) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestCheckClaudeSecurityMonitorResponseExposesReadFailure(t *testing.T) {
	response := &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(io.MultiReader(strings.NewReader(`{"type":"message",`), monitorReadFailure{}))}
	invalid, err := CheckClaudeSecurityMonitorResponse(monitorStageOneFixture(true), response)
	if invalid || err != io.ErrUnexpectedEOF {
		t.Fatalf("partial response must report transport failure, got invalid=%v err=%v", invalid, err)
	}
	restored, _ := io.ReadAll(response.Body)
	if string(restored) != `{"type":"message",` {
		t.Fatal("partial response bytes were consumed")
	}
}
