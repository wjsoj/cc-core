package mimicry

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// Synthetic structure only: no captured user transcript or classifier verdict.
func securityMonitorFixture() []byte {
	prompt := claudeSecurityMonitorPrefix + "\n" + strings.Join(claudeSecurityMonitorMarkers, "\n") + strings.Repeat("\nSynthetic policy fixture.", 450)
	obj := map[string]any{
		"model": "claude-haiku-4-5-20251001",
		"system": []any{
			map[string]any{"type": "text", "text": "Synthetic session context"},
			map[string]any{"type": "text", "text": prompt, "cache_control": map[string]any{"type": "ephemeral", "ttl": "5m"}},
			map[string]any{"type": "text", "text": "Trailing session context"},
		},
		"messages":             []any{map[string]any{"role": "user", "content": "<transcript>synthetic</transcript>", "cache_control": map[string]any{"type": "ephemeral"}}},
		"metadata":             map[string]any{"user_id": buildJSONUserID("client-device", "", policySourceSession), "future": map[string]any{"keep": true}},
		"safeguards":           []any{map[string]any{"type": "dangerous_tool_use", "classifier_context": map[string]any{"tool_id": "toolu_original", "future": true}}},
		"future_request_field": map[string]any{"keep": true},
	}
	b, _ := json.MarshalIndent(obj, "", " ")
	return b
}

func TestSecurityMonitorPreparedIdentityOnly(t *testing.T) {
	body := securityMonitorFixture()
	if ClassifyClaudeCodeRequest(body) != RequestClassGenuine {
		t.Fatal("security monitor was classified as generic")
	}
	id := testID()
	prepared := mustTransform(t, body, id, GenuineRequestRewrite)
	if !prepared.AccountIdentityApplied() || prepared.BillingVerified() {
		t.Fatal("incorrect identity/billing validation state")
	}
	if !metadataMatchesIdentity(prepared.Body(), id, SessionIDForSource(id, policySourceSession)) {
		t.Fatal("identity not rebound")
	}
	// Reverse only user_id and require byte equality for everything else,
	// including unknown fields, whitespace, tools, prompt, and cache markers.
	originalMD, _ := requireJSONObjectMemberSpan(body, "metadata")
	originalUID, _ := requireJSONObjectMemberSpan(body[originalMD.start:originalMD.end], "user_id")
	outMD, _ := requireJSONObjectMemberSpan(prepared.Body(), "metadata")
	outUID, _ := requireJSONObjectMemberSpan(prepared.Body()[outMD.start:outMD.end], "user_id")
	restored, err := applyByteReplacements(prepared.Body(), []byteReplacement{{start: outMD.start + outUID.start, end: outMD.start + outUID.end, value: body[originalMD.start+originalUID.start : originalMD.start+originalUID.end]}})
	if err != nil || !bytes.Equal(restored, body) {
		t.Fatal("nonidentity bytes changed")
	}
	req, _ := http.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", nil)
	req.Header.Set("Anthropic-Beta", "afk-mode-2026-01-31,auto-mode-classifier-2026-07-16,future-beta")
	if err := ApplyClaudeCodePreparedRequest(req, "synthetic-token", id.AccountKey, KindOAuth, true, true, prepared); err != nil {
		t.Fatal(err)
	}
	sent, _ := io.ReadAll(req.Body)
	if !bytes.Equal(sent, prepared.Body()) {
		t.Fatal("prepared bytes changed at apply")
	}
	for _, beta := range []string{"afk-mode-2026-01-31", "auto-mode-classifier-2026-07-16", "future-beta", claudeDangerousToolUseBeta} {
		if !strings.Contains(req.Header.Get("Anthropic-Beta"), beta) {
			t.Errorf("missing beta %s", beta)
		}
	}
	if req.Header.Get("X-Claude-Code-Session-Id") != prepared.SessionID() {
		t.Fatal("header/body session mismatch")
	}
}

func TestSecurityMonitorRecognitionIsNarrow(t *testing.T) {
	for _, mutation := range []struct{ name, old, new string }{
		{"short", strings.Repeat(`\nSynthetic policy fixture.`, 450), ""},
		{"missing marker", "## HARD BLOCK", "## DIFFERENT"},
		{"prefix", "You are a security monitor for autonomous AI coding agents.", "A different classifier."},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			body := bytes.Replace(securityMonitorFixture(), []byte(mutation.old), []byte(mutation.new), 1)
			if ClassifyClaudeCodeRequest(body) != RequestClassGeneric {
				t.Fatal("incomplete monitor matched")
			}
		})
	}
}

func TestSecurityMonitorRewriteFailsClosed(t *testing.T) {
	id := testID()
	for _, mutation := range []struct {
		name   string
		mutate func(map[string]json.RawMessage)
	}{
		{"missing metadata", func(o map[string]json.RawMessage) { delete(o, "metadata") }},
		{"bad identity", func(o map[string]json.RawMessage) { o["metadata"] = json.RawMessage(`{"user_id":"not-json"}`) }},
		{"missing session", func(o map[string]json.RawMessage) {
			o["metadata"] = json.RawMessage(`{"user_id":"{\"device_id\":\"device\",\"account_uuid\":\"\"}"}`)
		}},
		{"no messages", func(o map[string]json.RawMessage) { o["messages"] = json.RawMessage(`[]`) }},
		{"bad billing", func(o map[string]json.RawMessage) {
			o["system"] = bytes.Replace(o["system"], []byte("Synthetic session context"), []byte("x-anthropic-billing-header: broken"), 1)
		}},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			var obj map[string]json.RawMessage
			_ = json.Unmarshal(securityMonitorFixture(), &obj)
			mutation.mutate(obj)
			body, _ := json.Marshal(obj)
			_, err := PrepareClaudeCodeRequest(body, "claude-haiku-4-5", id, mustPolicy(t, RequestClassGenuine, GenuineRequestRewrite), KindOAuth)
			if err == nil {
				t.Fatal("invalid monitor was prepared")
			}
		})
	}
	prepared := mustTransform(t, securityMonitorFixture(), id, GenuineRequestRewrite)
	for _, tc := range []struct{ name, account, beta string }{
		{"wrong account", "other", "claude-code-20250219"},
		{"missing feature vector", id.AccountKey, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", nil)
			req.Header.Set("Anthropic-Beta", tc.beta)
			if err := ApplyClaudeCodePreparedRequest(req, "synthetic-token", tc.account, KindOAuth, true, true, prepared); err == nil {
				t.Fatal("unsafe apply succeeded")
			}
			if req.Body != nil {
				t.Fatal("failed apply mutated request")
			}
		})
	}
	prepared.body[0] = ' '
	req, _ := http.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", nil)
	if err := ApplyClaudeCodePreparedRequest(req, "synthetic-token", id.AccountKey, KindOAuth, true, true, prepared); err == nil {
		t.Fatal("mutated prepared body was accepted")
	}
}

func TestSafeguardsBetaNegotiation(t *testing.T) {
	for _, kind := range []string{KindOAuth, KindAPIKey} {
		for _, withBody := range []bool{false, true} {
			for _, explicit := range []bool{false, true} {
				body := []byte(`{"model":"claude-sonnet-5","messages":[]}`)
				if withBody {
					body = []byte(`{"model":"claude-sonnet-5","messages":[],"safeguards":[{"type":"dangerous_tool_use","classifier_context":{"tool_id":"toolu_unchanged"}}]}`)
				}
				original := bytes.Clone(body)
				req, _ := http.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", nil)
				beta := "future-beta"
				if explicit {
					beta += "," + claudeDangerousToolUseBeta
				}
				req.Header.Set("Anthropic-Beta", beta)
				ApplyClaudeCodeHeaders(req, "synthetic-token", kind, true, true, testID(), body)
				got := req.Header.Get("Anthropic-Beta")
				count := 0
				for _, v := range splitBetaList(got) {
					if v == claudeDangerousToolUseBeta {
						count++
					}
				}
				want := 0
				if withBody || explicit {
					want = 1
				}
				if count != want {
					t.Fatalf("%s body=%t explicit=%t beta count=%d", kind, withBody, explicit, count)
				}
				if !strings.Contains(got, "future-beta") || !bytes.Equal(body, original) {
					t.Fatal("unknown beta or body lost")
				}
				ApplyClaudeCodeHeaders(req, "synthetic-token", kind, true, true, testID(), body)
				if got != req.Header.Get("Anthropic-Beta") {
					t.Fatal("beta repair is not idempotent")
				}
			}
		}
	}
}

func TestGenericSafeguardsSurvivePreparedHeaderPinning(t *testing.T) {
	body := []byte(`{"model":"claude-sonnet-5","messages":[{"role":"user","content":"synthetic"}],"safeguards":[{"type":"dangerous_tool_use","classifier_context":{"tool_id":"toolu_original"}}]}`)
	id := testID()
	prepared, err := PrepareClaudeCodeRequest(body, "claude-sonnet-5", id, NewGenericClaudeCodeSynthesizePolicy(), KindOAuth)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", nil)
	req.Header.Set("Anthropic-Beta", "future-beta,afk-mode-2026-01-31")
	if err := ApplyClaudeCodePreparedRequest(req, "synthetic-token", id.AccountKey, KindOAuth, true, true, prepared); err != nil {
		t.Fatal(err)
	}
	for _, beta := range []string{"future-beta", "afk-mode-2026-01-31", claudeDangerousToolUseBeta} {
		if !strings.Contains(req.Header.Get("Anthropic-Beta"), beta) {
			t.Fatal("safety beta lost")
		}
	}
	var before, after map[string]json.RawMessage
	_ = json.Unmarshal(body, &before)
	_ = json.Unmarshal(prepared.Body(), &after)
	if !bytes.Equal(before["safeguards"], after["safeguards"]) {
		t.Fatal("safety context changed")
	}
}

func TestSecurityMonitorCurrentPromptProfile(t *testing.T) {
	body := securityMonitorFixture()
	body = bytes.Replace(body, []byte("## HARD BLOCK"), []byte("**HARD BLOCK**"), 1)
	body = bytes.Replace(body, []byte("## SOFT BLOCK"), []byte("**SOFT BLOCK**"), 1)
	body = bytes.Replace(body, []byte("## Threat Model"), []byte("## Context\\n## Input\\n## Default Rule\\n## Scope\\n## User Intent Rule\\n## Evaluation Rules\\n## Threat Model"), 1)
	if ClassifyClaudeCodeRequest(body) != RequestClassGenuine {
		t.Fatal("2.1.291 monitor profile was not recognized")
	}
	result := mustTransform(t, body, testID(), GenuineRequestRewrite)
	if result.BillingVerified() {
		t.Fatal("unbilled monitor acquired a billing claim")
	}
	var before, after map[string]json.RawMessage
	_ = json.Unmarshal(body, &before)
	_ = json.Unmarshal(result.Body(), &after)
	if !bytes.Equal(before["system"], after["system"]) {
		t.Fatal("current monitor prompt/cache was changed")
	}
	missing := bytes.Replace(body, []byte("## User Intent Rule"), []byte("## Missing Rule"), 1)
	if ClassifyClaudeCodeRequest(missing) != RequestClassGeneric {
		t.Fatal("incomplete current profile accepted")
	}
}

func TestEnsureClaudeSafeguardsBetaDirectRelay(t *testing.T) {
	body := []byte(`{"safeguards":[{"type":"dangerous_tool_use"}]}`)
	EnsureClaudeSafeguardsBeta(nil, body)
	h := http.Header{}
	h.Add("Anthropic-Beta", "future-a")
	h.Add("Anthropic-Beta", "future-b")
	EnsureClaudeSafeguardsBeta(h, body)
	if got := h.Get("Anthropic-Beta"); got != "future-a,future-b,"+claudeDangerousToolUseBeta {
		t.Fatalf("beta vector lost: %s", got)
	}
	EnsureClaudeSafeguardsBeta(h, body)
	if strings.Count(h.Get("Anthropic-Beta"), claudeDangerousToolUseBeta) != 1 {
		t.Fatal("duplicate safety beta")
	}
}
