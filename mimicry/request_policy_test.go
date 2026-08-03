package mimicry

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

const policySourceSession = "11111111-1111-4111-8111-111111111111"

func genuinePolicyBody(prompt, firstUser, sourceSession, billing string) []byte {
	uid := buildJSONUserID("downstream-device", "downstream-account", sourceSession)
	obj := map[string]any{
		"model": "claude-sonnet-5",
		"messages": []any{
			map[string]any{"role": "user", "content": firstUser},
		},
		"system": []any{
			map[string]any{"type": "text", "text": billing},
			map[string]any{"type": "text", "text": prompt},
		},
		"metadata": map[string]any{"trace": "keep-me", "user_id": uid},
		"stream":   true,
	}
	out, _ := json.Marshal(obj)
	return out
}

func standardGenuinePolicyBody() []byte {
	return genuinePolicyBody(
		ClaudeCodeSystemPrompt,
		"中文问题 cch=leave-user-text-alone",
		policySourceSession,
		"x-anthropic-billing-header: cc_version=2.1.214.abc; cc_entrypoint=cli; cch=1a2b3; cc_prev_req=req_previous;",
	)
}

func mustPolicy(t *testing.T, class RequestClass, mode GenuineRequestMode) RequestPolicy {
	t.Helper()
	policy, err := NewClaudeCodeRequestPolicy(class, mode)
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	return policy
}

func mustTransform(t *testing.T, body []byte, id SimIdentity, mode GenuineRequestMode) BodyTransformResult {
	t.Helper()
	class := ClassifyClaudeCodeRequest(body)
	result, err := PrepareClaudeCodeRequest(body, "claude-sonnet-5", id, mustPolicy(t, class, mode), KindOAuth)
	if err != nil {
		t.Fatalf("transform: %v", err)
	}
	return result
}

func TestClassifyClaudeCodeRequestFromBodyOnly(t *testing.T) {
	cases := []struct {
		name string
		body []byte
		want RequestClass
	}{
		{"main", standardGenuinePolicyBody(), RequestClassGenuine},
		{"haiku-title", genuinePolicyBody("You are a helpful AI assistant tasked with summarizing conversations", "title", policySourceSession, "x-anthropic-billing-header: cc_version=2.1.220.abc; cc_entrypoint=cli; cch=123ab;"), RequestClassGenuine},
		{"prompt-suggestion", genuinePolicyBody("You are a Claude agent, built on Anthropic's Claude Agent SDK", "suggest", policySourceSession, "x-anthropic-billing-header: cc_version=2.1.220.abc; cc_entrypoint=cli; cch=123ab;"), RequestClassGenuine},
		{"billing-block-prompt-drift", genuinePolicyBody("You are a bespoke internal coding agent.", "drifted", policySourceSession, "x-anthropic-billing-header: cc_version=2.1.220.abc; cc_entrypoint=cli; cch=123ab;"), RequestClassGenuine},
		{"generic", []byte(`{"model":"claude-sonnet-5","system":"be helpful","messages":[{"role":"user","content":"hi"}]}`), RequestClassGeneric},
		{"invalid", []byte(`not-json`), RequestClassUnknown},
		{"null", []byte(`null`), RequestClassUnknown},
		{"array", []byte(`[]`), RequestClassUnknown},
		{"scalar", []byte(`1`), RequestClassUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyClaudeCodeRequest(tc.body); got != tc.want {
				t.Fatalf("got %s want %s", got, tc.want)
			}
		})
	}
	if got, ok := ClaudeCodeSourceSessionID(standardGenuinePolicyBody()); !ok || got != policySourceSession {
		t.Fatalf("source session: got=%q ok=%v", got, ok)
	}
}

func TestLegacyBodyMimicryRejectsJSONNullWithoutPanic(t *testing.T) {
	in := []byte(`null`)
	if got := ApplyClaudeCodeBodyMimicry(in, "claude-sonnet-5", testID()); !bytes.Equal(got, in) {
		t.Fatalf("null body changed: %s", got)
	}
}

func TestGenuinePreserveIsByteExactAndKeepsClientProfile(t *testing.T) {
	// Deliberately retain whitespace, Chinese text, dateline, thinking, and a
	// dynamic cch. Preserve mode must not parse-and-remarshal these bytes.
	var obj map[string]any
	if err := json.Unmarshal(standardGenuinePolicyBody(), &obj); err != nil {
		t.Fatal(err)
	}
	obj["messages"] = append(obj["messages"].([]any), map[string]any{
		"role": "assistant",
		"content": []any{map[string]any{
			"type": "thinking", "thinking": "secret", "signature": "sig",
		}},
	})
	obj["system"] = append(obj["system"].([]any), map[string]any{
		"type": "text", "text": "Today's date is 2026-07-30.",
	})
	encoded, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	in := append([]byte(" \n"), encoded...)
	result := mustTransform(t, in, testID(), GenuineRequestPreserve)
	if !bytes.Equal(result.Body(), in) {
		t.Fatalf("preserve changed bytes\nin:  %s\nout: %s", in, result.Body())
	}
	if result.AccountIdentityApplied() || result.CCHStripped() {
		t.Fatalf("preserve reported mutation")
	}

	req, _ := http.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", nil)
	req.Header.Set("User-Agent", "claude-cli/2.1.214 (external, cli)")
	req.Header.Set("X-Stainless-Os", "MacOS")
	req.Header.Set("Anthropic-Beta", "client-version-specific-beta")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "client-encoding")
	req.Header.Set("X-Claude-Code-Session-Id", "conflicting-header-session")
	if err := ApplyClaudeCodePreparedRequest(req, "oauth-token", testID().AccountKey, KindOAuth, true, true, result); err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer oauth-token" {
		t.Fatalf("auth: %q", got)
	}
	if got := req.Header.Get("X-Claude-Code-Session-Id"); got != policySourceSession {
		t.Fatalf("body session did not win: %q", got)
	}
	if got := req.Header.Get("User-Agent"); got != "claude-cli/2.1.214 (external, cli)" {
		t.Fatalf("preserve UA changed: %q", got)
	}
	if got := req.Header.Get("X-Stainless-Os"); got != "MacOS" {
		t.Fatalf("preserve OS changed: %q", got)
	}
	if got := req.Header.Get("Anthropic-Beta"); got != "client-version-specific-beta" {
		t.Fatalf("preserve beta changed: %q", got)
	}
	if got := req.Header.Get("Accept"); got != "application/json" {
		t.Fatalf("preserve Accept changed: %q", got)
	}
	if got := req.Header.Get("Accept-Encoding"); got != "client-encoding" {
		t.Fatalf("preserve encoding changed: %q", got)
	}
}

func TestGenuineRewriteStripIsAtomicAndConsistent(t *testing.T) {
	in := standardGenuinePolicyBody()
	id := testID()
	result := mustTransform(t, in, id, GenuineRequestRewriteStripCCH)
	if !result.AccountIdentityApplied() || !result.CCHPresentBefore() || !result.CCHStripped() {
		t.Fatalf("unexpected outcome")
	}
	if strings.Contains(string(result.Body()), "cch=1a2b3") {
		t.Fatalf("billing cch survived: %s", result.Body())
	}
	if !strings.Contains(string(result.Body()), "cch=leave-user-text-alone") {
		t.Fatalf("user prose containing cch= was changed: %s", result.Body())
	}
	if !strings.Contains(string(result.Body()), "cc_prev_req=req_previous") {
		t.Fatalf("cc_prev_req was lost: %s", result.Body())
	}
	if !result.CCPrevReqPresent() || !result.CCPrevReqPreserved() {
		t.Fatalf("cc_prev_req audit flags: present=%v preserved=%v", result.CCPrevReqPresent(), result.CCPrevReqPreserved())
	}
	if got, want := result.CCPrevReqHash(), HashClaudeRequestID("req_previous"); got != want || got == "req_previous" {
		t.Fatalf("cc_prev_req hash: got %q want %q", got, want)
	}
	if !strings.Contains(string(result.Body()), "cc_version="+CLICurrentVersion+".") {
		t.Fatalf("billing version was not pinned: %s", result.Body())
	}

	identity, err := metadataIdentityFromBody(result.Body())
	if err != nil {
		t.Fatal(err)
	}
	if identity.DeviceID != DeviceIDFor(id.AccountKey) || identity.AccountUUID != id.AccountUUID {
		t.Fatalf("identity mismatch: %+v", identity)
	}
	if want := SessionIDForSource(id, policySourceSession); identity.SessionID != want {
		t.Fatalf("session: got %s want %s", identity.SessionID, want)
	}
	var obj struct {
		Metadata struct {
			Trace string `json:"trace"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(result.Body(), &obj); err != nil || obj.Metadata.Trace != "keep-me" {
		t.Fatalf("unrelated metadata lost: err=%v trace=%q", err, obj.Metadata.Trace)
	}

	req, _ := http.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", nil)
	req.Header.Set("User-Agent", "claude-cli/2.1.214 (external, cli)")
	req.Header.Set("X-Stainless-Os", "MacOS")
	mainBeta := "claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14,redact-thinking-2026-02-12,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05,mid-conversation-system-2026-04-07,advisor-tool-2026-03-01,advanced-tool-use-2025-11-20,effort-2025-11-24,extended-cache-ttl-2025-04-11,cache-diagnosis-2026-04-07"
	req.Header.Set("Anthropic-Beta", mainBeta)
	req.Header.Set("X-Claude-Code-Session-Id", "downstream-session")
	if err := ApplyClaudeCodePreparedRequest(req, "oauth-token", testID().AccountKey, KindOAuth, true, true, result); err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("User-Agent"); got != ClaudeCLIUserAgent {
		t.Fatalf("rewrite UA: %q", got)
	}
	if got := req.Header.Get("X-Stainless-Os"); got != ClaudeStainlessOS {
		t.Fatalf("rewrite OS: %q", got)
	}
	if got := req.Header.Get("Anthropic-Beta"); got != mainBeta {
		t.Fatalf("rewrite changed request feature vector: %q", got)
	}
	if got := req.Header.Get("Accept"); got != "application/json" {
		t.Fatalf("rewrite Accept: %q", got)
	}
	if got := req.Header.Get("X-Claude-Code-Session-Id"); got != identity.SessionID {
		t.Fatalf("header/body session mismatch: %q / %q", got, identity.SessionID)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer oauth-token" {
		t.Fatalf("prepared credential was not applied: %q", got)
	}
	sent, err := io.ReadAll(req.Body)
	if err != nil || !bytes.Equal(sent, result.Body()) {
		t.Fatalf("prepared body was not installed: err=%v\ngot:  %s\nwant: %s", err, sent, result.Body())
	}
}

func TestGenuineRewriteAcceptsOfficialSDKCLIEntrypoint(t *testing.T) {
	in := bytes.ReplaceAll(standardGenuinePolicyBody(), []byte("cc_entrypoint=cli;"), []byte("cc_entrypoint=sdk-cli;"))
	result := mustTransform(t, in, testID(), GenuineRequestRewriteStripCCH)
	if !bytes.Contains(result.Body(), []byte("cc_entrypoint=sdk-cli;")) {
		t.Fatalf("sdk-cli entrypoint was not preserved: %s", result.Body())
	}
	if bytes.Contains(result.Body(), []byte("cch=1a2b3")) || !result.CCHStripped() {
		t.Fatalf("sdk-cli cch was not stripped: %s", result.Body())
	}
	if !bytes.Contains(result.Body(), []byte("cc_version="+CLICurrentVersion+".")) {
		t.Fatalf("sdk-cli billing version was not pinned: %s", result.Body())
	}
}

func TestHashClaudeRequestIDIsTrimmedDomainSeparatedAndOpaque(t *testing.T) {
	got := HashClaudeRequestID("  req-123  ")
	if got == "" || got == "req-123" || got != HashClaudeRequestID("req-123") {
		t.Fatalf("unexpected request-id hash %q", got)
	}
	if got == HashClaudeRequestID("req-124") {
		t.Fatal("different request IDs produced the same audit hash")
	}
	if HashClaudeRequestID(" \t ") != "" {
		t.Fatal("empty request ID should not produce a digest")
	}
}

func TestHashClaudeAccountKeyIsStableOpaqueAndDomainSeparated(t *testing.T) {
	got := HashClaudeAccountKey(" account-uuid ")
	if got == "" || got == "account-uuid" || got != HashClaudeAccountKey("account-uuid") {
		t.Fatalf("unexpected account hash %q", got)
	}
	if got == HashClaudeRequestID("account-uuid") || got == HashClaudeAccountKey("other-account") {
		t.Fatal("account hash is not domain separated")
	}
}

func TestGenuineRewriteChangesOnlyIdentityAndBillingTextValues(t *testing.T) {
	const oldBilling = "x-anthropic-billing-header: cc_version = 2.1.214.abc ; cc_entrypoint=cli;  cch=1a2b3; cc_prev_req=req_previous; Unknown_Field = KeepMe ;"
	const oldUserID = `{"device_id":"downstream-device","account_uuid":"downstream-account","session_id":"11111111-1111-4111-8111-111111111111"}`
	body := []byte(`{
  "model": "claude-sonnet-5",
  "messages": [{"role":"user","content":[{"type":"text","text":"<system-reminder>meta & >__LS__</system-reminder>"},{"type":"text","text":"中文问题"}]}],
  "system": [
    {"type":"text","text":"x-anthropic-billing-header: cc_version = 2.1.214.abc ; cc_entrypoint=cli;  cch=1a2b3; cc_prev_req=req_previous; Unknown_Field = KeepMe ;"},
    {"type":"text","text":"You are Claude Code, Anthropic's official CLI for Claude."}
  ],
  "tools": [{"name":"keep","description":"<tag>&keep>"}],
  "metadata": {"trace":"keep-me", "user_id":"{\"device_id\":\"downstream-device\",\"account_uuid\":\"downstream-account\",\"session_id\":\"11111111-1111-4111-8111-111111111111\"}"},
  "max_tokens": 64000,
  "thinking": {"type":"adaptive"},
  "context_management": {"edits":[]},
  "output_config": {"effort":"high"},
  "diagnostics": {"previous_message_id":"msg_previous"},
  "stream": true
}`)
	body = bytes.Replace(body, []byte("__LS__"), []byte("\u2028"), 1)
	original := bytes.Clone(body)

	result := mustTransform(t, body, testID(), GenuineRequestRewriteStripCCH)
	newBilling := strings.Replace(oldBilling, "2.1.214.abc", CLICurrentVersion+"."+computeClaudeCodeFingerprint(body, CLICurrentVersion), 1)
	newBilling = strings.Replace(newBilling, "  cch=1a2b3;", "", 1)
	newUserID := buildJSONUserID(DeviceIDFor(testID().AccountKey), testID().AccountUUID, SessionIDForSource(testID(), policySourceSession))

	oldBillingToken, _ := json.Marshal(oldBilling)
	newBillingToken, _ := json.Marshal(newBilling)
	oldUserIDToken, _ := json.Marshal(oldUserID)
	newUserIDToken, _ := json.Marshal(newUserID)
	want := bytes.Replace(original, oldBillingToken, newBillingToken, 1)
	want = bytes.Replace(want, oldUserIDToken, newUserIDToken, 1)
	if !bytes.Equal(result.Body(), want) {
		t.Fatalf("rewrite changed bytes outside the two target values\ngot:  %s\nwant: %s", result.Body(), want)
	}
	if !bytes.Equal(body, original) {
		t.Fatal("rewrite mutated the input body")
	}
}

func TestGenuineRewriteRejectsDuplicateTargetKeys(t *testing.T) {
	base := standardGenuinePolicyBody()
	tests := map[string][]byte{
		"system":   bytes.Replace(base, []byte(`"system":`), []byte(`"system":[],"system":`), 1),
		"metadata": bytes.Replace(base, []byte(`"metadata":`), []byte(`"metadata":null,"metadata":`), 1),
		"user_id":  bytes.Replace(base, []byte(`"user_id":`), []byte(`"user_id":"decoy","user_id":`), 1),
		"text":     bytes.Replace(base, []byte(`{"text":`), []byte(`{"text":"decoy","text":`), 1),
	}
	policy := mustPolicy(t, RequestClassGenuine, GenuineRequestRewriteStripCCH)
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			result, err := PrepareClaudeCodeRequest(body, "claude-sonnet-5", testID(), policy, KindOAuth)
			if err == nil || result.IsValid() {
				t.Fatalf("duplicate %s target was accepted", name)
			}
		})
	}
}

func TestGenuineRewriteRetainsRequestSpecificBetaVector(t *testing.T) {
	main13 := "claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14,redact-thinking-2026-02-12,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05,mid-conversation-system-2026-04-07,advisor-tool-2026-03-01,advanced-tool-use-2025-11-20,effort-2025-11-24,extended-cache-ttl-2025-04-11,cache-diagnosis-2026-04-07"
	title9 := "oauth-2025-04-20,interleaved-thinking-2025-05-14,redact-thinking-2026-02-12,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05,advisor-tool-2026-03-01,structured-outputs-2025-12-15,cache-diagnosis-2026-04-07"
	titleBody := genuinePolicyBody(
		"You are a helpful AI assistant tasked with summarizing conversations",
		"title",
		policySourceSession,
		"x-anthropic-billing-header: cc_version=2.1.220.abc; cc_entrypoint=cli; cch=123ab;",
	)
	cases := []struct {
		name string
		body []byte
		beta string
		want string
	}{
		{"main-ordinary-13", standardGenuinePolicyBody(), main13, main13},
		{"main-context-1m-14", standardGenuinePolicyBody(), ClaudeAnthropicBetaFull, ClaudeAnthropicBetaFull},
		{"title-9", titleBody, title9, title9},
		{"missing-oauth-marker", standardGenuinePolicyBody(), "claude-code-20250219,interleaved-thinking-2025-05-14", "claude-code-20250219,interleaved-thinking-2025-05-14,oauth-2025-04-20"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := mustTransform(t, tc.body, testID(), GenuineRequestRewriteStripCCH)
			req, _ := http.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", nil)
			req.Header.Set("Anthropic-Beta", tc.beta)
			if err := ApplyClaudeCodePreparedRequest(req, "oauth-token", testID().AccountKey, KindOAuth, true, true, result); err != nil {
				t.Fatal(err)
			}
			if got := req.Header.Get("Anthropic-Beta"); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestGenuineRewriteRejectsMissingBetaWithoutMutation(t *testing.T) {
	result := mustTransform(t, standardGenuinePolicyBody(), testID(), GenuineRequestRewriteStripCCH)
	req, _ := http.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", strings.NewReader("original-body"))
	req.Header.Set("User-Agent", "original")
	beforeHeader := req.Header.Clone()
	beforeBody, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	req.Body = io.NopCloser(bytes.NewReader(beforeBody))
	if err := ApplyClaudeCodePreparedRequest(req, "oauth-token", testID().AccountKey, KindOAuth, true, true, result); err == nil {
		t.Fatal("rewrite without Anthropic-Beta was accepted")
	}
	afterBody, readErr := io.ReadAll(req.Body)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !reflect.DeepEqual(req.Header, beforeHeader) || !bytes.Equal(afterBody, beforeBody) {
		t.Fatalf("request changed after missing-beta rejection: headers=%v body=%q", req.Header, afterBody)
	}
}

func TestGenuineRewriteUsesSourceSessionAcrossRequestClasses(t *testing.T) {
	billing := "x-anthropic-billing-header: cc_version=2.1.220.abc; cc_entrypoint=cli; cch=123ab;"
	main := genuinePolicyBody(ClaudeCodeSystemPrompt, "main question", policySourceSession, billing)
	title := genuinePolicyBody("You are a helpful AI assistant tasked with summarizing conversations", "make a title", policySourceSession, billing)
	suggestion := genuinePolicyBody("You are a Claude agent, built on Anthropic's Claude Agent SDK", "suggest next", policySourceSession, billing)

	want := SessionIDForSource(testID(), policySourceSession)
	for name, body := range map[string][]byte{"main": main, "title": title, "suggestion": suggestion} {
		t.Run(name, func(t *testing.T) {
			result := mustTransform(t, body, testID(), GenuineRequestRewriteStripCCH)
			if result.SessionID() != want {
				t.Fatalf("got %s want %s", result.SessionID(), want)
			}
		})
	}

	otherAccount := testID()
	otherAccount.AccountKey = "other-account@example.com"
	otherAccount.AccountUUID = "22222222-2222-4222-8222-222222222222"
	other := mustTransform(t, main, otherAccount, GenuineRequestRewriteStripCCH)
	if other.SessionID() == want || DeviceIDFor(otherAccount.AccountKey) == DeviceIDFor(testID().AccountKey) {
		t.Fatal("switching accounts did not rotate the account-scoped identity")
	}
}

func TestGenuineRewriteWithoutIncomingCCH(t *testing.T) {
	in := bytes.ReplaceAll(standardGenuinePolicyBody(), []byte(" cch=1a2b3;"), nil)
	result := mustTransform(t, in, testID(), GenuineRequestRewriteStripCCH)
	if !result.AccountIdentityApplied() || result.CCHPresentBefore() || result.CCHStripped() {
		t.Fatal("unexpected no-cch result flags")
	}
	if err := verifyRewrittenBilling(result.Body()); err != nil {
		t.Fatal(err)
	}
}

func TestGenuineRewriteFailuresAreFailClosed(t *testing.T) {
	base := standardGenuinePolicyBody()
	validPolicy := mustPolicy(t, RequestClassGenuine, GenuineRequestRewriteStripCCH)

	tests := []struct {
		name string
		body []byte
		id   SimIdentity
	}{
		{"empty-account-key", base, SimIdentity{AccountUUID: testID().AccountUUID, ClientToken: testID().ClientToken}},
		{"empty-account-uuid", base, SimIdentity{AccountKey: testID().AccountKey, ClientToken: testID().ClientToken}},
		{"empty-client-token", base, SimIdentity{AccountKey: testID().AccountKey, AccountUUID: testID().AccountUUID}},
		{"missing-source-session", bytes.ReplaceAll(base, []byte(policySourceSession), nil), testID()},
		{"missing-billing", bytes.ReplaceAll(base, []byte("x-anthropic-billing-header: cc_version=2.1.214.abc; cc_entrypoint=cli; cch=1a2b3; cc_prev_req=req_previous;"), []byte("not a billing block")), testID()},
		{"malformed-cch", bytes.ReplaceAll(base, []byte("cch=1a2b3;"), []byte("cch=bad;")), testID()},
		{"duplicate-cch", bytes.ReplaceAll(base, []byte("cch=1a2b3;"), []byte("cch=1a2b3; cch=4d5e6;")), testID()},
		{"duplicate-version", bytes.ReplaceAll(base, []byte("cc_version=2.1.214.abc;"), []byte("cc_version=2.1.214.abc; cc_version=2.1.220.def;")), testID()},
		{"wrong-entrypoint", bytes.ReplaceAll(base, []byte("cc_entrypoint=cli;"), []byte("cc_entrypoint=sdk;")), testID()},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			original := bytes.Clone(tc.body)
			result, err := PrepareClaudeCodeRequest(tc.body, "claude-sonnet-5", tc.id, validPolicy, KindOAuth)
			if err == nil {
				t.Fatal("expected error")
			}
			if result.IsValid() || result.Body() != nil {
				t.Fatal("failed rewrite returned a usable result")
			}
			if !bytes.Equal(tc.body, original) {
				t.Fatal("failed rewrite mutated the input slice")
			}
		})
	}

	generic := []byte(`{"model":"claude-sonnet-5","messages":[{"role":"user","content":"hi"}]}`)
	if result, err := PrepareClaudeCodeRequest(generic, "claude-sonnet-5", testID(), validPolicy, KindOAuth); err == nil || result.IsValid() {
		t.Fatal("class/body mismatch was not rejected")
	}
	if _, err := NewClaudeCodeRequestPolicy(RequestClassGenuine, GenuineRequestMode(99)); err == nil {
		t.Fatal("unknown mode was accepted")
	}
}

func TestPreparedHeaderApplicationRejectsInvalidResultWithoutMutation(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", nil)
	req.Header.Set("User-Agent", "original")
	req.Header.Set("Authorization", "original-auth")
	before := req.Header.Clone()
	if err := ApplyClaudeCodePreparedRequest(req, "token", testID().AccountKey, KindOAuth, true, true, BodyTransformResult{}); err == nil {
		t.Fatal("unprepared result was accepted")
	}
	if !reflect.DeepEqual(req.Header, before) {
		t.Fatalf("headers changed on validation error: before=%v after=%v", before, req.Header)
	}
}

func TestPreparedRequestRejectsCredentialBindingMismatchWithoutMutation(t *testing.T) {
	result := mustTransform(t, standardGenuinePolicyBody(), testID(), GenuineRequestRewriteStripCCH)
	req, _ := http.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", strings.NewReader("original-body"))
	req.Header.Set("User-Agent", "original")
	req.Header.Set("Authorization", "original-auth")
	beforeHeader := req.Header.Clone()
	beforeBody, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	req.Body = io.NopCloser(bytes.NewReader(beforeBody))

	if err := ApplyClaudeCodePreparedRequest(req, "new-token", "different-account", KindOAuth, true, true, result); err == nil {
		t.Fatal("mismatched credential account was accepted")
	}
	afterBody, readErr := io.ReadAll(req.Body)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !reflect.DeepEqual(req.Header, beforeHeader) || !bytes.Equal(afterBody, beforeBody) {
		t.Fatalf("request changed on credential mismatch: headers=%v body=%q", req.Header, afterBody)
	}
}

func TestPreparedRequestInitializesHeadersAndOwnsBodyCopy(t *testing.T) {
	result := mustTransform(t, standardGenuinePolicyBody(), testID(), GenuineRequestPreserve)
	expected := bytes.Clone(result.Body())
	req := &http.Request{}
	if err := ApplyClaudeCodePreparedRequest(req, "oauth-token", testID().AccountKey, KindOAuth, true, true, result); err != nil {
		t.Fatal(err)
	}
	if req.Header == nil || req.Header.Get("Authorization") != "Bearer oauth-token" {
		t.Fatalf("nil headers were not initialized: %v", req.Header)
	}
	result.Body()[0] ^= 0xff // must not mutate the request's owned body copy
	sent, err := io.ReadAll(req.Body)
	if err != nil || !bytes.Equal(sent, expected) {
		t.Fatalf("request body aliases result: err=%v\ngot:  %x\nwant: %x", err, sent, expected)
	}
}

func TestPrepareRejectsMissingCredentialBinding(t *testing.T) {
	body := standardGenuinePolicyBody()
	policy := mustPolicy(t, RequestClassGenuine, GenuineRequestPreserve)
	emptyID := testID()
	emptyID.AccountKey = ""
	if result, err := PrepareClaudeCodeRequest(body, "claude-sonnet-5", emptyID, policy, KindOAuth); err == nil || result.IsValid() {
		t.Fatal("empty credential account key was accepted")
	}
	if result, err := PrepareClaudeCodeRequest(body, "claude-sonnet-5", testID(), policy, "other"); err == nil || result.IsValid() {
		t.Fatal("unknown credential kind was accepted")
	}
	rewritePolicy := mustPolicy(t, RequestClassGenuine, GenuineRequestRewriteStripCCH)
	if result, err := PrepareClaudeCodeRequest(body, "claude-sonnet-5", testID(), rewritePolicy, KindAPIKey); err == nil || result.IsValid() {
		t.Fatal("API-key credential accepted rewrite_strip")
	}
}
