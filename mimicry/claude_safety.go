package mimicry

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Claude Code 2.1.291 requests server-side tool review with safeguards and
// this beta. The beta is also gated by safeguards in CLIProxyAPI's executor.
// This is protocol negotiation, never a substitute for a classifier verdict.
const claudeDangerousToolUseBeta = "dangerous-tool-use-2026-09-03"

func claudeHasSafeguards(body []byte) bool {
	var obj map[string]json.RawMessage
	if json.Unmarshal(body, &obj) != nil {
		return false
	}
	_, ok := obj["safeguards"]
	return ok
}

func appendMissingClaudeBetas(existing, additions string) string {
	present := make(map[string]bool)
	for _, beta := range splitBetaList(existing) {
		present[beta] = true
	}
	for _, beta := range splitBetaList(additions) {
		if !present[beta] {
			if existing != "" {
				existing += ","
			}
			existing += beta
			present[beta] = true
		}
	}
	return existing
}

// EnsureClaudeSafeguardsBeta preserves the caller's feature vector and adds
// the beta required for a safeguards request. It never edits the body or
// fabricates a classifier result. Direct API-key relays can call this without
// applying any OAuth identity or fingerprint policy. A nil header is a no-op.
func EnsureClaudeSafeguardsBeta(headers http.Header, body []byte) {
	if headers != nil && claudeHasSafeguards(body) {
		headers.Set("Anthropic-Beta", appendMissingClaudeBetas(strings.Join(headers.Values("Anthropic-Beta"), ","), claudeDangerousToolUseBeta))
	}
}

// Recognition follows sub2api's security-monitor validator. These markers
// identify a request shape, not a trusted caller or a successful safety check.
// System and cache blocks must remain untouched for this auxiliary request.
const claudeSecurityMonitorPrefix = "You are a security monitor for autonomous AI coding agents."

var claudeSecurityMonitorMarkers = []string{
	"## Threat Model", "- `<transcript>`:", "## HARD BLOCK", "## SOFT BLOCK",
	"## Classification Process", "## Output Format", "<block>yes</block>", "<block>no</block>",
}

// The 2.1.291 bundled prompt uses evaluation sections and bold block labels,
// replacing 2.1.220's HARD/SOFT BLOCK headings. Require the complete profile,
// rather than accepting arbitrary prompts that mention either label.
var claudeSecurityMonitorCurrentMarkers = []string{
	"## Context", "## Threat Model", "## Input", "- `<transcript>`:",
	"## Default Rule", "## Scope", "## User Intent Rule", "## Evaluation Rules",
	"**HARD BLOCK**", "**SOFT BLOCK**", "## Classification Process", "## Output Format",
	"<block>yes</block>", "<block>no</block>",
}

// Current severity mode replaces only the Output Format section of the block
// profile. Require its exact output instructions as well as every shared heading.
var claudeSecurityMonitorSeverityMarkers = append(
	append([]string(nil), claudeSecurityMonitorCurrentMarkers[:len(claudeSecurityMonitorCurrentMarkers)-2]...),
	"Output <severity>N</severity> where N is an integer 0-100 and 50 is exactly the allow/block boundary under the rules above.",
	"Do NOT include a <category> tag when no BLOCK rule matches.",
)

func hasSecurityMonitorMarkers(text string, markers []string) bool {
	for _, marker := range markers {
		if !strings.Contains(text, marker) {
			return false
		}
	}
	return true
}

func isClaudeSecurityMonitorSystem(raw json.RawMessage) bool {
	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &blocks) != nil {
		return false
	}
	matches := 0
	for _, block := range blocks {
		if block.Type != "text" || len(block.Text) < 10000 || !strings.HasPrefix(block.Text, claudeSecurityMonitorPrefix) {
			continue
		}
		if hasSecurityMonitorMarkers(block.Text, claudeSecurityMonitorMarkers) || hasSecurityMonitorMarkers(block.Text, claudeSecurityMonitorCurrentMarkers) || hasSecurityMonitorMarkers(block.Text, claudeSecurityMonitorSeverityMarkers) {
			matches++
		}
	}
	return matches == 1
}

// A malformed billing block must still go through the normal billing parser;
// it must never turn this narrow no-billing path into a validation escape.
func isUnbilledClaudeSecurityMonitor(body []byte) bool {
	system, err := requireJSONObjectMemberSpan(body, "system")
	if err != nil {
		return false
	}
	raw := body[system.start:system.end]
	if !isClaudeSecurityMonitorSystem(raw) {
		return false
	}
	var blocks []struct {
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &blocks) != nil {
		return false
	}
	for _, block := range blocks {
		if strings.Contains(block.Text, claudeBillingHeaderPrefix) {
			return false
		}
	}
	return true
}

// Validate the no-billing exception both before preparation and at Apply time.
// The ordinary account/session/digest/credential binding checks remain active.
func validateUnbilledClaudeSecurityMonitor(body []byte) error {
	if !isUnbilledClaudeSecurityMonitor(body) {
		return errors.New("not an unbilled security-monitor request")
	}
	model, err := requireJSONObjectMemberSpan(body, "model")
	if err != nil {
		return err
	}
	var modelName string
	if json.Unmarshal(body[model.start:model.end], &modelName) != nil || strings.TrimSpace(modelName) == "" {
		return errors.New("security monitor requires a model")
	}
	messages, err := requireJSONObjectMemberSpan(body, "messages")
	if err != nil {
		return err
	}
	var turns []json.RawMessage
	if json.Unmarshal(body[messages.start:messages.end], &turns) != nil || len(turns) == 0 {
		return errors.New("security monitor requires a nonempty messages array")
	}
	metadata, err := requireJSONObjectMemberSpan(body, "metadata")
	if err != nil {
		return err
	}
	userID, err := requireJSONObjectMemberSpan(body[metadata.start:metadata.end], "user_id")
	if err != nil {
		return err
	}
	var identityJSON string
	if json.Unmarshal(body[metadata.start+userID.start:metadata.start+userID.end], &identityJSON) != nil {
		return errors.New("security monitor requires a JSON identity string")
	}
	for _, key := range []string{"device_id", "account_uuid", "session_id"} {
		span, err := requireJSONObjectMemberSpan([]byte(identityJSON), key)
		if err != nil {
			return fmt.Errorf("security monitor identity: %w", err)
		}
		var value string
		if json.Unmarshal([]byte(identityJSON)[span.start:span.end], &value) != nil || (key != "account_uuid" && strings.TrimSpace(value) == "") {
			return fmt.Errorf("invalid security monitor identity field %s", key)
		}
	}
	return nil
}

func rewriteUnbilledClaudeSecurityMonitor(body []byte, id SimIdentity, sessionID string) ([]byte, error) {
	if err := validateUnbilledClaudeSecurityMonitor(body); err != nil {
		return nil, err
	}
	metadata, _ := requireJSONObjectMemberSpan(body, "metadata")
	userID, _ := requireJSONObjectMemberSpan(body[metadata.start:metadata.end], "user_id")
	encoded, err := json.Marshal(buildJSONUserID(DeviceIDFor(id.AccountKey), id.AccountUUID, sessionID))
	if err != nil {
		return nil, err
	}
	out, err := applyByteReplacements(body, []byteReplacement{{start: metadata.start + userID.start, end: metadata.start + userID.end, value: encoded}})
	if err != nil {
		return nil, err
	}
	if !metadataMatchesIdentity(out, id, sessionID) {
		return nil, errors.New("security monitor identity verification failed")
	}
	return out, nil
}
