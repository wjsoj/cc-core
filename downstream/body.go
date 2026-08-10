package downstream

import (
	"bytes"
	"encoding/json"
	"regexp"
)

// Error bodies are the other place upstream identity reaches the client.
//
// Anthropic returns errors as
//
//	{"type":"error","error":{"type":"...","message":"..."},"request_id":"req_…"}
//
// The `request_id` is the correlator for OUR upstream call, and the free-text
// message occasionally names the organization or account that failed. Neither
// belongs downstream — the caller cannot act on either, and the captured
// third-party gateway returns neither.
//
// Unlike request bodies, these are not matched against a capture: the shape a
// gateway returns is its own. So a plain decode/encode is fine here, and the
// byte-splice machinery the request side needs would be misplaced.

// identityPatterns are redacted wherever they appear in an error message.
//
// Both are unambiguous: a `req_`-prefixed token is an Anthropic request id, and
// a bare UUID in an Anthropic error message is an organization, account, or
// workspace. Only free text is rewritten — never `type`, which clients switch
// on.
var identityPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\breq_[A-Za-z0-9]{8,}\b`),
	regexp.MustCompile(`\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b`),
}

const redactedMarker = "[redacted]"

// dropPayloadKeys are removed from the top level of an error payload.
var dropPayloadKeys = []string{"request_id", "requestId"}

// ScrubErrorPayload removes upstream identity from an error JSON payload,
// returning the rewritten bytes and whether anything changed.
//
// Input that is not a JSON object is returned unchanged: an upstream that
// answered with HTML or a truncated body is a problem to surface, not to
// silently rewrite into something else.
func ScrubErrorPayload(b []byte) ([]byte, bool) {
	trimmed := bytes.TrimSpace(b)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return b, false
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &obj); err != nil || obj == nil {
		return b, false
	}

	changed := false
	for _, key := range dropPayloadKeys {
		if _, ok := obj[key]; ok {
			delete(obj, key)
			changed = true
		}
	}
	if scrubbed, ok := scrubErrorMessage(obj["error"]); ok {
		obj["error"] = scrubbed
		changed = true
	}
	if !changed {
		return b, false
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return b, false
	}
	return out, true
}

func scrubErrorMessage(raw json.RawMessage) (json.RawMessage, bool) {
	if len(raw) == 0 {
		return nil, false
	}
	var inner map[string]json.RawMessage
	if err := json.Unmarshal(raw, &inner); err != nil || inner == nil {
		return nil, false
	}
	var message string
	if err := json.Unmarshal(inner["message"], &message); err != nil {
		return nil, false
	}
	redacted := redactIdentity(message)
	if redacted == message {
		return nil, false
	}
	encoded, err := json.Marshal(redacted)
	if err != nil {
		return nil, false
	}
	inner["message"] = encoded
	out, err := json.Marshal(inner)
	if err != nil {
		return nil, false
	}
	return out, true
}

func redactIdentity(s string) string {
	for _, pattern := range identityPatterns {
		s = pattern.ReplaceAllString(s, redactedMarker)
	}
	return s
}

// sseDataPrefix is the only line form carrying a payload.
var sseDataPrefix = []byte("data:")

// ScrubSSELine scrubs an SSE line when it belongs to an `error` event,
// returning the replacement line and whether it changed.
//
// Scoped to error events on purpose. A relay sees thousands of
// content_block_delta lines per response, and running a JSON decode over each
// one to find a field that only ever appears in errors would be a real cost for
// no benefit. event is SSEScanner.Event(); the check is one string compare.
//
// The line's `data:` prefix, any space after it, and its trailing newline are
// preserved so the caller can keep emitting byte-for-byte.
func ScrubSSELine(event string, line []byte) ([]byte, bool) {
	if event != "error" || !bytes.HasPrefix(line, sseDataPrefix) {
		return line, false
	}
	payload := line[len(sseDataPrefix):]

	leading := 0
	for leading < len(payload) && (payload[leading] == ' ' || payload[leading] == '\t') {
		leading++
	}
	trailing := len(payload)
	for trailing > leading && (payload[trailing-1] == '\n' || payload[trailing-1] == '\r') {
		trailing--
	}

	scrubbed, changed := ScrubErrorPayload(payload[leading:trailing])
	if !changed {
		return line, false
	}
	out := make([]byte, 0, len(sseDataPrefix)+leading+len(scrubbed)+(len(payload)-trailing))
	out = append(out, sseDataPrefix...)
	out = append(out, payload[:leading]...)
	out = append(out, scrubbed...)
	out = append(out, payload[trailing:]...)
	return out, true
}
