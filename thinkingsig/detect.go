package thinkingsig

import "bytes"

// IsSignatureError reports whether an Anthropic 4xx response body
// indicates a thinking-block signature failure — the recoverable
// flavor that disappears once the signed `thinking` blocks are
// stripped from past assistant turns.
//
// The canonical wire shape is:
//
//	{"type":"error","error":{"type":"invalid_request_error",
//	 "message":"messages.5.content.0: Invalid `signature` in `thinking` block"}}
//
// Anthropic also returns a closely related error when the conversation
// has top-level `thinking` enabled but a leading `text` block where it
// expects a `thinking` or `redacted_thinking` block — that one is
// likewise fixed by stripping past thinking. Both fall under the same
// "sanitize and retry" remedy, so this matcher handles both.
//
// Match is intentionally substring-based on lowercase to survive minor
// wording drift across CC versions. False positives here are cheap:
// the worst case is one extra retry on an unrelated 400 that would
// have failed anyway.
func IsSignatureError(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	lower := bytes.ToLower(body)
	if bytes.Contains(lower, []byte("signature")) && bytes.Contains(lower, []byte("thinking")) {
		return true
	}
	// "Expected `thinking` or `redacted_thinking`, but found `text`"
	if bytes.Contains(lower, []byte("expected")) &&
		(bytes.Contains(lower, []byte("`thinking`")) || bytes.Contains(lower, []byte("redacted_thinking"))) {
		return true
	}
	return false
}
