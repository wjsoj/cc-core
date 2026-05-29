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

// IsThinkingError reports whether a 4xx/5xx body indicates ANY thinking-block
// rejection — the signature flavor handled by SanitizeForSwitch, plus the
// inverse flavor that stripping CANNOT fix:
//
//	"`thinking` or `redacted_thinking` blocks in the latest assistant message
//	 cannot be modified. These blocks must remain as they were in the original
//	 response."
//
// This one fires when the thinking blocks on the message being continued were
// minted by a different account than the one now validating them (common on
// relays / Bedrock backends that rotate accounts per request). You can't strip
// them — the latest assistant turn's thinking must stay put — and you can't
// keep them — the validator rejects the signature. The only escape is to
// replay with thinking disabled entirely (DisableThinking), so there is no
// thinking block left to validate.
//
// Used to gate the proxy's tier-2 recovery. Substring match on lowercase to
// survive wording drift.
func IsThinkingError(body []byte) bool {
	if IsSignatureError(body) {
		return true
	}
	lower := bytes.ToLower(body)
	if !bytes.Contains(lower, []byte("thinking")) {
		return false
	}
	return bytes.Contains(lower, []byte("cannot be modified")) ||
		bytes.Contains(lower, []byte("must remain as they were")) ||
		bytes.Contains(lower, []byte("must be the same"))
}
