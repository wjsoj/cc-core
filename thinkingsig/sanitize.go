package thinkingsig

import "encoding/json"

// SanitizeForSwitch rewrites past assistant messages so the request
// is safe to send to a different upstream credential than the one that
// produced them.
//
// Background — the `signature` field on `thinking` blocks is a
// cryptographic token that Anthropic binds to the issuing account. When a
// multi-turn conversation rotates from account A to account B mid-stream,
// the prior `assistant` turns echoed back in `messages[]` still carry A's
// signatures; B's verifier rejects them with 400 "signature in thinking".
//
// Two transformations:
//
//  1. Drop every `thinking` block from past assistant messages. The
//     model on B has no way to validate A's reasoning trace, and there's
//     no safe substitute (an empty signature also 400s, a forged one
//     also 400s). Dropping is the only correct option. Subsequent turns
//     keep the user prompts and tool outputs which is what the model
//     actually needs to continue.
//
//  2. Strip any `signature` field from `tool_use` blocks. Anthropic
//     does not accept a signature on tool_use even from the original
//     account; some clients/proxies inject one defensively and that
//     also yields 400. CLIProxyAPI does the same defensive strip.
//
// Returns body unchanged on parse failure or when no rewrites were needed.
// Pure function — no logging, no state — so it's safe to call repeatedly.
func SanitizeForSwitch(body []byte) []byte {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return body
	}
	rawMsgs, ok := obj["messages"]
	if !ok {
		return body
	}
	var msgs []map[string]json.RawMessage
	if err := json.Unmarshal(rawMsgs, &msgs); err != nil {
		return body
	}

	bodyChanged := false
	for _, m := range msgs {
		roleRaw, ok := m["role"]
		if !ok {
			continue
		}
		var role string
		if err := json.Unmarshal(roleRaw, &role); err != nil || role != "assistant" {
			continue
		}
		contentRaw, ok := m["content"]
		if !ok {
			continue
		}
		// content is either a string (no thinking blocks possible) or an
		// array of block objects.
		var blocks []map[string]json.RawMessage
		if err := json.Unmarshal(contentRaw, &blocks); err != nil {
			continue
		}
		kept := blocks[:0]
		blockChanged := false
		for _, b := range blocks {
			tRaw, ok := b["type"]
			if !ok {
				kept = append(kept, b)
				continue
			}
			var t string
			if err := json.Unmarshal(tRaw, &t); err != nil {
				kept = append(kept, b)
				continue
			}
			if t == "thinking" {
				blockChanged = true
				continue
			}
			if t == "tool_use" {
				if _, has := b["signature"]; has {
					delete(b, "signature")
					blockChanged = true
				}
			}
			kept = append(kept, b)
		}
		if blockChanged {
			nb, err := json.Marshal(kept)
			if err != nil {
				continue
			}
			m["content"] = nb
			bodyChanged = true
		}
	}
	if !bodyChanged {
		return body
	}
	nm, err := json.Marshal(msgs)
	if err != nil {
		return body
	}
	obj["messages"] = nm
	out, err := json.Marshal(obj)
	if err != nil {
		return body
	}
	return out
}

// DisableThinking is the tier-2 rescue for thinking-block errors that
// SanitizeForSwitch can't fix — chiefly "thinking blocks in the latest
// assistant message cannot be modified", where the offending blocks are on
// the very turn being continued, so stripping them is itself rejected and
// keeping them fails signature validation. It makes the request safe by
// removing thinking from the equation entirely:
//
//  1. Drop every `thinking` / `redacted_thinking` block from ALL assistant
//     messages (including the latest), and strip stray `signature` fields off
//     `tool_use` blocks.
//  2. Delete the top-level `thinking` field so extended thinking is off for
//     this request — with no thinking blocks present and thinking disabled,
//     there is nothing left for the upstream to validate.
//
// The cost is that this one turn runs without extended thinking; tool_use /
// tool_result continuity is preserved, so an in-flight tool loop keeps going.
// Returns body unchanged on parse failure or when there was nothing to remove.
func DisableThinking(body []byte) []byte {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return body
	}
	changed := false
	if _, has := obj["thinking"]; has {
		delete(obj, "thinking")
		changed = true
	}

	if rawMsgs, ok := obj["messages"]; ok {
		var msgs []map[string]json.RawMessage
		if err := json.Unmarshal(rawMsgs, &msgs); err == nil {
			msgsChanged := false
			for _, m := range msgs {
				roleRaw, ok := m["role"]
				if !ok {
					continue
				}
				var role string
				if err := json.Unmarshal(roleRaw, &role); err != nil || role != "assistant" {
					continue
				}
				contentRaw, ok := m["content"]
				if !ok {
					continue
				}
				var blocks []map[string]json.RawMessage
				if err := json.Unmarshal(contentRaw, &blocks); err != nil {
					continue
				}
				kept := blocks[:0]
				blockChanged := false
				for _, b := range blocks {
					var t string
					if tRaw, ok := b["type"]; ok {
						_ = json.Unmarshal(tRaw, &t)
					}
					if t == "thinking" || t == "redacted_thinking" {
						blockChanged = true
						continue
					}
					if t == "tool_use" {
						if _, has := b["signature"]; has {
							delete(b, "signature")
							blockChanged = true
						}
					}
					kept = append(kept, b)
				}
				if blockChanged {
					if nb, err := json.Marshal(kept); err == nil {
						m["content"] = nb
						msgsChanged = true
					}
				}
			}
			if msgsChanged {
				if nm, err := json.Marshal(msgs); err == nil {
					obj["messages"] = nm
					changed = true
				}
			}
		}
	}

	if !changed {
		return body
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return body
	}
	return out
}
