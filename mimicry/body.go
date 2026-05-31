package mimicry

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/cespare/xxhash/v2"
)

// Body-layer Claude Code mimicry. Header-only spoofing is enough to pass
// UA / X-Stainless / Anthropic-Beta inspection, but Anthropic also
// inspects the request body for signals that the official CLI always emits:
//
//  1. system[0] is an "x-anthropic-billing-header" text block carrying
//     cc_version=X.Y.Z.{3hex}, cc_entrypoint=cli, and cch={5hex}
//     (xxhash64 of the body with a fixed seed).
//  2. system[1] is "You are Claude Code, Anthropic's official CLI for Claude."
//     (bare — no cache_control, matches real 2.1.158).
//  3. messages carry a stable cache breakpoint on the last block.
//  4. metadata.user_id is JSON: {"device_id":..., "account_uuid":..., "session_id":...}
//
// Missing any of these downgrades the request to "third-party app" billing
// on OAuth credentials. The algorithms below are reverse-engineered
// constants (fingerprintSalt, cchSeed) from sub2api / Parrot — keeping
// them byte-for-byte identical is what lets us look like the real CLI.

const (
	// fingerprintSalt is the salt used in the cc_version 3-char fingerprint.
	// Originated from a real CLI capture; do not change.
	fingerprintSalt = "59cf53e54c78"
	// cchSeed is the xxhash64 seed for the billing header cch field.
	cchSeed uint64 = 0x6E52736AC806831E
)

var cchPlaceholderRe = regexp.MustCompile(`(x-anthropic-billing-header:[^"]*?\bcch=)(00000)(;)`)

// ApplyClaudeCodeBodyMimicry rewrites the JSON request body to match the
// shape of a real Claude Code CLI request. Returns the original body
// unchanged if any step fails (best-effort — the request still ships).
//
// id binds the request to the per-account device fingerprint and to the
// per-downstream-user CC session. The conversation hash (sha256 of the
// first user message) makes session_id stable across multi-turn requests
// in the same conversation but rotate when a new conversation starts.
//
// Skips entirely when:
//   - body isn't a JSON object (not an Anthropic /v1/messages payload)
//   - model contains "haiku" (Anthropic doesn't third-party-check Haiku)
//   - the request already looks like Claude Code (system already has the
//     official prompt prefix — likely a real CLI client passing through)
//     — in that case only the cch signature is refreshed so it matches
//     the bytes actually being sent.
func ApplyClaudeCodeBodyMimicry(body []byte, model string, id SimIdentity) []byte {
	if len(body) == 0 || strings.Contains(strings.ToLower(model), "haiku") {
		return body
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return body
	}

	// Detect "already a Claude Code request" — leave it alone, double-injection
	// would corrupt the system field.
	if hasClaudeCodeSystemPrefix(obj["system"]) {
		return signBillingHeaderCCH(body)
	}

	// Step 1: rebuild system to match the CC 2.1.158 layout.
	out, err := rewriteSystemForOAuth(obj, body)
	if err != nil {
		return body
	}

	// Step 2: stable cache breakpoints on the last message only.
	out = stripMessageCacheControl(out)
	out = addMessageCacheBreakpoints(out)

	// Step 3: metadata.user_id (JSON shape, CC 2.1.78+).
	out = ensureMetadataUserID(out, id)

	// NOTE: real CC 2.1.158 also carries `thinking` ({"type":"adaptive"}),
	// `output_config` ({"effort":...}), `context_management` ({"edits":[...]}),
	// and `diagnostics` ({"previous_message_id":...}) on every non-Haiku
	// /v1/messages. We deliberately do NOT inject them — each is gated by a
	// beta header AND alters response semantics in ways that break downstream
	// clients which aren't real CC. Mocking them is a bigger fingerprint risk
	// than omitting them, since the upstream returns 400 if the credential's
	// beta list lacks the matching marker.

	// Step 4: replace cch=00000 placeholder with xxhash64 of the final body.
	// MUST be the last transformation — any later edit invalidates the hash.
	return signBillingHeaderCCH(out)
}

// hasClaudeCodeSystemPrefix reports whether the system field already contains
// one of the Claude Code prompt prefixes. Accepts string, []block, or null.
func hasClaudeCodeSystemPrefix(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		return matchesClaudeCodePrefix(asString)
	}
	var asArray []map[string]any
	if err := json.Unmarshal(raw, &asArray); err == nil {
		for _, blk := range asArray {
			if t, _ := blk["text"].(string); matchesClaudeCodePrefix(t) {
				return true
			}
		}
	}
	return false
}

func matchesClaudeCodePrefix(text string) bool {
	for _, p := range ClaudeCodePromptPrefixes {
		if strings.HasPrefix(text, p) {
			return true
		}
	}
	return false
}

// rewriteSystemForOAuth rebuilds the system field to match the real CC 2.1.158
// layout captured in crack/claude (SPEC.md §2):
//
//	system[0] = billing block (no cache_control)
//	system[1] = "You are Claude Code, Anthropic's official CLI for Claude."
//	            (no cache_control — real CC leaves this bare)
//	system[2..] = the client's original system prompt, preserved as text blocks
//	              with cache_control: ephemeral 1h scope=global on the
//	              second-to-last block and a plain ephemeral 1h breakpoint on
//	              the last block
//
// The client's original prompt stays in system, NOT moved into messages —
// real CC never moves it, and a stray [user/assistant] pair at message[0..1]
// is itself a third-party-tool fingerprint.
func rewriteSystemForOAuth(obj map[string]json.RawMessage, body []byte) ([]byte, error) {
	originalBlocks := extractSystemBlocks(obj["system"])

	billing := buildBillingBlock(body, CLICurrentVersion)
	ccIntro := buildSystemTextBlock(ClaudeCodeSystemPrompt, false, false)

	systemBlocks := []json.RawMessage{billing, ccIntro}
	if len(originalBlocks) > 0 {
		stripCacheControlFromBlocks(originalBlocks)
		applySystemCacheBreakpoints(originalBlocks)
		systemBlocks = append(systemBlocks, originalBlocks...)
	}

	systemArr, err := json.Marshal(systemBlocks)
	if err != nil {
		return nil, err
	}
	obj["system"] = systemArr
	return json.Marshal(obj)
}

func extractSystemBlocks(raw json.RawMessage) []json.RawMessage {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		s := strings.TrimSpace(asString)
		if s == "" {
			return nil
		}
		blk, _ := json.Marshal(map[string]any{"type": "text", "text": asString})
		return []json.RawMessage{blk}
	}
	var asArray []json.RawMessage
	if err := json.Unmarshal(raw, &asArray); err == nil {
		return asArray
	}
	return nil
}

func stripCacheControlFromBlocks(blocks []json.RawMessage) {
	for i, raw := range blocks {
		var b map[string]json.RawMessage
		if err := json.Unmarshal(raw, &b); err != nil {
			continue
		}
		if _, ok := b["cache_control"]; !ok {
			continue
		}
		delete(b, "cache_control")
		if nb, err := json.Marshal(b); err == nil {
			blocks[i] = nb
		}
	}
}

func applySystemCacheBreakpoints(blocks []json.RawMessage) {
	if len(blocks) == 0 {
		return
	}
	// Real CC 2.1.158 puts scope:global on the SECOND-TO-LAST system block
	// (the heavy, stable prefix) and a plain ephemeral 1h breakpoint on the
	// LAST block. Verified across all 18 /v1/messages in the 2026-05-29
	// capture (sysCC = ['-','-','S1h','e1h']). Earlier code had these swapped.
	if len(blocks) >= 2 {
		blocks[len(blocks)-2] = injectCacheControl(blocks[len(blocks)-2], true)
	}
	blocks[len(blocks)-1] = injectCacheControl(blocks[len(blocks)-1], false)
}

func injectCacheControl(raw json.RawMessage, withGlobalScope bool) json.RawMessage {
	var b map[string]json.RawMessage
	if err := json.Unmarshal(raw, &b); err != nil {
		return raw
	}
	cc := map[string]any{"type": "ephemeral", "ttl": ClaudeDefaultCacheTTL}
	if withGlobalScope {
		cc["scope"] = ClaudeDefaultCacheScope
	}
	if mb, err := json.Marshal(cc); err == nil {
		b["cache_control"] = mb
	}
	if nb, err := json.Marshal(b); err == nil {
		return nb
	}
	return raw
}

func buildSystemTextBlock(text string, cache, withGlobalScope bool) json.RawMessage {
	m := map[string]any{"type": "text", "text": text}
	if cache {
		cc := map[string]any{"type": "ephemeral", "ttl": ClaudeDefaultCacheTTL}
		if withGlobalScope {
			cc["scope"] = ClaudeDefaultCacheScope
		}
		m["cache_control"] = cc
	}
	out, _ := json.Marshal(m)
	return out
}

// buildBillingBlock returns the system[0] x-anthropic-billing-header block.
// cch=00000 is a placeholder; signBillingHeaderCCH replaces it after the
// rest of the body is finalized (so the hash covers the final bytes).
func buildBillingBlock(body []byte, cliVersion string) json.RawMessage {
	fp := computeClaudeCodeFingerprint(body, cliVersion)
	text := fmt.Sprintf("x-anthropic-billing-header: cc_version=%s.%s; cc_entrypoint=cli; cch=00000;", cliVersion, fp)
	out, _ := json.Marshal(map[string]any{"type": "text", "text": text})
	return out
}

// computeClaudeCodeFingerprint replicates the real CLI's cc_version suffix:
//
//  1. Take the first text in the first user message.
//  2. Pick characters at positions 4, 7, 20 (pad with '0' if shorter).
//  3. SHA256(salt + chars + cliVersion); take hex[:3].
//
// Algorithm and constants must match Parrot src/transform/cc_mimicry.py
// byte-for-byte; the upstream uses this triplet to detect non-CLI clients.
func computeClaudeCodeFingerprint(body []byte, version string) string {
	first := extractFirstUserText(body)
	chars := make([]byte, 0, 3)
	for _, idx := range []int{4, 7, 20} {
		if idx < len(first) {
			chars = append(chars, first[idx])
		} else {
			chars = append(chars, '0')
		}
	}
	sum := sha256.Sum256([]byte(fingerprintSalt + string(chars) + version))
	return hex.EncodeToString(sum[:])[:3]
}

func extractFirstUserText(body []byte) string {
	var obj struct {
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &obj); err != nil {
		return ""
	}
	for _, m := range obj.Messages {
		if m.Role != "user" {
			continue
		}
		var asString string
		if err := json.Unmarshal(m.Content, &asString); err == nil {
			return asString
		}
		var blocks []map[string]any
		if err := json.Unmarshal(m.Content, &blocks); err == nil {
			for _, b := range blocks {
				if t, _ := b["type"].(string); t == "text" {
					if s, _ := b["text"].(string); s != "" {
						return s
					}
				}
			}
		}
		return ""
	}
	return ""
}

// signBillingHeaderCCH replaces the cch=00000 placeholder in the billing
// block with a 5-char hex digest of the body. xxhash64-with-seed matches
// what the real CLI uses (signature derived from Parrot reverse-engineering).
func signBillingHeaderCCH(body []byte) []byte {
	if !cchPlaceholderRe.Match(body) {
		return body
	}
	d := xxhash.NewWithSeed(cchSeed)
	_, _ = d.Write(body)
	cch := fmt.Sprintf("%05x", d.Sum64()&0xFFFFF)
	return cchPlaceholderRe.ReplaceAll(body, []byte("${1}"+cch+"${3}"))
}

func stripMessageCacheControl(body []byte) []byte {
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
	changed := false
	for _, m := range msgs {
		contentRaw, ok := m["content"]
		if !ok {
			continue
		}
		var blocks []map[string]json.RawMessage
		if err := json.Unmarshal(contentRaw, &blocks); err != nil {
			continue
		}
		blockChanged := false
		for _, b := range blocks {
			if _, ok := b["cache_control"]; ok {
				delete(b, "cache_control")
				blockChanged = true
				changed = true
			}
		}
		if blockChanged {
			if nb, err := json.Marshal(blocks); err == nil {
				m["content"] = nb
			}
		}
	}
	if !changed {
		return body
	}
	if nm, err := json.Marshal(msgs); err == nil {
		obj["messages"] = nm
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return body
	}
	return out
}

// addMessageCacheBreakpoints injects an ephemeral 1h cache_control on the
// last block of the last message — exactly what real CC 2.1.158 does
// (verified in crack/claude, SPEC.md §2).
func addMessageCacheBreakpoints(body []byte) []byte {
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
	if len(msgs) == 0 {
		return body
	}

	msgs[len(msgs)-1] = injectBreakpointOnMessage(msgs[len(msgs)-1])

	if nm, err := json.Marshal(msgs); err == nil {
		obj["messages"] = nm
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return body
	}
	return out
}

func injectBreakpointOnMessage(msg map[string]json.RawMessage) map[string]json.RawMessage {
	contentRaw, ok := msg["content"]
	if !ok {
		return msg
	}

	var asString string
	if err := json.Unmarshal(contentRaw, &asString); err == nil {
		blk, _ := json.Marshal(map[string]any{
			"type": "text",
			"text": asString,
			"cache_control": map[string]any{
				"type": "ephemeral",
				"ttl":  ClaudeDefaultCacheTTL,
			},
		})
		arr, _ := json.Marshal([]json.RawMessage{blk})
		msg["content"] = arr
		return msg
	}

	var blocks []map[string]any
	if err := json.Unmarshal(contentRaw, &blocks); err != nil {
		return msg
	}
	if len(blocks) == 0 {
		return msg
	}
	last := blocks[len(blocks)-1]
	if cc, ok := last["cache_control"].(map[string]any); ok {
		if ttl, _ := cc["ttl"].(string); ttl != "" {
			return msg // client already set a breakpoint here — respect it
		}
		cc["ttl"] = ClaudeDefaultCacheTTL
		last["cache_control"] = cc
	} else {
		last["cache_control"] = map[string]any{
			"type": "ephemeral",
			"ttl":  ClaudeDefaultCacheTTL,
		}
	}
	blocks[len(blocks)-1] = last
	if nb, err := json.Marshal(blocks); err == nil {
		msg["content"] = nb
	}
	return msg
}

// ensureMetadataUserID writes a JSON-shaped metadata.user_id (the format
// used by CC >= 2.1.78). device_id is anchored to the account so every
// request routed through this account presents the same device. Refuses
// to overwrite a user-supplied metadata.user_id.
func ensureMetadataUserID(body []byte, id SimIdentity) []byte {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return body
	}

	deviceID := DeviceIDFor(id.AccountKey)
	sessionID := SessionIDFor(id, body)
	uid := buildJSONUserID(deviceID, id.AccountUUID, sessionID)

	if rawMD, ok := obj["metadata"]; ok && len(rawMD) > 0 {
		var md map[string]json.RawMessage
		if err := json.Unmarshal(rawMD, &md); err == nil {
			if existing, ok := md["user_id"]; ok && len(existing) > 0 && string(existing) != "null" && string(existing) != `""` {
				return body
			}
			md["user_id"], _ = json.Marshal(uid)
			if nm, err := json.Marshal(md); err == nil {
				obj["metadata"] = nm
				out, _ := json.Marshal(obj)
				return out
			}
			return body
		}
	}

	md, _ := json.Marshal(map[string]any{"user_id": uid})
	obj["metadata"] = md
	out, _ := json.Marshal(obj)
	return out
}

// BuildJSONUserID returns the JSON-form user_id used by CC >= 2.1.78
// when populating metadata.user_id. Exported so the sidecar package can
// produce the same value for its bootstrap/heartbeat payloads.
func BuildJSONUserID(deviceID, accountUUID, sessionID string) string {
	return buildJSONUserID(deviceID, accountUUID, sessionID)
}

func buildJSONUserID(deviceID, accountUUID, sessionID string) string {
	b, _ := json.Marshal(map[string]string{
		"device_id":    deviceID,
		"account_uuid": accountUUID,
		"session_id":   sessionID,
	})
	return string(b)
}
