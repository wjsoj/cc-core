package mimicry

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf16"

	"github.com/cespare/xxhash/v2"
)

// Body-layer Claude Code mimicry. Header-only spoofing is enough to pass
// UA / X-Stainless / Anthropic-Beta inspection, but Anthropic also
// inspects the request body for signals that the official CLI always emits:
//
//  1. system[0] is an "x-anthropic-billing-header" text block carrying
//     cc_version=X.Y.Z.{3hex}, cc_entrypoint=cli, and cch={5hex}
//     (a per-request five-hex value; the exact 2.1.220 signer is unresolved).
//  2. system[1] is "You are Claude Code, Anthropic's official CLI for Claude."
//     (bare — no cache_control, matches real 2.1.201).
//  3. messages carry a stable cache breakpoint on the last block.
//  4. metadata.user_id is JSON: {"device_id":..., "account_uuid":..., "session_id":...}
//
// Missing any of these downgrades the request to "third-party app" billing
// on OAuth credentials. The version suffix is extracted from the real CLI.
// The cch implementation remains a legacy best-effort reconstruction: the
// genuine 2.1.220 client emits a dynamic value, but its signer did not match
// the seeded-xxhash guess on any of 37 captured requests (claudev2.1.220/SPEC.md).
//
// An exhaustive static search of the 2.1.220 bundle (2026-07-31) proved WHY
// that reconstruction can't be finished from the binary: the JS emits the
// literal placeholder `cch=00000` and contains NO code that replaces it —
// `cc_version=` and `cc_prev_req` each appear exactly once (the one builder),
// the only other references to the billing block merely EXCLUDE it from the
// local cache-diagnosis hashes, and there is no native symbol for it either.
// The real substitution happens below the JS layer. See claudev2.1.220/SPEC.md,
// "`cch` — exhaustive static analysis".
//
// Therefore: keep signing. Do NOT "correct" this to emit 00000 just because
// that is what the bundle's source says — 43/43 captured real requests carry
// a non-zero, unique value, so the placeholder is a shape no genuine client
// ever puts on the wire. TestCCHIsNeverPlaceholder guards this.

const (
	// fingerprintSalt is the salt used in the cc_version 3-char fingerprint.
	// Originated from a real CLI capture; do not change.
	fingerprintSalt = "59cf53e54c78"
	// cchSeed is retained for the legacy best-effort cch signer. Do not claim
	// it is byte-identical to Claude Code 2.1.220 without new validation.
	cchSeed uint64 = 0x6E52736AC806831E

	// claudeBillingHeaderPrefix / claudeEntrypointMarker identify the billing
	// attribution block real Claude Code injects as system[0]
	// ("x-anthropic-billing-header: cc_version=…; cc_entrypoint=…; cch=…;").
	//
	// Presence of this block is a far more STABLE "this is genuine Claude Code"
	// signal than the intro system prompt: it survives prompt-text revisions,
	// subagent/other-tool prompts, and user-edited prompts, and it rides along
	// when an upstream API gateway (new-api etc.) proxies real CC traffic —
	// which mangles the User-Agent to Go-http-client but leaves the body's CC
	// fingerprint intact. Matching it lets us SKIP body rewriting for such
	// requests and preserve the client's own system blocks + cache_control
	// breakpoints; rewriting them would invalidate Anthropic's prefix-based
	// prompt cache (cache_read locks low, cache_creation grows every turn,
	// single-request cost blows up 10-20×). We only ever MATCH on these markers
	// here — buildBillingBlock is the sole writer. The entrypoint value drifts
	// (cli / claude-vscode / jetbrains / sdk …) and is not an anti-forgery
	// boundary, so we require the marker's presence, not a specific value.
	// Ported from sub2api's systemHasBillingAttributionBlock (community fix
	// for oauth-mimicry-cache-prefix-break).
	claudeBillingHeaderPrefix = "x-anthropic-billing-header"
	claudeEntrypointMarker    = "cc_entrypoint="
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
//   - the request already looks like Claude Code — either its system carries
//     the billing attribution block (the robust signal; see
//     claudeBillingHeaderPrefix) or it starts with a known CC prompt prefix.
//     Likely a real CLI client passing through (direct or proxied); rewriting
//     would corrupt the system field and destroy the client's prompt-cache
//     prefix. In that case only the cch signature is refreshed so it matches
//     the bytes actually being sent.
func ApplyClaudeCodeBodyMimicry(body []byte, model string, id SimIdentity) []byte {
	if len(body) == 0 || strings.Contains(strings.ToLower(model), "haiku") {
		return body
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil || obj == nil {
		return body
	}

	// Detect "already a Claude Code request" — leave it alone. Rewriting would
	// double-inject the system field AND destroy the client's prompt-cache
	// prefix (a changed system invalidates all downstream message caching).
	// Two signals, most-robust first:
	//   1. billing attribution block present — the strongest tell of genuine
	//      CC; survives prompt drift and upstream proxying (see const doc).
	//   2. system already opens with a known CC prompt prefix.
	if systemHasBillingBlock(obj["system"]) || hasClaudeCodeSystemPrefix(obj["system"]) {
		return signBillingHeaderCCH(body)
	}

	// Step 1: rebuild system to match the captured CC system layout.
	out, err := rewriteSystemForOAuth(obj, body)
	if err != nil {
		return body
	}

	// Step 2: stable cache breakpoints on the last message only.
	out = stripMessageCacheControl(out)
	out = addMessageCacheBreakpoints(out)

	// Step 3: metadata.user_id (JSON shape, CC 2.1.78+).
	out = ensureMetadataUserID(out, id)

	// NOTE: real CC 2.1.201 also carries `thinking` ({"type":"adaptive"}),
	// `output_config` ({"effort":...}), `context_management` ({"edits":[...]}),
	// and `diagnostics` ({"previous_message_id":...}) on every non-Haiku
	// /v1/messages. We deliberately do NOT inject any of them. For thinking /
	// output_config / context_management the reason is they are beta-gated AND
	// alter response semantics in ways that break downstream clients which
	// aren't real CC (upstream returns 400 if the credential's beta list lacks
	// the matching marker). `diagnostics` is semantically neutral
	// (previous_message_id is conversation-threading metadata), so that
	// argument doesn't apply — we omit it purely to keep the injection surface
	// minimal; we have nothing meaningful to set previous_message_id to.

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

// systemHasBillingBlock reports whether the system field already carries the
// Claude Code billing attribution block (system[0] in real CC). Only the
// []block shape can hold it — a bare-string system cannot. This is the
// cache-safe "already genuine Claude Code" guard that survives prompt drift
// and upstream proxying; see claudeBillingHeaderPrefix for the full rationale.
func systemHasBillingBlock(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var blocks []map[string]any
	if err := json.Unmarshal(raw, &blocks); err != nil {
		return false
	}
	for _, blk := range blocks {
		if t, _ := blk["text"].(string); strings.HasPrefix(t, claudeBillingHeaderPrefix) &&
			strings.Contains(t, claudeEntrypointMarker) {
			return true
		}
	}
	return false
}

// rewriteSystemForOAuth rebuilds the system field to match the real CC system
// layout captured in crack/claudev2.1.220/SPEC.md:
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
		if nb, err := deleteJSONObjectMember(raw, "cache_control"); err == nil {
			blocks[i] = nb
		}
	}
}

func applySystemCacheBreakpoints(blocks []json.RawMessage) {
	if len(blocks) == 0 {
		return
	}
	// Real CC 2.1.201 puts scope:global on the SECOND-TO-LAST system block
	// (the heavy, stable prefix) and a plain ephemeral 1h breakpoint on the
	// LAST block. Verified across all 18 /v1/messages in the 2026-05-29
	// capture (sysCC = ['-','-','S1h','e1h']). Earlier code had these swapped.
	if len(blocks) >= 2 {
		blocks[len(blocks)-2] = injectCacheControl(blocks[len(blocks)-2], true)
	}
	blocks[len(blocks)-1] = injectCacheControl(blocks[len(blocks)-1], false)
}

// injectCacheControl edits the block in place rather than round-tripping it
// through a map, so the client's own key order — and any keys we don't model —
// survive, and cache_control lands last as it does in capture.
func injectCacheControl(raw json.RawMessage, withGlobalScope bool) json.RawMessage {
	out, err := setJSONObjectMember(raw, "cache_control", claudeSystemCacheControl(withGlobalScope))
	if err != nil {
		return raw
	}
	return out
}

// claudeSystemBlock marshals in the captured field order, {"type","text",…}.
type claudeSystemBlock struct {
	Type         string              `json:"type"`
	Text         string              `json:"text"`
	CacheControl *claudeCacheControl `json:"cache_control,omitempty"`
}

func buildSystemTextBlock(text string, cache, withGlobalScope bool) json.RawMessage {
	block := claudeSystemBlock{Type: "text", Text: text}
	if cache {
		cc := claudeSystemCacheControl(withGlobalScope)
		block.CacheControl = &cc
	}
	out, _ := json.Marshal(block)
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

// computeClaudeCodeFingerprint replicates the real CLI's cc_version suffix.
// Verified byte-for-byte against the CC 2.1.198 bundle (functions xtf/awo,
// extracted from the standalone binary at 2.1.197/2.1.198; that per-version
// archive dir was pruned, see git history. UTF-16 semantics re-verified against
// the live capture in crack/claudev2.1.220/SPEC.md "Billing, fingerprint suffix, and
// `cch`"):
//
//	function xtf(e){let t=e.find(r=>r.type==="user"&&!r.isMeta); ... first text block}
//	function awo(e,t){let r=[4,7,20].map(i=>e[i]||"0").join(""); return
//	                  sha256(SALT+r+VERSION).slice(0,3)}
//
//	1. Take the first text of the first NON-META user message. `isMeta` marks
//	   CC's injected messages (system-reminders etc.); on the wire those are
//	   merged as LEADING blocks of the first user message, so we skip any text
//	   block that is a <system-reminder> wrapper — matching CC's !isMeta filter.
//	2. Pick JavaScript UTF-16 code units at positions 4, 7, 20 (pad with '0'
//	   if shorter). JavaScript indexes strings by UTF-16 code unit, not UTF-8
//	   byte or Unicode code point; isolated selected surrogates are converted
//	   to U+FFFD by Node's UTF-8 encoder before hashing.
//	3. SHA256(salt + chars + cliVersion); take hex[:3].
//
// Skipping the reminder is what was wrong before v2.1.198: CC computes this fp
// BEFORE injecting the ephemeral system-reminder, so it hashes the user's real
// first message, not the reminder text that leads the wire body.
func computeClaudeCodeFingerprint(body []byte, version string) string {
	first := extractFirstUserText(body)
	units := utf16.Encode([]rune(first))
	selected := make([]uint16, 0, 3)
	for _, idx := range []int{4, 7, 20} {
		if idx < len(units) {
			selected = append(selected, units[idx])
		} else {
			selected = append(selected, '0')
		}
	}
	chars := string(utf16.Decode(selected))
	sum := sha256.Sum256([]byte(fingerprintSalt + chars + version))
	return hex.EncodeToString(sum[:])[:3]
}

// systemReminderPrefix marks CC's injected (isMeta) context blocks. The real
// CLI excludes these when picking the fp input; on the wire they arrive merged
// as leading text blocks of the first user message.
const systemReminderPrefix = "<system-reminder>"

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
			var firstText string
			for _, b := range blocks {
				if t, _ := b["type"].(string); t != "text" {
					continue
				}
				s, _ := b["text"].(string)
				if s == "" {
					continue
				}
				if firstText == "" {
					firstText = s // fallback if every block is a reminder
				}
				// Skip CC's injected system-reminder blocks (isMeta) — the real
				// CLI hashes the first NON-reminder user text.
				if strings.HasPrefix(strings.TrimLeft(s, " \t\r\n"), systemReminderPrefix) {
					continue
				}
				return s
			}
			return firstText
		}
		return ""
	}
	return ""
}

// signBillingHeaderCCH replaces the cch=00000 placeholder in the billing
// block with a dynamic 5-char hex digest of the body. This seeded xxhash is a
// legacy best-effort reconstruction. It keeps the field dynamic, but 0/37
// genuine 2.1.220 samples matched it; the real signer remains unresolved.
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
// last block of the last message — exactly what real CC does
// (verified in crack/claudev2.1.220/SPEC.md).
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
		arr, _ := json.Marshal([]json.RawMessage{buildSystemTextBlock(asString, true, false)})
		msg["content"] = arr
		return msg
	}

	// Edit the last block as raw bytes so the client's own key order and any
	// keys we don't model survive, and cache_control lands last — the same
	// reason injectCacheControl does it this way.
	var blocks []json.RawMessage
	if err := json.Unmarshal(contentRaw, &blocks); err != nil || len(blocks) == 0 {
		return msg
	}
	last := blocks[len(blocks)-1]
	if existing, ok := findJSONObjectMemberSpan(last, "cache_control"); ok {
		var cc claudeCacheControl
		if err := json.Unmarshal(last[existing.start:existing.end], &cc); err != nil || cc.TTL != "" {
			// Unreadable, or the client already set a breakpoint here — respect it.
			return msg
		}
		cc.TTL = ClaudeDefaultCacheTTL
		updated, err := setJSONObjectMember(last, "cache_control", cc)
		if err != nil {
			return msg
		}
		last = updated
	} else {
		updated, err := setJSONObjectMember(last, "cache_control", claudeSystemCacheControl(false))
		if err != nil {
			return msg
		}
		last = updated
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
	b, _ := json.Marshal(struct {
		DeviceID    string `json:"device_id"`
		AccountUUID string `json:"account_uuid"`
		SessionID   string `json:"session_id"`
	}{
		DeviceID:    deviceID,
		AccountUUID: accountUUID,
		SessionID:   sessionID,
	})
	return string(b)
}
