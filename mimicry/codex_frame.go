package mimicry

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Codex WebSocket client-frame rebinding.
//
// The WS relay forwards a downstream client's `response.create` frame upstream
// essentially verbatim. That is wrong in a way the handshake work made visible:
//
//   - The frame's `client_metadata` carries the DOWNSTREAM client's own
//     installation id, session id, thread id, turn id and window id. Forwarded
//     as-is under our pooled credential, N downstream users present as N
//     different installations on one ChatGPT account — the same "many machines,
//     one account" signal that auth.HostProfile exists to defuse on the
//     Anthropic side, inverted.
//   - Worse, those ids then DISAGREE with the ones we put on the handshake
//     (codexws.BuildUpstreamHeadersWithOptions derives session/installation from
//     the account). A genuine client sends the same values in both places —
//     `x-client-request-id == session-id == thread-id`, and the frame's
//     `client_metadata.session_id` matches the header. One comparison separates
//     us from every real client.
//
// RewriteCodexClientFrame rebinds those ids to the identity we advertise on the
// handshake, so the two halves agree.
//
// Ground truth: crack/codexapp0.147.0/rows/15 (turn-opening frame) and rows/18
// (continuation), 8 captured frames across 3 sessions.
//
// # Why substitution rather than a re-encode
//
// Top-level key order in `response.create` is stable across every captured
// frame (type, model, [previous_response_id,] input, tool_choice,
// parallel_tool_calls, reasoning, store, stream, [stream_options,] include,
// prompt_cache_key, text, [generate,] client_metadata) and is part of the
// captured shape, so a map round-trip — which Go would emit in sorted order —
// is not acceptable here. This is the same rule that governs the Anthropic
// body rewrites.
//
// The ids we need to change are UUIDs, and each one appears in several places
// that MUST stay consistent with each other:
//
//	turn_id  →  client_metadata.turn_id
//	         →  client_metadata["x-codex-turn-metadata"] (an embedded JSON string)
//	         →  input[].internal_chat_message_metadata_passthrough.turn_id
//
// Rewriting them structurally would mean walking `input`, which is the largest
// and most variable part of the frame. Instead we substitute each id as a
// literal token across the whole frame. A v4/v7 UUID is 36 unique characters;
// replacing the exact strings we just read out of the frame's own metadata
// cannot collide with unrelated content, and it keeps every other byte —
// including all key ordering — untouched.
//
// Note that `client_metadata`'s OWN key order is deliberately not preserved
// when we synthesize one: the captures show it varying between frames of a
// single session (it is a Rust HashMap), so unlike the top level, its order
// carries no signal.

// CodexFrameIdentity is the upstream identity a rewritten frame must present.
//
// It MUST match what codexws put on the handshake for the same connection.
// Build it once per upstream connection and hand the same value to both, or the
// frame and the headers will disagree — which is the exact tell this whole file
// exists to remove. codexws.UpstreamHeaderOptions.Identity takes this type for
// that reason.
type CodexFrameIdentity struct {
	// AccountKey anchors every derived value. Required.
	//
	// Use the SAME anchor everywhere for one credential — auth.Auth.AccountKey()
	// is the intended value. Deriving the installation id from the ChatGPT
	// account UUID in one place and from the account key in another produces two
	// different installation ids for one account.
	AccountKey string
	// SessionID is the UUIDv7 sent as the handshake's session-id. Required, and
	// must be a canonical UUID.
	//
	// Never pass a value a downstream client controls. It becomes our upstream
	// session-id, thread-id, window-id prefix and prompt_cache_key, so a
	// caller-supplied value lets one downstream user land in another's upstream
	// prompt-cache namespace. Derive it with CodexSessionUUIDFor.
	SessionID string
	// ThreadID defaults to SessionID (a brand-new thread), matching every
	// captured handshake.
	ThreadID string
	// InstallationID defaults to CodexInstallationIDFor(AccountKey).
	InstallationID string
	// WindowIndex is the suffix on x-codex-window-id. A proxy serves one
	// logical window per session, so 0 unless a caller knows better.
	WindowIndex int
}

// Normalized fills the defaults and validates. Exported so codexws can resolve
// exactly the same values this package will put in the frame.
func (id CodexFrameIdentity) Normalized() (CodexFrameIdentity, error) {
	if strings.TrimSpace(id.AccountKey) == "" {
		return id, errors.New("mimicry: CodexFrameIdentity.AccountKey is required")
	}
	id.SessionID = strings.TrimSpace(id.SessionID)
	if id.SessionID == "" {
		return id, errors.New("mimicry: CodexFrameIdentity.SessionID is required")
	}
	if !looksLikeUUID(id.SessionID) {
		return id, fmt.Errorf("mimicry: CodexFrameIdentity.SessionID %q is not a UUID", id.SessionID)
	}
	if id.ThreadID == "" {
		id.ThreadID = id.SessionID
	}
	if id.InstallationID == "" {
		id.InstallationID = CodexInstallationIDFor(id.AccountKey)
	}
	if id.WindowIndex < 0 {
		id.WindowIndex = 0
	}
	return id, nil
}

// WindowID renders this identity's x-codex-window-id.
func (id CodexFrameIdentity) WindowID() string {
	return fmt.Sprintf("%s:%d", id.SessionID, id.WindowIndex)
}

// CodexTurnIDFor maps a downstream client's turn id into our identity domain.
//
// Deterministic so that every place the id appears in one frame — and every
// later frame of the same turn — resolves to the same value. Keyed on the
// account as well, so two downstream users who happen to mint the same turn id
// do not collide, and a turn id never survives across accounts.
//
// The result is a v7-shaped UUID because that is what real Codex mints; the
// timestamp is carried over from the client's own id when it is itself a v7,
// so the ordering property survives.
func CodexTurnIDFor(accountKey, clientTurnID string) string {
	sum := sha256.Sum256([]byte("cc-core-codex-turn/" + accountKey + "|" + clientTurnID))
	var tail [10]byte
	copy(tail[:], sum[:10])
	if ts, ok := uuidV7Timestamp(clientTurnID); ok {
		return codexUUIDv7FromParts(ts, tail)
	}
	return UUIDFromBytes(sum[:16])
}

// codexFrameType extracts a frame's "type" value with a real parse of the
// top-level object.
//
// A substring search for `"response.create"` is not good enough: a Codex frame
// carries arbitrary user prose (prompts, tool output, file contents), so a
// client discussing the Codex protocol would make a response.cancel frame look
// like a response.create and get it rewritten. downstream.ScrubCodexEvent
// already takes the strict route for the same reason.
func codexFrameType(frame []byte) string {
	var out string
	scanTopLevelObject(frame, func(k string, vs, ve int) bool {
		if k != "type" {
			return true
		}
		if ve-vs >= 2 && frame[vs] == '"' {
			out = string(frame[vs+1 : ve-1])
		}
		return false
	})
	return out
}

// RewriteCodexClientFrame rebinds a downstream `response.create` frame to the
// upstream identity in id.
//
// Frames that are not `response.create` (client-side control frames, anything
// unrecognised) are returned unchanged — this must never be the thing that
// breaks a turn. A frame with no `client_metadata` gets one synthesized, since
// every genuine client sends it; it is appended last, which is where the
// captures put it.
//
// The returned slice is a fresh allocation whenever anything changed, and a
// sub-slice of the input otherwise.
func RewriteCodexClientFrame(frame []byte, id CodexFrameIdentity) ([]byte, error) {
	norm, err := id.Normalized()
	if err != nil {
		return frame, err
	}
	trimmed := bytes.TrimSpace(frame)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return frame, nil
	}
	if codexFrameType(trimmed) != "response.create" {
		return frame, nil
	}

	meta, found := extractCodexClientMetadata(trimmed)
	if !found {
		out, aerr := appendCodexClientMetadata(trimmed, norm)
		if aerr != nil {
			return frame, aerr
		}
		// The synthesized metadata is already ours, but prompt_cache_key is a
		// TOP-LEVEL key and may still be the client's. This branch is exactly
		// the third-party client the rebinding exists for — returning early
		// here used to skip it, so the one case the doc promised to cover was
		// the one case that leaked.
		return rebindCodexPromptCacheKey(out, norm.SessionID), nil
	}

	// Read the client's ids, then map each to ours. Anything the client did not
	// send simply has no substitution — we never invent a replacement for a
	// value that was not there.
	//
	// Ordered, and first-write-wins on a duplicate source. Both matter: a
	// genuine client sends session_id == thread_id, so one UUID legitimately
	// maps from two slots, and a map would pick a winner nondeterministically.
	// Session is registered first, so a collapsed pair stays collapsed on our
	// side too — which is the genuine shape.
	var subs []tokenSub
	seen := map[string]bool{}
	addSub := func(from, to string) {
		// Only canonical UUIDs are substituted. from is fully downstream-
		// controlled, and a short value would rewrite every occurrence of that
		// text in the frame, including JSON syntax and user prose.
		if !looksLikeUUID(from) || to == "" || from == to || seen[from] {
			return
		}
		seen[from] = true
		subs = append(subs, tokenSub{from: from, to: to})
	}
	clientSession := metaString(meta, "session_id")
	clientThread := metaString(meta, "thread_id")
	clientTurn := metaString(meta, "turn_id")
	clientInstall := metaString(meta, "x-codex-installation-id")

	// The embedded turn-metadata is the authority when the flat keys are absent
	// — the captures show frames that carry one and not the other.
	if embedded := decodeEmbeddedTurnMetadata(meta); embedded != nil {
		if clientSession == "" {
			clientSession = metaString(embedded, "session_id")
		}
		if clientThread == "" {
			clientThread = metaString(embedded, "thread_id")
		}
		if clientTurn == "" {
			clientTurn = metaString(embedded, "turn_id")
		}
		if clientInstall == "" {
			clientInstall = metaString(embedded, "installation_id")
		}
	}

	addSub(clientSession, norm.SessionID)
	addSub(clientThread, norm.ThreadID)
	addSub(clientInstall, norm.InstallationID)
	if clientTurn != "" {
		addSub(clientTurn, CodexTurnIDFor(norm.AccountKey, clientTurn))
	}

	out := trimmed
	if len(subs) > 0 {
		// Substitute over the WHOLE frame, not just client_metadata: the same
		// turn id also appears in input[].internal_chat_message_metadata_passthrough,
		// and the window id embeds the session id. Leaving those behind would
		// produce a frame that contradicts itself.
		out = substituteTokens(out, subs)
	}

	// Everything below addresses a specific top-level key or stays inside
	// client_metadata, so none of it can reach into user prose.
	out = rebindCodexWindowID(out, norm.WindowID())
	out = rebindCodexPromptCacheKey(out, norm.SessionID)
	return out, nil
}

// RemoveCodexPreviousResponseID deletes the top-level `previous_response_id`
// key from a client frame, preserving every other byte.
//
// A relay has to drop this key when the id belongs to a response served by a
// different credential — the new upstream has never heard of it. The obvious
// implementation is unmarshal → delete → marshal, and both forks did exactly
// that; the problem is that Go emits map keys in sorted order, so the frame
// comes back with its top-level key order rewritten. Codex's own order is
// stable across every captured frame and is part of the shape, which makes the
// map round-trip a fingerprint defect that survives all the identity work in
// this file.
//
// Frames without the key are returned unchanged, sharing the input's backing
// array.
func RemoveCodexPreviousResponseID(frame []byte) []byte {
	start, end, ok := topLevelValueSpan(frame, "previous_response_id")
	if !ok {
		return frame
	}
	// Widen the cut to swallow the key, its colon, and exactly one adjacent
	// comma, so the object stays well-formed whether the key was first, last,
	// or in the middle.
	keyStart := bytes.LastIndex(frame[:start], []byte(`"previous_response_id"`))
	if keyStart < 0 {
		return frame
	}
	cutFrom, cutTo := keyStart, end

	trailing := skipJSONSpace(frame, cutTo)
	if trailing < len(frame) && frame[trailing] == ',' {
		// Swallow the separator AND the whitespace that followed it, so the
		// member that moves up keeps the spacing style of the one we removed
		// rather than inheriting both.
		cutTo = skipJSONSpace(frame, trailing+1)
	} else {
		// No comma after: this was the last member, so take the one before it.
		leading := cutFrom
		for leading > 0 && isJSONSpace(frame[leading-1]) {
			leading--
		}
		if leading > 0 && frame[leading-1] == ',' {
			cutFrom = leading - 1
		}
	}
	out := make([]byte, 0, len(frame)-(cutTo-cutFrom))
	out = append(out, frame[:cutFrom]...)
	out = append(out, frame[cutTo:]...)
	return out
}

// CodexPreviousResponseID reads the top-level previous_response_id, or "".
func CodexPreviousResponseID(frame []byte) string {
	start, end, ok := topLevelValueSpan(frame, "previous_response_id")
	if !ok || end-start < 2 || frame[start] != '"' {
		return ""
	}
	return string(frame[start+1 : end-1])
}

// rebindCodexPromptCacheKey forces the top-level prompt_cache_key to our
// session id.
//
// Every captured frame has prompt_cache_key == session_id, so the token
// substitution above already covers a genuine client. A third-party client that
// sends some other value would otherwise leak its own identifier upstream and
// land in a cache namespace that disagrees with the session we advertised.
func rebindCodexPromptCacheKey(b []byte, sessionID string) []byte {
	start, end, ok := topLevelValueSpan(b, "prompt_cache_key")
	if !ok || end-start < 2 || b[start] != '"' {
		return b
	}
	if string(b[start+1:end-1]) == sessionID {
		return b
	}
	quoted, err := json.Marshal(sessionID)
	if err != nil {
		return b
	}
	return replaceSpan(b, start, end, quoted)
}

// rebindCodexWindowID pins every window id to ours.
//
// Scoped to the client_metadata object — both the plain key and the escaped
// copy inside the x-codex-turn-metadata string live there — so a window id
// appearing in a user's prompt is never touched.
func rebindCodexWindowID(b []byte, want string) []byte {
	start, end, ok := topLevelValueSpan(b, "client_metadata")
	if !ok {
		return b
	}
	patched := replaceQuotedValue(b[start:end], `"x-codex-window-id":"`, `"`, want)
	patched = replaceQuotedValue(patched, `\"window_id\":\"`, `\"`, want)
	if bytes.Equal(patched, b[start:end]) {
		return b
	}
	return replaceSpan(b, start, end, patched)
}

// replaceQuotedValue rewrites the value following each occurrence of prefix, up
// to the next terminator, leaving everything else alone.
func replaceQuotedValue(b []byte, prefix, terminator, want string) []byte {
	out := b
	idx := 0
	for {
		i := bytes.Index(out[idx:], []byte(prefix))
		if i < 0 {
			return out
		}
		vs := idx + i + len(prefix)
		rel := bytes.Index(out[vs:], []byte(terminator))
		if rel < 0 {
			return out
		}
		ve := vs + rel
		if string(out[vs:ve]) == want {
			idx = ve
			continue
		}
		out = replaceSpan(out, vs, ve, []byte(want))
		idx = vs + len(want)
	}
}

type tokenSub struct{ from, to string }

// substituteTokens replaces every literal occurrence of each source token with
// its replacement, in ONE left-to-right pass.
//
// A single pass is required, not an optimisation. Running bytes.ReplaceAll per
// pair would chain: with {A→B, B→C} an A in the input becomes B and then C,
// which is not what any of the pairs asked for. Since the account-derived
// replacements are drawn from the same UUID space as the client values that
// feed them, that collision is reachable rather than theoretical. Scanning once
// and skipping past each emitted replacement makes a substituted value
// permanently ineligible for further substitution.
//
// Sources are matched longest-first so that one token being a prefix of another
// cannot split it. Callers must only pass canonical UUIDs (see looksLikeUUID),
// which makes both hazards unreachable in practice — this is defence in depth.
func substituteTokens(b []byte, subs []tokenSub) []byte {
	if len(subs) == 0 {
		return b
	}
	ordered := make([]tokenSub, len(subs))
	copy(ordered, subs)
	sort.SliceStable(ordered, func(i, j int) bool {
		return len(ordered[i].from) > len(ordered[j].from)
	})

	var out []byte
	i := 0
	for i < len(b) {
		matched := false
		for _, s := range ordered {
			if len(s.from) == 0 || i+len(s.from) > len(b) {
				continue
			}
			if string(b[i:i+len(s.from)]) != s.from {
				continue
			}
			if out == nil {
				out = make([]byte, 0, len(b)+64)
				out = append(out, b[:i]...)
			}
			out = append(out, s.to...)
			i += len(s.from)
			matched = true
			break
		}
		if matched {
			continue
		}
		if out != nil {
			out = append(out, b[i])
		}
		i++
	}
	if out == nil {
		return b
	}
	return out
}

// extractCodexClientMetadata returns the decoded client_metadata object.
func extractCodexClientMetadata(frame []byte) (map[string]any, bool) {
	start, end, ok := topLevelValueSpan(frame, "client_metadata")
	if !ok || end <= start || frame[start] != '{' {
		return nil, false
	}
	var meta map[string]any
	if err := json.Unmarshal(frame[start:end], &meta); err != nil {
		return nil, false
	}
	return meta, true
}

// matchBrace returns the index just past the object starting at frame[start].
func matchBrace(frame []byte, start int) (int, bool) {
	return matchDelim(frame, start, '{', '}')
}

// appendCodexClientMetadata adds a synthesized client_metadata to a frame that
// has none, as the LAST key — which is where every captured frame puts it.
//
// The synthesized object carries all EIGHT keys the captures show, not just the
// ones we happen to derive: a client_metadata missing two keys is its own
// fingerprint. It declares request_kind "prewarm" with an empty turn_id,
// because that is the only combination the captures pair together — the turn
// variant always has a non-empty turn_id and three extra fields
// (code_mode_tool_names, turn_started_at_unix_ms, workspace_kind) that a proxy
// cannot synthesize, so claiming "turn" here would produce a shape no genuine
// client emits.
func appendCodexClientMetadata(frame []byte, id CodexFrameIdentity) ([]byte, error) {
	end := bytes.LastIndexByte(frame, '}')
	if end < 0 {
		return frame, errors.New("mimicry: frame is not a JSON object")
	}
	md := CodexTurnMetadata{
		InstallationID: id.InstallationID,
		SessionID:      id.SessionID,
		ThreadID:       id.ThreadID,
		TurnID:         "",
		WindowID:       id.WindowID(),
		RequestKind:    CodexRequestKindPrewarm,
		ThreadSource:   "user",
		Sandbox:        "seccomp",
	}
	meta := map[string]any{
		"session_id":              id.SessionID,
		"thread_id":               id.ThreadID,
		"turn_id":                 "",
		"x-codex-installation-id": id.InstallationID,
		"x-codex-window-id":       id.WindowID(),
		"x-codex-turn-metadata":   md.Encode(),
		// Real Codex smuggles this HTTP header into the frame body because a
		// WebSocket cannot set per-message headers.
		"ws_request_header_x_openai_internal_codex_responses_lite": "true",
		"x-codex-ws-stream-request-start-ms":                       strconv.FormatInt(time.Now().UnixMilli(), 10),
	}
	encoded, err := json.Marshal(meta)
	if err != nil {
		return frame, err
	}
	sep := ","
	if len(bytes.TrimSpace(frame[1:end])) == 0 {
		sep = ""
	}
	out := make([]byte, 0, len(frame)+len(encoded)+24)
	out = append(out, frame[:end]...)
	out = append(out, sep...)
	out = append(out, `"client_metadata":`...)
	out = append(out, encoded...)
	out = append(out, frame[end:]...)
	return out, nil
}

func decodeEmbeddedTurnMetadata(meta map[string]any) map[string]any {
	raw, _ := meta["x-codex-turn-metadata"].(string)
	if raw == "" {
		return nil
	}
	var out map[string]any
	if json.Unmarshal([]byte(raw), &out) != nil {
		return nil
	}
	return out
}

func metaString(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	s, _ := m[key].(string)
	return strings.TrimSpace(s)
}

// uuidV7Timestamp reads the 48-bit millisecond timestamp out of a v7 UUID.
func uuidV7Timestamp(s string) (time.Time, bool) {
	if !looksLikeUUID(s) || s[14] != '7' {
		return time.Time{}, false
	}
	hexPart := s[0:8] + s[9:13]
	var ms int64
	for i := 0; i < len(hexPart); i++ {
		c := hexPart[i]
		var v int64
		switch {
		case c >= '0' && c <= '9':
			v = int64(c - '0')
		case c >= 'a' && c <= 'f':
			v = int64(c-'a') + 10
		case c >= 'A' && c <= 'F':
			v = int64(c-'A') + 10
		default:
			return time.Time{}, false
		}
		ms = ms<<4 | v
	}
	return time.UnixMilli(ms), true
}
