package mimicry

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// Codex client identities.
//
// There are two genuine Codex clients on the ChatGPT subscription backend and
// they are NOT interchangeable. Each carries its own Originator / User-Agent /
// Version triple, and the backend 404s a request whose originator disagrees
// with the User-Agent's leading segment, so the three values must always move
// together as one profile.
//
//   - Codex Desktop — the Electron/Tauri app. Ground truth:
//     crack/codexapp0.153.4/ (whistle dump 2026-09-07, a complete re-login plus
//     nineteen WS upgrades). It supersedes crack/codexapp0.147.0/, which
//     remains the only record of the 0.147.0 handshake shape.
//   - codex-tui — the Rust terminal client. Ground truth:
//     crack/codexv0.153.4/ (whistle dump 2026-09-05).
//
// Desktop is the larger installed base but is NOT the default; codex-tui is.
// The reason is not the version floor that first forced the switch (the
// constants below now clear it) — it is that the two clients send the same
// WebSocket upgrade, so the profile decides identity only, and only the CLI's
// identity has byte-parity tests against a live capture. See
// DefaultCodexProfile for the full history, including why the 0.153.4 Desktop
// capture did not justify flipping back.
const (
	// CodexDesktopVersion is the `version` header value and the version
	// segment of CodexDesktopUserAgent. The two must always agree.
	//
	// 0.153.4 is a STABLE tag. The 0.147.0 capture pinned a pre-release
	// ("0.147.0-alpha.6.6"), which is why the surrounding comments warn about
	// inventing this string: the backend has been observed 404ing clients
	// whose version is below a floor (openai/codex#3901), so it parses this
	// field, and a version/UA mismatch is a one-header tell.
	CodexDesktopVersion = "0.153.4"

	// CodexDesktopBuild is the Desktop app build number that appears ONLY in
	// the User-Agent's trailing parenthetical and in the analytics-events
	// body as app_server_client.client_version. It is not a semver and is
	// not the same thing as CodexDesktopVersion (which is the codex-rs core
	// version, reported as runtime.codex_rs_version in the same body).
	//
	// 26.803.81509 (0.147.0) → 26.901.51231 (0.153.4): it moves independently
	// of the version, so it cannot be derived and must come from a capture.
	CodexDesktopBuild = "26.901.51231"

	CodexDesktopOriginator = "Codex Desktop"

	// CodexDesktopUserAgent follows codex-rs's get_codex_user_agent():
	// "{originator}/{version} ({os_type} {os_version}; {arch}) {terminal_ua}{suffix}".
	// The OS/terminal segment is our synthetic Arch/Konsole identity, shared
	// with CodexCLIUserAgent; see the note on per-account variation below.
	//
	// THREE segments moved between 0.147.0 and 0.153.4 — the version, the
	// terminal (Konsole/260403 → Konsole/260800) and the build tail. A version
	// bump here is never a one-token edit; re-read the capture for all three.
	CodexDesktopUserAgent = "Codex Desktop/" + CodexDesktopVersion +
		" (Arch Linux Rolling Release; x86_64) Konsole/260800 (Codex Desktop; " + CodexDesktopBuild + ")"

	// CodexDesktopBetaFeatures is the x-codex-beta-features value. This drifts
	// per release and is NOT derivable — 0.135.0 sent "terminal_resize_reflow",
	// 0.147.0 and 0.153.4 send "remote_compaction_v2". Re-capture on every
	// version bump.
	//
	// The CLI and Desktop values have CONVERGED at 0.153.4 — both send
	// "remote_compaction_v2" on every ordinary upgrade — which is one more
	// reason the two clients' handshakes are indistinguishable.
	CodexDesktopBetaFeatures = "remote_compaction_v2"

	// CodexDesktopModelsClientVersion is the `client_version` query parameter
	// on GET /backend-api/codex/models.
	//
	// At 0.147.0 this was a DIFFERENT string from the version header: the app
	// self-reported "0.147.0-alpha.6.6" in the header and the base "0.147.0"
	// in the query. 0.153.4 is a stable tag with no pre-release suffix, and
	// crack/codexapp0.153.4/rows/12 shows client_version=0.153.4 — the two
	// coincide, so this is defined as the version rather than retyped. If a
	// future capture pins a pre-release again, split this back out to the base
	// triple instead of letting the alpha suffix leak into the query.
	CodexDesktopModelsClientVersion = CodexDesktopVersion
)

// CodexDesktopBaseUserAgent is the Desktop User-Agent MINUS the trailing
// "(Codex Desktop; <build>)" parenthetical.
//
// Four User-Agent forms coexist in one Desktop process (crack/codexapp0.153.4/
// SPEC.md §1). Two of them are per-component and unambiguous
// (codex-mcp-client/… on ps/mcp, the OTLP exporter on the metrics endpoint);
// the other two are this one and the full CodexDesktopUserAgent.
//
// The full-vs-base split is NOT per-endpoint — do not encode a rule that says
// otherwise. codex/models, plugins/featured, ps/plugins/{installed,suggested}
// and wham/remote/control each appear with BOTH forms inside the single
// capture, most likely because the app-server and the codex-rs core reach the
// same endpoints under the same originator. The two endpoints that never vary
// are POST /oauth/token and the WebSocket upgrade, and both send the FULL UA.
//
// It is DERIVED rather than written out, exactly as CodexModelsUserAgent is
// derived from CodexCLIUserAgent, so a version or build bump cannot move one
// form and leave the other stale. That is the whole failure mode this file
// exists to prevent, and it is why this is exported: callers that need the
// base form must take it from here rather than re-deriving it locally.
var CodexDesktopBaseUserAgent = strings.TrimSuffix(
	CodexDesktopUserAgent, " ("+CodexDesktopOriginator+"; "+CodexDesktopBuild+")")

// CodexClientProfile is one complete, self-consistent Codex client identity.
// Never mix fields across profiles: originator, UA and version are validated
// against each other upstream.
type CodexClientProfile struct {
	// Originator is the `originator` header.
	Originator string
	// UserAgent is the `user-agent` header. Its leading "{name}/{version}"
	// segment must agree with Originator and Version.
	UserAgent string
	// Version is the `version` header.
	Version string
	// BetaFeatures is the `x-codex-beta-features` header. Empty omits it.
	BetaFeatures string
	// ModelsClientVersion is the client_version query parameter on
	// GET /backend-api/codex/models. Empty falls back to Version.
	ModelsClientVersion string
	// SendsTurnMetadata reports whether this client sends the
	// x-codex-turn-metadata / x-codex-window-id / thread-id / session-id /
	// x-client-request-id cluster on a WebSocket handshake.
	//
	// Both real clients do, and they send the SAME cluster: the ordinary
	// upgrade is identical in header set and order whether it comes from
	// Codex Desktop or codex-tui (crack/codexapp0.153.4/SPEC.md §3). There is
	// no per-client handshake shape to select — see DefaultCodexProfile.
	SendsTurnMetadata bool
}

// CodexDesktopClientProfile returns the Codex Desktop app identity — the
// default. It is a function, not a var, so a consumer cannot reach in and
// mutate a fingerprint constant for every caller in the process; a profile is
// meant to be selected, never edited.
func CodexDesktopClientProfile() CodexClientProfile { return codexDesktopClientProfile }

// CodexTUIClientProfile returns the codex-tui terminal client identity, kept so
// a consumer that specifically wants the CLI shape can still ask for it.
func CodexTUIClientProfile() CodexClientProfile { return codexTUIClientProfile }

var codexDesktopClientProfile = CodexClientProfile{
	Originator:          CodexDesktopOriginator,
	UserAgent:           CodexDesktopUserAgent,
	Version:             CodexDesktopVersion,
	BetaFeatures:        CodexDesktopBetaFeatures,
	ModelsClientVersion: CodexDesktopModelsClientVersion,
	SendsTurnMetadata:   true,
}

var codexTUIClientProfile = CodexClientProfile{
	Originator:          CodexOriginator,
	UserAgent:           CodexCLIUserAgent,
	Version:             CodexCLIVersion,
	BetaFeatures:        CodexCLIBetaFeatures,
	ModelsClientVersion: CodexCLIVersion,
	SendsTurnMetadata:   true,
}

// DefaultCodexProfile returns the identity cc-core presents upstream by
// default. Both forks get this without opting in, so changing it is a
// behaviour change for production traffic on both at once.
//
// It returns the codex-tui (CLI) profile. It used to return Desktop; the flip
// happened on 2026-09-05 and was RE-EXAMINED on 2026-09-07 against a fresh
// Desktop capture, which did not justify flipping back. Both halves are
// recorded so this is not re-litigated a third time.
//
// Why it flipped, 2026-09-05: the 0.153.4 model catalog gates gpt-6-astra
// behind minimal_client_version "0.153.0". The Desktop profile self-reported
// 0.147.0-alpha.6.6, below that floor, so a Desktop-identified request could
// not be routed to the current flagship at all — and Desktop could not be
// bumped past it, because its version, build number and terminal segment are
// three independent values and no capture backed them.
//
// Why it did NOT flip back, 2026-09-07: crack/codexapp0.153.4/ supplied that
// missing capture, and the constants above were refreshed from it, so the
// version-floor argument is spent — Desktop is 0.153.4 now and clears it. The
// flip back was proposed on the further belief that Desktop had its own
// WebSocket handshake shape that cc-core was failing to emit. It does not.
// All 19 upgrades in that capture carry originator "Codex Desktop", and the
// ordinary-thread ones are IDENTICAL in header set and order to the codex-tui
// upgrade in crack/codexv0.153.4/rows/10 (SPEC §3). The 18-header variant that
// looked like a Desktop shape is an auto-review GUARDIAN subagent running
// Responses-Lite — a connection kind a proxy never has — and a single
// 21-header row proves guardians use the ordinary shape too, so it is not even
// universal among subagents.
//
// So the handshake is the same either way, and the choice of profile decides
// only the advertised identity. The CLI wins that on evidence: it is the
// profile with a live capture behind every constant AND byte-parity tests
// against it (codexws/capture_parity_test.go reads the row). Presenting
// Desktop would buy nothing and give up the verified identity. Revisit only if
// a capture shows the two clients' UPGRADES actually diverging.
func DefaultCodexProfile() CodexClientProfile { return codexTUIClientProfile }

// NOTE ON PER-ACCOUNT VARIATION — deliberately NOT done here.
//
// Every account routed through the proxy currently advertises the same
// synthetic machine ("Arch Linux Rolling Release; x86_64" / "Konsole/260800"),
// which is the same "many users, one rare machine" signal auth.HostProfile
// exists to defuse on the Anthropic side. Wiring HostProfile into the Codex UA
// would require inventing an os_type/os_version pair per distro and a
// terminal_ua version per terminal — values that no capture backs. Per the
// repo rule that fingerprint constants must match crack/, guessing them is a
// worse fingerprint than uniformity. Doing this properly needs captures from
// Codex clients on other distros/terminals first.

// CodexInstallationIDFor derives the installation_id that appears in
// x-codex-turn-metadata and in the analytics-events body. Real Codex mints a
// random v4 UUID once at install time and reuses it forever; ours is
// content-addressed off the account anchor so it survives credential-file
// rotation and stays identical across every request for that account — the
// same property, reached the way the rest of cc-core derives identity.
//
// It is keyed on the ACCOUNT, not the client token: one upstream account is
// one installation. Deriving it per downstream user would present a single
// ChatGPT account as N machines, which is the inverse of the real shape.
func CodexInstallationIDFor(accountKey string) string {
	sum := sha256.Sum256([]byte("cc-core-codex-installation/" + accountKey))
	return UUIDFromBytes(sum[:16])
}

// NewCodexSessionUUID returns a fresh UUIDv7 for a Codex session/thread id.
//
// Version 7, not 4: every session/thread/window/request id in both Codex
// captures is a v7 (time-ordered, "01a0011b-…" prefix). The version nibble is
// visible in the string, so minting a v4 where the genuine client mints a v7
// is a tell that survives every other layer of mimicry.
func NewCodexSessionUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand cannot realistically fail; degrade to a deterministic
		// value rather than dropping the request.
		return codexUUIDv7FromParts(time.Now(), [10]byte{})
	}
	var tail [10]byte
	copy(tail[:], b[6:])
	return codexUUIDv7FromParts(time.Now(), tail)
}

// CodexSessionUUIDFor derives a STABLE UUIDv7 session id for one conversation.
//
// startedAt must be an instant the caller can reproduce for every request of
// the same conversation (e.g. when the session was first seen). A v7's leading
// 48 bits are a Unix-millisecond timestamp, so passing time.Now() per request
// would mint a new id each time and break session stickiness; passing a
// constant far from the present would produce a timestamp that disagrees with
// when the traffic actually arrives. The random tail is derived from anchor, so
// the same (anchor, startedAt) always yields the same id.
func CodexSessionUUIDFor(anchor string, startedAt time.Time) string {
	sum := sha256.Sum256([]byte("cc-core-codex-session/" + anchor))
	var tail [10]byte
	copy(tail[:], sum[:10])
	if startedAt.IsZero() || startedAt.UnixMilli() <= 0 {
		// A forgotten startedAt would otherwise mint a v7 whose timestamp is
		// 1970-01-01. Real v7s are always "roughly now", so that is a
		// single-field tell — and a silent one, since nothing else about the id
		// would look wrong. Falling back to now costs the caller session
		// stickiness (each call yields a new id), which is a visible bug they
		// will notice, rather than an invisible fingerprint they will not.
		startedAt = time.Now()
	}
	return codexUUIDv7FromParts(startedAt, tail)
}

// codexUUIDv7FromParts assembles an RFC 9562 v7 UUID: 48-bit big-endian
// Unix-millisecond timestamp, 4-bit version, 12 bits of entropy, 2-bit
// variant, 62 bits of entropy.
func codexUUIDv7FromParts(t time.Time, tail [10]byte) string {
	var b [16]byte
	ms := t.UnixMilli()
	if ms < 0 {
		ms = 0
	}
	var stamp [8]byte
	binary.BigEndian.PutUint64(stamp[:], uint64(ms))
	copy(b[0:6], stamp[2:8]) // low 48 bits
	copy(b[6:16], tail[:])
	b[6] = (b[6] & 0x0f) | 0x70 // version 7
	b[8] = (b[8] & 0x3f) | 0x80 // variant RFC 4122
	return formatUUIDHex(b)
}

func formatUUIDHex(b [16]byte) string {
	var out [36]byte
	hexEnc := make([]byte, 32)
	hex.Encode(hexEnc, b[:])
	copy(out[0:8], hexEnc[0:8])
	out[8] = '-'
	copy(out[9:13], hexEnc[8:12])
	out[13] = '-'
	copy(out[14:18], hexEnc[12:16])
	out[18] = '-'
	copy(out[19:23], hexEnc[16:20])
	out[23] = '-'
	copy(out[24:36], hexEnc[20:32])
	return string(out[:])
}

// Codex request_kind values carried in x-codex-turn-metadata.
const (
	// CodexRequestKindPrewarm is what the WebSocket HANDSHAKE carries. Both
	// captures show turn_id empty and request_kind "prewarm" at handshake
	// time — the connection is opened before the user's turn exists.
	CodexRequestKindPrewarm = "prewarm"
	// CodexRequestKindTurn is what the in-band response.create frame carries,
	// alongside a non-empty turn_id.
	CodexRequestKindTurn = "turn"
)

// CodexDefaultAgentName is the `agent_name` value emitted when the downstream
// client did not declare one.
//
// It is the client's working directory. A proxy cannot know the real one, and
// every connection in crack/codexv0.153.4 carried "/root" — a plausible value
// for the server and container hosts most subscription Codex traffic runs on.
//
// This is uniform across accounts on purpose, for the same reason the synthetic
// User-Agent is (see the per-account-variation note above): inventing a
// per-account directory tree is a guess no capture backs, and a wrong-shaped
// guess is a worse fingerprint than a real value shared by many accounts. It is
// also a real gap — recorded in crack/codexv0.153.4/README.md — and the right
// fix is carrying the DOWNSTREAM client's own agent_name through, which
// RewriteCodexClientFrame does whenever the client sends one.
const CodexDefaultAgentName = "/root"

// Codex sandbox_mode values carried in x-codex-turn-metadata. The capture pairs
// workspace-write with thread_source "user" and read-only with "system" /
// "guardian_review".
const (
	CodexSandboxModeWorkspaceWrite = "workspace-write"
	CodexSandboxModeReadOnly       = "read-only"
)

// CodexTurnMetadata is the x-codex-turn-metadata payload.
//
// The 0.135.0 CLI capture carried a `workspaces` map here holding the user's
// cwd, git remote URL, commit hash and dirty flag — genuinely unforgeable by a
// proxy, and the documented reason cc-core omitted this header entirely. The
// 0.147.0 Desktop capture no longer sends it (workspace state moved to a
// `workspace_kind` string on the turn variant only), leaving nothing in the
// handshake variant that a proxy cannot legitimately synthesize. That is why
// the header is emitted now.
//
// 0.153.4 grew the payload from 8 fields to 15 (17 on a subagent connection).
// Three of the new ones are NOT strings — WindowNumber is a JSON number and the
// three review/repl flags are JSON booleans — which is why Encode writes typed
// values rather than another run of writeJSONPair. Emitting `"window_number":"0"`
// would be a one-character tell.
type CodexTurnMetadata struct {
	InstallationID string
	SessionID      string
	ThreadID       string
	AgentName      string
	TurnID         string
	WindowID       string
	WindowNumber   int
	// ContextWindowID is a UUIDv7 sharing thread_id's first four groups; see
	// CodexContextWindowIDFor.
	ContextWindowID string
	RequestKind     string

	// ParentThreadID and SubagentKind appear together, between request_kind
	// and thread_source, and ONLY on a subagent connection. Both empty means
	// neither key is emitted — a plain thread sends 15 keys, not 17 with two
	// empty strings.
	ParentThreadID string
	SubagentKind   string

	ThreadSource string
	Sandbox      string
	SandboxMode  string

	AutoReviewEnabled          bool
	NodeReplAutoReviewRequired bool
	NodeReplDisabled           bool
}

// NewCodexHandshakeMetadata builds the handshake ("prewarm") variant for one
// session. threadID defaults to sessionID, which is what a brand-new thread
// sends in every capture.
//
// The defaults describe the ordinary user thread of
// crack/codexv0.153.4/rows/10: workspace-write, auto-review on, neither
// node_repl flag set. The system-initiated and subagent variants (rows 11 and
// 12) differ, so a caller that knows it is neither should adjust the returned
// struct rather than expect this to guess.
func NewCodexHandshakeMetadata(installationID, sessionID, threadID string) CodexTurnMetadata {
	if threadID == "" {
		threadID = sessionID
	}
	return CodexTurnMetadata{
		InstallationID:  installationID,
		SessionID:       sessionID,
		ThreadID:        threadID,
		AgentName:       CodexDefaultAgentName,
		TurnID:          "",
		WindowID:        CodexWindowID(threadID),
		WindowNumber:    0,
		ContextWindowID: CodexContextWindowIDFor(threadID),
		RequestKind:     CodexRequestKindPrewarm,
		ThreadSource:    "user",
		Sandbox:         "seccomp",
		SandboxMode:     CodexSandboxModeWorkspaceWrite,

		AutoReviewEnabled:          true,
		NodeReplAutoReviewRequired: false,
		NodeReplDisabled:           false,
	}
}

// CodexWindowID renders the x-codex-window-id value: the id, a colon, and the
// window index. A proxy serves one logical window per thread, so the index is
// always 0 — matching every handshake in every capture.
//
// It is anchored on the THREAD id, not the session id. The two are equal on a
// fresh thread, which is why the earlier session-anchored derivation looked
// right; crack/codexv0.153.4/rows/12 separates them (session 01a06fa9-a7f8-…,
// thread 01a06fa9-a85e-…) and the window id there follows the thread.
func CodexWindowID(threadID string) string {
	if threadID == "" {
		return ""
	}
	return threadID + ":0"
}

// CodexContextWindowIDFor derives the `context_window_id` for a thread.
//
// It is not an independent id: in all three handshakes of
// crack/codexv0.153.4 it is a UUIDv7 sharing thread_id's first FOUR groups and
// differing only in the trailing 12 hex digits — the real client mints it from
// the same timestamp and random-high bits as the thread. Reproducing that
// relationship matters, because an unrelated UUID here is a structural
// mismatch a single comparison finds.
//
// The trailing group is derived from the thread id rather than randomised, so
// one thread keeps one context window across reconnects.
func CodexContextWindowIDFor(threadID string) string {
	if len(threadID) != 36 {
		return ""
	}
	sum := sha256.Sum256([]byte("codex-context-window\x00" + threadID))
	return threadID[:24] + hex.EncodeToString(sum[:6])
}

// Encode renders the metadata as the compact JSON string that goes in the
// header value.
//
// Key ORDER is part of the captured shape, so this writes the fields
// positionally instead of marshalling a map (which Go would sort). The order is
// verbatim from crack/codexv0.153.4/rows/13-x-codex-turn-metadata-decoded.json:
//
//	installation_id, session_id, thread_id, agent_name, turn_id, window_id,
//	window_number, context_window_id, request_kind,
//	[parent_thread_id, subagent_kind,]
//	thread_source, sandbox, sandbox_mode,
//	auto_review_enabled, node_repl_auto_review_required, node_repl_disabled
//
// turn_id is emitted even when empty — the genuine handshake sends
// `"turn_id":""`, not an absent key. The subagent pair is the opposite: absent
// entirely on a plain thread rather than present-and-empty.
//
// window_number is a NUMBER and the three trailing flags are BOOLEANS. Writing
// them through writeJSONPair would quote them, which is why they go through
// writeJSONRaw.
func (m CodexTurnMetadata) Encode() string {
	var sb strings.Builder
	sb.WriteByte('{')
	writeJSONPair(&sb, "installation_id", m.InstallationID, true)
	writeJSONPair(&sb, "session_id", m.SessionID, false)
	writeJSONPair(&sb, "thread_id", m.ThreadID, false)
	writeJSONPair(&sb, "agent_name", m.AgentName, false)
	writeJSONPair(&sb, "turn_id", m.TurnID, false)
	writeJSONPair(&sb, "window_id", m.WindowID, false)
	writeJSONRaw(&sb, "window_number", strconv.Itoa(m.WindowNumber))
	writeJSONPair(&sb, "context_window_id", m.ContextWindowID, false)
	writeJSONPair(&sb, "request_kind", m.RequestKind, false)
	// Emitted as a pair or not at all — a plain thread sends neither key.
	if m.ParentThreadID != "" || m.SubagentKind != "" {
		writeJSONPair(&sb, "parent_thread_id", m.ParentThreadID, false)
		writeJSONPair(&sb, "subagent_kind", m.SubagentKind, false)
	}
	writeJSONPair(&sb, "thread_source", m.ThreadSource, false)
	writeJSONPair(&sb, "sandbox", m.Sandbox, false)
	writeJSONPair(&sb, "sandbox_mode", m.SandboxMode, false)
	writeJSONRaw(&sb, "auto_review_enabled", strconv.FormatBool(m.AutoReviewEnabled))
	writeJSONRaw(&sb, "node_repl_auto_review_required", strconv.FormatBool(m.NodeReplAutoReviewRequired))
	writeJSONRaw(&sb, "node_repl_disabled", strconv.FormatBool(m.NodeReplDisabled))
	sb.WriteByte('}')
	return sb.String()
}

// writeJSONRaw writes a key whose value is already a JSON literal — a number or
// a boolean. The key is still marshalled; only the value is written verbatim,
// and every caller supplies it from strconv, never from user input.
func writeJSONRaw(sb *strings.Builder, key, literal string) {
	sb.WriteByte(',')
	k, _ := json.Marshal(key)
	sb.Write(k)
	sb.WriteByte(':')
	sb.WriteString(literal)
}

func writeJSONPair(sb *strings.Builder, key, value string, first bool) {
	if !first {
		sb.WriteByte(',')
	}
	k, _ := json.Marshal(key)
	v, _ := json.Marshal(value)
	sb.Write(k)
	sb.WriteByte(':')
	sb.Write(v)
}
