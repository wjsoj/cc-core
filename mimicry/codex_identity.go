package mimicry

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
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
//     crack/codexapp0.147.0/ (whistle dump 2026-08-14, full login → WS turn).
//   - codex-tui — the Rust terminal client. Ground truth:
//     crack/codexv0.135.0/ (whistle dump 2026-05-30), version-bumped to
//     0.147.0 against the codex-rs source.
//
// Desktop is the default because it is the larger installed base. The cost of
// that choice is spelled out here so it is not forgotten: the captured Desktop
// build self-reports a PRE-RELEASE version (0.147.0-alpha.6.6) and a build
// number (26.803.81509). Pinning an alpha means the target drifts faster than
// a stable CLI tag does, and the version string is not free to invent — see
// CodexDesktopVersion.
const (
	// CodexDesktopVersion is the `version` header value and the version
	// segment of CodexDesktopUserAgent. The two must always agree.
	//
	// It is a pre-release string, verbatim from the capture. Do not "clean"
	// it to 0.147.0: the backend has been observed 404ing clients whose
	// version is below a floor (openai/codex#3901), which proves it parses
	// this field, and a version/UA mismatch is a one-header tell.
	CodexDesktopVersion = "0.147.0-alpha.6.6"

	// CodexDesktopBuild is the Desktop app build number that appears ONLY in
	// the User-Agent's trailing parenthetical and in the analytics-events
	// body as app_server_client.client_version. It is not a semver and is
	// not the same thing as CodexDesktopVersion (which is the codex-rs core
	// version, reported as runtime.codex_rs_version in the same body).
	CodexDesktopBuild = "26.803.81509"

	CodexDesktopOriginator = "Codex Desktop"

	// CodexDesktopUserAgent follows codex-rs's get_codex_user_agent():
	// "{originator}/{version} ({os_type} {os_version}; {arch}) {terminal_ua}{suffix}".
	// The OS/terminal segment is our synthetic Arch/Konsole identity, shared
	// with CodexCLIUserAgent; see the note on per-account variation below.
	CodexDesktopUserAgent = "Codex Desktop/" + CodexDesktopVersion +
		" (Arch Linux Rolling Release; x86_64) Konsole/260403 (Codex Desktop; " + CodexDesktopBuild + ")"

	// CodexDesktopBetaFeatures is the x-codex-beta-features value. This drifts
	// per release and is NOT derivable — 0.135.0 sent "terminal_resize_reflow",
	// 0.147.0 sends "remote_compaction_v2". Re-capture on every version bump.
	CodexDesktopBetaFeatures = "remote_compaction_v2"

	// CodexDesktopModelsClientVersion is the `client_version` query parameter
	// on GET /backend-api/codex/models. The capture shows Desktop sending the
	// BASE version here (0.147.0) while the `version` header carries the full
	// pre-release string — the mismatch is the client's own behaviour, not a
	// capture artifact, so it is reproduced rather than reconciled.
	CodexDesktopModelsClientVersion = "0.147.0"
)

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
func DefaultCodexProfile() CodexClientProfile { return codexDesktopClientProfile }

// NOTE ON PER-ACCOUNT VARIATION — deliberately NOT done here.
//
// Every account routed through the proxy currently advertises the same
// synthetic machine ("Arch Linux Rolling Release; x86_64" / "Konsole/260403"),
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

// CodexTurnMetadata is the x-codex-turn-metadata payload.
//
// The 0.135.0 CLI capture carried a `workspaces` map here holding the user's
// cwd, git remote URL, commit hash and dirty flag — genuinely unforgeable by a
// proxy, and the documented reason cc-core omitted this header entirely. The
// 0.147.0 Desktop capture no longer sends it (workspace state moved to a
// `workspace_kind` string on the turn variant only), leaving nothing in the
// handshake variant that a proxy cannot legitimately synthesize. That is why
// the header is emitted now.
type CodexTurnMetadata struct {
	InstallationID string
	SessionID      string
	ThreadID       string
	TurnID         string
	WindowID       string
	RequestKind    string
	ThreadSource   string
	Sandbox        string
}

// NewCodexHandshakeMetadata builds the handshake ("prewarm") variant for one
// session. threadID defaults to sessionID, which is what a brand-new thread
// sends in both captures.
func NewCodexHandshakeMetadata(installationID, sessionID, threadID string) CodexTurnMetadata {
	if threadID == "" {
		threadID = sessionID
	}
	return CodexTurnMetadata{
		InstallationID: installationID,
		SessionID:      sessionID,
		ThreadID:       threadID,
		TurnID:         "",
		WindowID:       CodexWindowID(sessionID),
		RequestKind:    CodexRequestKindPrewarm,
		ThreadSource:   "user",
		Sandbox:        "seccomp",
	}
}

// CodexWindowID renders the x-codex-window-id value: the session id, a colon,
// and the window index. A proxy serves one logical window per session, so the
// index is always 0 — matching every handshake in both captures.
func CodexWindowID(sessionID string) string {
	if sessionID == "" {
		return ""
	}
	return sessionID + ":0"
}

// Encode renders the metadata as the compact JSON string that goes in the
// header value.
//
// Key ORDER is part of the captured shape, so this writes the fields
// positionally instead of marshalling a map (which Go would sort). The order
// is verbatim from crack/codexapp0.147.0/rows/10-ws-handshake-codex-responses.json:
// installation_id, session_id, thread_id, turn_id, window_id, request_kind,
// thread_source, sandbox. turn_id is emitted even when empty — the genuine
// handshake sends `"turn_id":""`, not an absent key.
func (m CodexTurnMetadata) Encode() string {
	var sb strings.Builder
	sb.WriteByte('{')
	writeJSONPair(&sb, "installation_id", m.InstallationID, true)
	writeJSONPair(&sb, "session_id", m.SessionID, false)
	writeJSONPair(&sb, "thread_id", m.ThreadID, false)
	writeJSONPair(&sb, "turn_id", m.TurnID, false)
	writeJSONPair(&sb, "window_id", m.WindowID, false)
	writeJSONPair(&sb, "request_kind", m.RequestKind, false)
	writeJSONPair(&sb, "thread_source", m.ThreadSource, false)
	writeJSONPair(&sb, "sandbox", m.Sandbox, false)
	sb.WriteByte('}')
	return sb.String()
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
