package codexws

import (
	"net/http"
	"time"

	"github.com/wjsoj/cc-core/mimicry"
)

// CodexOpenAIBetaWS / CodexOpenAIBetaWSV1 are the OpenAI-Beta markers real
// Codex sends on the WebSocket handshake to
// wss://chatgpt.com/backend-api/codex/responses. This is the ONLY place real
// Codex sets OpenAI-Beta — the HTTP path sends none (see the note on
// mimicry.ApplyCodexCLIHeaders). Both the 0.135.0 CLI capture and the 0.147.0
// Desktop capture show the same value, so it has outlived one release cycle.
const (
	CodexOpenAIBetaWS   = "responses_websockets=2026-02-06" // v2 (default)
	CodexOpenAIBetaWSV1 = "responses_websockets=2026-02-04" // v1
)

// handshakeHeaderOrder is the verbatim header order a genuine Codex client
// sends on the upgrade, from
// crack/codexapp0.147.0/rows/10-ws-handshake-codex-responses.json (identical
// in crack/codexv0.135.0/rows/01). Go sorts headers alphabetically when it
// writes a request, which produces an order no real client emits; orderedConn
// in dial.go replays the handshake in this order instead.
//
// sec-websocket-extensions is last because the genuine client appends it at
// the application layer rather than letting its WS library emit it.
var handshakeHeaderOrder = []string{
	"Host",
	"Connection",
	"Upgrade",
	"Sec-WebSocket-Version",
	"Sec-WebSocket-Key",
	"chatgpt-account-id",
	"authorization",
	"user-agent",
	"originator",
	"openai-beta",
	"version",
	"x-codex-beta-features",
	"x-client-request-id",
	"session-id",
	"thread-id",
	"x-codex-window-id",
	"x-codex-turn-metadata",
	"sec-websocket-extensions",
}

// HandshakeHeaderOrder returns a copy of the captured handshake header order.
func HandshakeHeaderOrder() []string {
	out := make([]string, len(handshakeHeaderOrder))
	copy(out, handshakeHeaderOrder)
	return out
}

// UpstreamHeaderOptions describes one upstream WebSocket handshake.
//
// SessionID/InstallationID identify the conversation and the "installation"
// this proxy presents for the account. Both should be stable for the life of a
// conversation and an account respectively — see
// mimicry.CodexSessionUUIDFor and mimicry.CodexInstallationIDFor. Leaving
// SessionID empty mints a fresh UUIDv7, which is correct for a one-shot
// connection but loses session stickiness across reconnects.
type UpstreamHeaderOptions struct {
	AccessToken string
	AccountID   string

	// Identity is the preferred way to supply the session/thread/installation
	// ids, because it is the SAME type mimicry.RewriteCodexClientFrame takes.
	// Passing one value to both is what guarantees the handshake headers and
	// the in-band client_metadata agree — and a genuine client always has them
	// agree, so a mismatch is a one-comparison tell.
	//
	// When nil, the loose fields below are used and the installation id falls
	// back to being derived from AccountID. That fallback is legacy: the frame
	// rewriter derives from the account KEY, so the two disagree unless the
	// caller passes Identity or sets InstallationID explicitly.
	Identity *mimicry.CodexFrameIdentity

	SessionID      string
	ThreadID       string // defaults to SessionID (a brand-new thread)
	InstallationID string
	BetaValue      string                      // defaults to CodexOpenAIBetaWS
	Profile        *mimicry.CodexClientProfile // nil => mimicry.DefaultCodexProfile()
}

// BuildUpstreamHeadersWithOptions returns the WebSocket-handshake headers for
// the ChatGPT Codex backend. The gorilla dialer owns Host / Upgrade /
// Connection / Sec-WebSocket-*, so those must NOT be set here.
//
// Header NAMES are written as non-canonical lowercase map keys because that is
// what the captures show on the wire; http.Header.Set would canonicalize them
// (notably "session-id" → "Session-Id"). Do not read these back with
// Header.Get.
//
// The five headers cc-core used to omit — x-codex-turn-metadata,
// x-codex-window-id, x-codex-beta-features, thread-id, x-client-request-id —
// are now sent. The old rationale was that x-codex-turn-metadata carried real
// workspace and git state a proxy cannot invent; that was true of the 0.135.0
// CLI capture and is no longer true of the 0.147.0 Desktop capture, whose
// handshake variant contains only ids we legitimately own. Omitting five
// headers every genuine client sends is now the larger tell.
//
// NOTE: x-codex-routing-hint is deliberately NOT set on the handshake. It used
// to be, on the strength of a reading of codex-rs's build_websocket_headers,
// but neither capture shows it on an upgrade — 0.135.0 and 0.147.0 both send
// 18 headers and the hint is not among them. It remains on the HTTP path
// (mimicry.ApplyCodexCLIHeaders), where the source reading is uncontradicted.
func BuildUpstreamHeadersWithOptions(opts UpstreamHeaderOptions) http.Header {
	beta := opts.BetaValue
	if beta == "" {
		beta = CodexOpenAIBetaWS
	}
	profile := mimicry.DefaultCodexProfile()
	if opts.Profile != nil {
		profile = *opts.Profile
	}
	sessionID := opts.SessionID
	threadID := opts.ThreadID
	installationID := opts.InstallationID
	if opts.Identity != nil {
		// One source of truth for the connection: whatever goes in the headers
		// here is exactly what the frame rewriter will put in client_metadata.
		if norm, err := opts.Identity.Normalized(); err == nil {
			sessionID, threadID, installationID = norm.SessionID, norm.ThreadID, norm.InstallationID
		}
	}
	if sessionID == "" {
		sessionID = mimicry.NewCodexSessionUUID()
	}
	if threadID == "" {
		threadID = sessionID
	}
	if installationID == "" && opts.AccountID != "" {
		// Never emit "installation_id":"" — a genuine client always has one.
		// Deriving it from the account keeps one upstream account presenting as
		// one installation, which is the real shape.
		//
		// Note this anchors on the ChatGPT account UUID while
		// mimicry.CodexFrameIdentity anchors on the account KEY, so the two
		// produce DIFFERENT installation ids. Pass Identity to avoid it.
		installationID = mimicry.CodexInstallationIDFor(opts.AccountID)
	}

	h := http.Header{}
	set := func(name, value string) { h[name] = []string{value} }

	if opts.AccountID != "" {
		set("chatgpt-account-id", opts.AccountID)
	}
	set("authorization", "Bearer "+opts.AccessToken)
	// User-Agent needs BOTH keys, and the nil one is not redundant.
	//
	// net/http writes User-Agent from a dedicated slot in Request.Write, and it
	// looks the key up by the EXACT string "User-Agent" — our lowercase key does
	// not match, so it falls back to the default and emits
	// "User-Agent: Go-http-client/1.1". Then writeSubset, which excludes only the
	// canonical spelling, writes our lowercase one as well: two User-Agent
	// headers, one of them announcing a Go program.
	//
	// Assigning a nil slice under the canonical key makes that slot resolve to
	// the empty string, which net/http declines to write, while writeSubset still
	// excludes it. The lowercase key then carries the only value on the wire.
	h["User-Agent"] = nil
	set("user-agent", profile.UserAgent)
	set("originator", profile.Originator)
	set("openai-beta", beta)
	set("version", profile.Version)
	if profile.BetaFeatures != "" {
		set("x-codex-beta-features", profile.BetaFeatures)
	}
	if profile.SendsTurnMetadata {
		// Both captures show x-client-request-id == session-id == thread-id on
		// a fresh thread's handshake; they are not three independent values.
		set("x-client-request-id", sessionID)
		set("session-id", sessionID)
		set("thread-id", threadID)
		set("x-codex-window-id", mimicry.CodexWindowID(sessionID))
		md := mimicry.NewCodexHandshakeMetadata(installationID, sessionID, threadID)
		set("x-codex-turn-metadata", md.Encode())
	}
	return h
}

// BuildUpstreamHeaders keeps the original positional signature — both forks
// call it that way — and now delegates to BuildUpstreamHeadersWithOptions.
//
// model and serviceTier are accepted and IGNORED. They only ever fed
// x-codex-routing-hint on the handshake, and no captured handshake carries
// that header (see the note on BuildUpstreamHeadersWithOptions). Callers that
// still pass them are not broken, they simply no longer have an effect here;
// the hint is still applied on the HTTP path by mimicry.ApplyCodexCLIHeaders.
//
// This form derives the installation id from accountID. That is enough to
// avoid emitting an empty one, but it anchors on the ChatGPT account UUID while
// mimicry.CodexFrameIdentity anchors on the account key — so a caller that also
// rewrites frames will produce two different installation ids for one account,
// which is worse than either alone. Prefer BuildUpstreamHeadersWithOptions with
// a shared Identity.
//
// An empty accountID leaves the installation id empty, which no genuine client
// ever sends; callers on that path must supply Identity.
func BuildUpstreamHeaders(accessToken, accountID, sessionID, betaValue, model, serviceTier string) http.Header {
	_, _ = model, serviceTier
	return BuildUpstreamHeadersWithOptions(UpstreamHeaderOptions{
		AccessToken: accessToken,
		AccountID:   accountID,
		SessionID:   sessionID,
		BetaValue:   betaValue,
	})
}

// SessionIDForAccount is a convenience wrapper minting the stable per-
// conversation UUIDv7 the handshake wants. anchor should combine the account
// and the downstream conversation; startedAt must be reproducible across every
// request of that conversation.
func SessionIDForAccount(anchor string, startedAt time.Time) string {
	return mimicry.CodexSessionUUIDFor(anchor, startedAt)
}
