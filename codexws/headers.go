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
//
// x-codex-routing-hint was added from crack/codexv0.153.4/rows/10-12, which
// carry it on every upgrade, immediately after x-codex-turn-metadata. It is
// emitted only when the caller supplies a model, so this slice can be one name
// longer than what actually goes on the wire; the order conn skips names it
// does not find, and the invariant is that whatever IS emitted appears in this
// relative order.
//
// Two further names appear in that position on a SUBAGENT upgrade, between
// x-codex-turn-metadata and x-codex-routing-hint: x-codex-parent-thread-id and
// x-openai-subagent (crack/codexv0.153.4/rows/12). They are deliberately absent
// here — cc-core never presents as a subagent, and a header that announces one
// without the matching thread topology behind it is worse than its absence.
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
	"x-codex-routing-hint",
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

	// Model is the upstream model slug for x-codex-routing-hint. Empty means
	// the header is omitted — which no genuine 0.153.4 client does, so callers
	// on the WebSocket path should always pass the model they are about to put
	// in the frame. Passing a DIFFERENT one than the body carries is worse
	// than passing none.
	Model string
	// ServiceTier is emitted only when set. Empty means the hint carries the
	// model alone — see the note where the header is written.
	ServiceTier string
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
// x-codex-routing-hint IS set on the handshake, when a Model is supplied. It
// was removed once because neither the 0.135.0 nor the 0.147.0 capture carried
// it on an upgrade; crack/codexv0.153.4/rows/10-12 carry it on all three, right
// after x-codex-turn-metadata, in the same "model={slug};tier={tier}" form the
// HTTP path uses. The older captures were older, not contradictory — do not
// re-derive its absence from them.
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
	if opts.Model != "" {
		// ServiceTier is passed through, NOT defaulted to priority.
		//
		// Every handshake in crack/codexv0.153.4 carries tier=priority, so
		// defaulting to it looks like the better fingerprint. It is the worse
		// bill: pricing.CostWithOptions charges the Fast multiplier off the
		// tier the request actually asked for, so a hint that claims priority
		// on a request we bill at standard rates asks the backend for a paid
		// upgrade nobody is paying for. The captured client sent priority
		// because that account genuinely requested it.
		//
		// Callers that want the captured shape pass ServiceTier explicitly.
		set(mimicry.CodexRoutingHintHeader, mimicry.CodexRoutingHint(opts.Model, opts.ServiceTier))
	}
	return h
}

// BuildUpstreamHeaders keeps the original positional signature — both forks
// call it that way — and now delegates to BuildUpstreamHeadersWithOptions.
//
// model and serviceTier feed x-codex-routing-hint again. They were accepted and
// ignored for as long as the handshake was believed not to carry that header;
// crack/codexv0.153.4 shows it does, so they are forwarded once more. A caller
// still passing "" for model gets no hint — which no genuine client does.
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
	return BuildUpstreamHeadersWithOptions(UpstreamHeaderOptions{
		AccessToken: accessToken,
		AccountID:   accountID,
		SessionID:   sessionID,
		BetaValue:   betaValue,
		Model:       model,
		ServiceTier: serviceTier,
	})
}

// SessionIDForAccount is a convenience wrapper minting the stable per-
// conversation UUIDv7 the handshake wants. anchor should combine the account
// and the downstream conversation; startedAt must be reproducible across every
// request of that conversation.
func SessionIDForAccount(anchor string, startedAt time.Time) string {
	return mimicry.CodexSessionUUIDFor(anchor, startedAt)
}
