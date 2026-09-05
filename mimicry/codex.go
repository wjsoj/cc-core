package mimicry

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/wjsoj/cc-core/servicetier"
)

// The codex-tui (Rust terminal client) fingerprint, pinned to 0.147.0.
//
// This is NO LONGER the default identity. cc-core presents Codex Desktop —
// see mimicry.DefaultCodexProfile and the constants in codex_identity.go,
// captured live at 0.147.0-alpha.6.6 in crack/codexapp0.147.0/. The constants
// below remain the CLI profile, selectable via CodexTUIClientProfile, and they
// still anchor everything the two clients share.
//
// The identity template (Originator / UA shape / Version header) was verified
// against a live ChatGPT Pro `codex` session capture at 0.135.0 — see
// crack/codexv0.135.0/SPEC.md (whistle dump 2026-05-30).
//
// 0.147.0 (released 2026-08-07) was verified against the UPSTREAM SOURCE rather
// than a new capture — codex-rs is open source, and for header construction the
// source is stronger evidence than a dump, since it is the thing that generates
// the dump. Two findings from codex-rs/login/src/auth/default_client.rs and
// codex-rs/core/src/client.rs at that tag drive the constants below.
//
// The UA template is unchanged: get_codex_user_agent() builds
// "{originator}/{version} ({os_type} {os_version}; {arch}) {terminal_ua}{suffix}",
// which is exactly the 0.135.0 shape, so only the version segments move. The
// OS/terminal segment stays our synthetic Arch/Konsole identity.
//
// `codex-tui` remains a live originator at 0.147.0 (it is still in the known-
// originator set in codex-rs/otel/src/metrics/tags.rs alongside the library
// default `codex_cli_rs`), and it is what our own capture shows the TUI send,
// so it is deliberately NOT changed to the library default.
//
// Transport note: real Codex streams a turn over a WebSocket
// (OpenAI-Beta: responses_websockets=2026-02-06, wss://chatgpt.com/backend-api/
// codex/responses) — the 0.147.0 Desktop capture contains no HTTP /responses
// call at all. We also forward over the HTTP POST /backend-api/codex/responses
// path, which the backend still accepts and which an HTTP-API proxy needs, and
// we mimic the *identity* (Originator / User-Agent / Version) over it.
//
// The WS handshake headers this file used to refuse to synthesize
// (x-codex-turn-metadata, x-codex-window-id, x-codex-beta-features, thread-id,
// x-client-request-id) ARE now sent — but only on the WebSocket path, by
// codexws.BuildUpstreamHeadersWithOptions. The old objection was that
// x-codex-turn-metadata carried real workspace and git state; that was true of
// the 0.135.0 capture and is no longer true at 0.147.0, whose handshake variant
// holds only ids we legitimately own. They are still NOT set on the HTTP path,
// where no capture shows them.
//
// The CLI constants below are pinned to a LIVE capture again as of 0.153.4
// (crack/codexv0.153.4/, 2026-09-05) rather than to a source reading — 0.147.0
// was bumped from the codex-rs tag because no CLI capture existed at the time.
// Note the User-Agent's terminal segment moved too (Konsole/260401 →
// Konsole/260800): a version bump is never a one-line edit here.
//
// This version floor is now load-bearing rather than cosmetic. The 0.153.4
// model catalog gives gpt-6-astra minimal_client_version "0.153.0", so any
// profile self-reporting below that cannot be routed to the current flagship —
// which is why DefaultCodexProfile returns the CLI profile and not Desktop
// (see mimicry/codex_identity.go).
//
// Bumping the version target requires re-verifying against real Codex traffic
// or the codex-rs source at that tag; CodexCLIVersion must match the version
// baked into CodexCLIUserAgent.
const (
	CodexCLIVersion   = "0.153.4"
	CodexCLIUserAgent = "codex-tui/0.153.4 (Arch Linux Rolling Release; x86_64) Konsole/260800 (codex-tui; 0.153.4)"
	CodexOriginator   = "codex-tui"

	// CodexCLIBetaFeatures is the x-codex-beta-features value the TUI sends.
	// Re-verified at 0.153.4 against every handshake in
	// crack/codexv0.153.4/rows/10-12: the TUI now sends the same value the
	// Desktop client sent at 0.147.0, i.e. the two profiles' beta-features
	// have CONVERGED. It was "terminal_resize_reflow" at 0.135.0, so this
	// header does drift between releases and is not derivable — re-capture it
	// on every bump rather than carrying it forward.
	CodexCLIBetaFeatures = "remote_compaction_v2"

	// CodexModelsOriginator / CodexModelsUserAgent are the identity the CLI
	// presents on GET /backend-api/codex/models specifically, and they are NOT
	// the handshake's.
	//
	// crack/codexv0.153.4/rows/01 shows that one request going out as
	// originator `codex_cli_rs` — the codex-rs library default — with a
	// User-Agent that DROPS the trailing "(codex-tui; <ver>)" parenthetical
	// the WebSocket upgrade carries. Same process, same second, different
	// component: the model fetch goes through the library's own HTTP client
	// while the turn goes through the TUI's. Pairing the TUI originator with
	// this endpoint, or this originator with the TUI's full User-Agent, is a
	// combination no genuine client emits.
	CodexModelsOriginator = "codex_cli_rs"

	// CodexSessionIDHeader is the session id header name. It is spelled with a
	// HYPHEN. cc-core previously sent "Session_id" — an underscore, which Go's
	// header canonicalization preserves verbatim — while both captures
	// (crack/codexv0.135.0/rows/01, crack/codexapp0.147.0/rows/10) show real
	// Codex sending "session-id". A single header name is enough to separate
	// us from every genuine client, so this must be written through a
	// non-canonical map assignment (see setCodexHeader) rather than
	// Header.Set, which would re-canonicalize it to "Session-Id".
	CodexSessionIDHeader = "session-id"

	// CodexRoutingHintHeader carries the model (and optionally the effective
	// service tier) the ChatGPT backend should route to. It is
	// X_CODEX_ROUTING_HINT_HEADER in codex-rs/core/src/client.rs, gated on
	// `auth.uses_codex_backend()`, i.e. exactly the subscription-backed traffic
	// we forward. Omitting it is not neutral: the backend resolves some models
	// per-originator/per-hint, which is how third-party clients end up with
	// "Model not found gpt-5.6-luna-…" while the official CLI succeeds on the
	// same account (openai/codex#31967).
	//
	// SCOPE — both paths. This header was removed from the WebSocket handshake
	// once, because neither the 0.135.0 CLI capture nor the 0.147.0 Desktop
	// capture carried it (both sent 18 headers and the hint was not among
	// them). The 0.153.4 CLI capture falsifies that: all three upgrades in
	// crack/codexv0.153.4/rows/10-12 carry it, positioned immediately after
	// x-codex-turn-metadata and before sec-websocket-extensions, in the same
	// "model={slug};tier={tier}" format the HTTP path uses. It is sent on both
	// paths again. Do not re-derive its absence from the older captures — they
	// are older, not contradictory.
	CodexRoutingHintHeader = "x-codex-routing-hint"
)

// CodexServiceTier* are the only tier values that belong in a routing hint.
//
// Upstream formats the hint as "model={model};tier={tier}" whenever its own
// resolved service_tier is Some. Its service_tier comes from Codex's own
// validated config; ours comes off an arbitrary client request body, so we
// restrict the hint to the two tiers Codex actually selects rather than
// forwarding whatever a caller typed into a header. "default" is excluded on
// purpose — Codex treats it as a standard-routing sentinel, not a tier to send.
const (
	CodexServiceTierPriority = "priority"
	CodexServiceTierFlex     = "flex"
)

// CodexRoutingHint renders the x-codex-routing-hint value for a request, or ""
// when there is nothing safe to advertise (no model). serviceTier may be empty.
//
// The model is emitted as-is because the backend keys on the exact upstream
// slug; a caller must therefore pass the model it actually puts in the request
// body, after any model-map rewrite, or the hint and the body will disagree.
func CodexRoutingHint(model, serviceTier string) string {
	model = strings.TrimSpace(model)
	// A header value must be printable ASCII with no CR/LF. Model names are
	// slugs, so anything else is either a caller bug or an injection attempt;
	// drop the hint rather than emit a malformed header.
	if model == "" || !validHeaderValue(model) {
		return ""
	}
	hint := "model=" + model
	switch servicetier.Normalize(serviceTier) {
	case CodexServiceTierPriority:
		hint += ";tier=" + CodexServiceTierPriority
	case CodexServiceTierFlex:
		hint += ";tier=" + CodexServiceTierFlex
	}
	return hint
}

// CodexModelAndTier reads the model and service_tier out of a Codex request
// body. Callers pass it the body they are ABOUT TO SEND — after sanitization
// and any model-map rewrite — so the routing hint and the body can never
// disagree about which model this request is for. Missing fields come back
// empty, which CodexRoutingHint handles by omitting the hint or the tier.
func CodexModelAndTier(body []byte) (model, serviceTier string) {
	var b struct {
		Model       string `json:"model"`
		ServiceTier string `json:"service_tier"`
	}
	if json.Unmarshal(body, &b) != nil {
		return "", ""
	}
	return b.Model, servicetier.Normalize(b.ServiceTier)
}

// validHeaderValue reports whether s is safe to use as an HTTP header value:
// printable ASCII (plus horizontal tab), no control characters, no CR/LF.
func validHeaderValue(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c != '\t' && (c < 0x20 || c > 0x7e) {
			return false
		}
	}
	return true
}

// ApplyCodexCLIHeaders rewrites req to look like the Codex CLI talking to the
// ChatGPT subscription backend over the HTTP POST /codex/responses{,/compact}
// path. The caller supplies the OAuth access token and the chatgpt_account_id
// claim (from the id_token). isCompact selects the /responses/compact variant
// (plain JSON) vs the streaming /responses variant (SSE).
//
// Always overwrites Authorization and User-Agent: forwarding a client's UA
// (e.g. "curl/8.x") makes Cloudflare's edge 403 the request before it reaches
// the OpenAI backend, and the credential token must win over anything the
// downstream client sent.
//
// Accept-Encoding is forced to "identity" so SSE streams and 4xx error bodies
// stay readable end-to-end (a transport necessity, not part of the captured
// fingerprint).
//
// model is the model name going into the request body (post model-map rewrite)
// and serviceTier the request's service_tier, if any; together they produce the
// x-codex-routing-hint real Codex sends. Passing an empty model simply omits the
// hint — the header is never emitted with a stale or guessed value.
//
// NOTE: no OpenAI-Beta header is set here, and that is deliberate. Real Codex
// sets OpenAI-Beta *only* on the WebSocket handshake
// (responses_websockets=…, see codexws.BuildUpstreamHeaders); at 0.147.0 the
// string "responses=experimental" does not appear anywhere in codex-rs, so the
// legacy HTTP beta we used to send was a value no genuine client emits — a pure
// third-party tell. Any OpenAI-Beta the downstream client sent is left alone.
//
// The advertised identity is DefaultCodexProfile() — Codex Desktop. Use
// ApplyCodexHeadersWithProfile to pick a different one.
//
// It mints a FRESH session id per request. That is correct only for a caller
// with no conversation to speak of; anything serving multi-turn traffic must
// pass a stable one through ApplyCodexHeadersWithSession — see the session-id
// note there for what a per-request id costs.
func ApplyCodexCLIHeaders(req *http.Request, accessToken, accountID string, isCompact bool, model, serviceTier string) {
	ApplyCodexHeadersWithProfile(req, DefaultCodexProfile(), accessToken, accountID, isCompact, model, serviceTier)
}

// ApplyCodexHeadersWithProfile is ApplyCodexCLIHeaders with an explicit client
// identity. The profile's Originator / UserAgent / Version are written as one
// unit and must never be mixed with another profile's — see CodexClientProfile.
//
// Like ApplyCodexCLIHeaders, this mints a fresh session id per request.
func ApplyCodexHeadersWithProfile(req *http.Request, p CodexClientProfile, accessToken, accountID string, isCompact bool, model, serviceTier string) {
	ApplyCodexHeadersWithSession(req, p, accessToken, accountID, isCompact, model, serviceTier, "")
}

// ApplyCodexHeadersWithSession is ApplyCodexHeadersWithProfile with the
// conversation's upstream session id supplied by the caller.
//
// # Why the session id must be stable
//
// `session-id` is not decoration on this path: the backend uses it to place a
// conversation in the upstream prompt cache, exactly as it does for the frame's
// prompt_cache_key on the WebSocket path (see codexws.SessionRegistry, where a
// stable key bought 22272 of 22735 input tokens in the captured turn). A fresh
// id per request tells the backend every turn is a brand-new conversation, so
// each one re-uploads a context the account already has cached.
//
// This was not always visible. cc-core sent the id under the misspelled header
// name `Session_id` for two capture generations; the backend ignored a name no
// client sends, so the per-request value was harmless. Correcting the spelling
// to `session-id` made the backend start reading it — and production Codex
// cache hit rate fell from ~87% to ~45% over the following days, with a third
// of all turns arriving with cache_read == 0 while carrying >10k of context.
// Passing a per-request id here is therefore a REGRESSION, not a default.
//
// sessionID must be a UUIDv7 the caller can reproduce for every request of the
// same conversation — derive it with CodexSessionUUIDFor, or let a
// codexws.SessionRegistry own the (anchor, startedAt) bookkeeping. Empty falls
// back to a freshly minted v7, which costs stickiness but never ships a shape
// the backend rejects.
func ApplyCodexHeadersWithSession(req *http.Request, p CodexClientProfile, accessToken, accountID string, isCompact bool, model, serviceTier, sessionID string) {
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	if isCompact {
		req.Header.Set("Accept", "application/json")
	} else {
		req.Header.Set("Accept", "text/event-stream")
	}
	// Delete before conditionally setting so a retried/rebuilt request can
	// never carry a routing hint for the previous attempt's model.
	req.Header.Del(CodexRoutingHintHeader)
	if hint := CodexRoutingHint(model, serviceTier); hint != "" {
		req.Header.Set(CodexRoutingHintHeader, hint)
	}
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Connection", "Keep-Alive")
	// Drop the historical misspelling before writing the correct one, so a
	// rebuilt/retried request can never carry both.
	req.Header.Del("Session_id")
	// Version 7, not v4: every session id in both Codex captures is a v7 and
	// the version nibble is visible on the wire. NewRequestUUID (v4) stood here
	// until the header name was corrected, at which point the backend began
	// reading a field that was both unstable and the wrong UUID version.
	if sessionID == "" {
		sessionID = NewCodexSessionUUID()
	}
	setCodexHeader(req.Header, CodexSessionIDHeader, sessionID)
	req.Header.Set("Version", p.Version)
	req.Header.Set("Originator", p.Originator)
	req.Header.Set("User-Agent", p.UserAgent)
	if accountID != "" {
		req.Header.Set("Chatgpt-Account-Id", accountID)
	}
}

// setCodexHeader writes a header under its EXACT captured spelling.
//
// http.Header.Set canonicalizes ("session-id" → "Session-Id"), and for HTTP/1.1
// Go writes the map key verbatim, so Set would put a name on the wire that no
// genuine Codex client sends. Assigning the map key directly is the documented
// escape hatch. Over HTTP/2 this is moot (h2 lowercases every name), but the
// ChatGPT backend is reached over HTTP/1.1 for WebSockets and the value must be
// right on both paths.
//
// Callers must read these back with the same literal key, never Header.Get.
func setCodexHeader(h http.Header, name, value string) {
	h[name] = []string{value}
}

// CodexUsageUserAgent is the User-Agent the Codex CLI sends on its
// GET /backend-api/wham/usage probe — the same codex-tui UA as the request
// path, NOT the web portal's Chrome UA. The CLI's usage call carries only
// Authorization + Chatgpt-Account-Id + this UA (no oai-client-* headers).
const CodexUsageUserAgent = CodexCLIUserAgent

// CodexModelsUserAgent is the User-Agent for GET /backend-api/codex/models.
//
// Derived from CodexCLIUserAgent rather than written out, so a version bump
// cannot move one and leave the other behind — the two differ only by the
// trailing "(codex-tui; <version>)" parenthetical, which the models fetch
// omits. See CodexModelsOriginator for why the two differ at all.
var CodexModelsUserAgent = strings.TrimSuffix(
	CodexCLIUserAgent, " ("+CodexOriginator+"; "+CodexCLIVersion+")")
