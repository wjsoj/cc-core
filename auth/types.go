package auth

import (
	"fmt"
	"math/rand/v2"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// NormalizeGroup canonicalizes a group identifier. Empty string and the
// literal "public" (case-insensitive) both mean the public/default pool.
// The reserved built-in "new" group is always lowercased so any casing
// ("NEW", "New") collapses to the same tier. All other values are trimmed
// and preserved case-sensitively.
func NormalizeGroup(s string) string {
	g := strings.TrimSpace(s)
	if g == "" {
		return ""
	}
	if strings.EqualFold(g, "public") {
		return ""
	}
	if strings.EqualFold(g, "new") {
		return "new"
	}
	return g
}

// Kind distinguishes OAuth credentials (concurrency-limited) from API keys
// (unlimited; used as fallback).
type Kind int

const (
	KindOAuth Kind = iota
	KindAPIKey
)

// Auth is a single upstream credential.
// For OAuth: AccessToken/RefreshToken/ExpiresAt are managed by the refresher.
// For APIKey: only AccessToken (the literal key) is used.
type Auth struct {
	mu        sync.RWMutex
	refreshMu sync.Mutex // serializes OAuth refresh calls; prevents concurrent burns of a rotating refresh_token

	ID       string // stable identifier (OAuth: file basename; APIKey: "apikey:<label-or-prefix>")
	Kind     Kind
	Provider string // "anthropic" | "openai" — drives routing + per-provider token endpoints
	Label    string
	Email    string

	// Credentials
	AccessToken  string
	RefreshToken string // OAuth only
	ExpiresAt    time.Time

	// Codex (OpenAI) OAuth specifics. IDToken carries the ChatGPT account
	// claims; AccountID + PlanType drive upstream request headers and
	// per-plan model visibility. Unused for Anthropic auths.
	IDToken   string
	AccountID string
	PlanType  string

	// Anthropic OAuth account/org UUIDs returned by the token-exchange
	// response. Used by the body mimicry layer to populate
	// metadata.user_id.account_uuid so requests look identical to the real
	// Claude Code CLI's. Empty when not yet captured (legacy credentials
	// saved before this field existed); body mimicry then falls back to
	// deriving a stable per-account anchor from Email or ID.
	AccountUUID      string
	OrganizationUUID string

	// Subscription / rate-limit tier captured from the
	// /api/claude_cli/bootstrap response (oauth_account.organization_type
	// and organization_rate_limit_tier). Used by the GrowthBook sidecar
	// (buildGrowthBookBody) to send authentic per-account experiment
	// attributes instead of the previous hardcoded "max" defaults — a
	// hardcoded value that didn't match the real subscription is itself
	// a fingerprint signal. Empty when not yet captured (the very first
	// bootstrap pass falls back to "max" / "default_claude_max_20x");
	// persisted to the credential file once known so subsequent process
	// starts have it without waiting for another bootstrap.
	OrganizationType          string // e.g. "claude_max", "claude_pro", "claude_team"
	OrganizationRateLimitTier string // e.g. "default_claude_max_20x"

	// HostProfile is the per-account synthetic Linux "client machine"
	// (distro/kernel/terminal/shell) reported in sidecar telemetry, so that
	// distinct OAuth accounts don't all advertise one identical host. Zero
	// value = not yet pinned; HostProfileOrDefault() derives one on the fly
	// and EnsureHostProfile() persists it to the credential file on first
	// touch (see hostprofile.go). Append-only field — old credential files
	// without it keep loading.
	HostProfile HostProfile

	// Routing
	ProxyURL      string // per-credential upstream proxy (empty = direct/use default)
	BaseURL       string // per-credential upstream base URL override (API-key only; empty = config.AnthropicBaseURL)
	MaxConcurrent int    // OAuth: max client sessions; 0 = unlimited. APIKey: ignored.

	// Group gates which client tokens may be served by this credential.
	// Empty string = public pool (usable by anyone). Any other value means
	// the credential is restricted to client tokens whose Group matches, with
	// public acting as a fallback when the group's credentials are exhausted.
	Group string

	// ModelMap (API-key only) is a pure REWRITE table from client-facing
	// model names to upstream model names. It does NOT filter / allow-list:
	// the credential still accepts every model. For a model listed with a
	// non-empty value, the request body's "model" field is rewritten to that
	// value before being sent upstream (e.g. a relay that registered haiku as
	// "claude-haiku-4-5" but receives the dated "claude-haiku-4-5-20251001").
	// Any model not in the map — or mapped to "" — passes through unchanged.
	// Nil/empty map = no rewriting. OAuth credentials ignore this field.
	ModelMap map[string]string

	// StripThinking, when true, makes consumers proactively sanitize prior
	// `thinking` block signatures from messages[] before every forward on this
	// credential. Set + persisted automatically the first time an upstream
	// thinking-signature-error recovery succeeds: relays that pool/rotate
	// backend accounts per request (e.g. an aws2-style vllmproxy) reject every
	// echoed signature, so without proactive stripping each request fails once
	// and recovers via replay. Persisted to the credential file so the decision
	// survives restarts. Append-only field; old files default to false.
	StripThinking bool

	// Order is the operator-assigned selection priority for API-key
	// credentials: lower comes first, so the pool keeps p.apikeys sorted by
	// Order and Acquire returns the first viable (highest-priority) key. Ties
	// fall back to load order via a stable sort. Default 0 = unranked (sorts
	// before any positive Order, after any negative). Ignored for OAuth, which
	// load-balances by rolling usage instead. Append-only field — old
	// credential files without it default to 0.
	Order int

	// PriceMultiplier overrides billing for API-key credentials: when > 0, a
	// request served by this key is charged official_price × PriceMultiplier,
	// bypassing the client's pricing-group multiplier entirely. This models
	// upstream relay keys bought at near-official cost, which must NOT inherit
	// the cheap OAuth-subscription discount. 0 = unset = fall back to the
	// pricing-group multiplier (legacy behaviour). Ignored for OAuth. Append-
	// only field — old credential files without it default to 0.
	PriceMultiplier float64
	// RelayPeer marks an API-key credential as pointing at a cooperating proxy
	// we also run, rather than at a vendor or a third-party relay. Requests
	// forwarded on it carry cc-core/relay headers naming the DOWNSTREAM caller,
	// so the peer can spread them across its own credentials instead of pinning
	// every user behind this proxy onto one. Off by default and meaningless for
	// OAuth: to any other upstream the headers are noise that leaks topology.
	// Append-only field — old credential files default to false.
	RelayPeer bool

	// Source file for OAuth and file-backed APIKey credentials.
	FilePath string

	// Health
	Disabled        bool
	QuotaExceededAt time.Time // zero = not flagged
	QuotaResetAt    time.Time // when to try again (may be zero = manual reset)

	// ModelRateLimits scopes a cooldown to a subset of models instead of the
	// whole credential. Key is a family scope (e.g. "anthropic:fable"), value
	// is when that scope's cooldown expires. Unlike QuotaExceededAt this NEVER
	// makes the credential globally unschedulable — only requests whose model
	// maps to a live scope are skipped, so the account keeps serving every
	// other model. Used for Anthropic's per-model overage windows (fable's
	// 7d_oi bucket is an independent ~half-of-weekly allotment that rejects on
	// its own while 5h/7d stay allowed). nil/empty = no scoped limits. Append-
	// only field: old credential files without it decode as nil.
	ModelRateLimits     map[string]time.Time
	LastFailure         time.Time
	LastFailureReason   string
	LastSuccess         time.Time // set on every <400 upstream response
	ConsecutiveFailures int       // reset on success; drives auto hard-fail
	Consecutive429s     int       // reset on success; drives 429-specific hard-fail (suspected stealth ban)
	Consecutive401s     int       // reset on success; drives 401-specific hard-fail (only after a token refresh keeps succeeding — see MarkAuthRejection)
	HardFailureAt       time.Time // sticky unhealthy; cleared only by ClearFailure
	HardFailureReason   string

	// Circuit breaker for API-key channels. Unlike HardFailureAt these are
	// self-healing: QuarantineUntil is a deadline, never a sticky flag, so a
	// channel is only ever *paused*, never retired. QuarantineStrikes counts
	// consecutive quarantine rounds and drives the exponential backoff.
	// See apiKeyQuarantineThreshold. Cleared by MarkSuccess / ClearFailure.
	QuarantineUntil   time.Time
	QuarantineStrikes int

	// Client-initiated cancellations (ctrl-C, connection close). Tracked
	// for admin visibility only — does NOT affect IsHealthy / cooldown /
	// consecutive-failure counters, since the credential itself is fine.
	LastClientCancel       time.Time
	LastClientCancelReason string

	// Codex rate-limit snapshot. ChatGPT's Codex backend returns
	// x-codex-* headers on every response describing the caller's
	// rolling primary (5h) and secondary (weekly) quota windows.
	// We capture them verbatim so the admin UI can render whatever
	// fields the backend currently exposes without code changes per
	// header addition. CodexRateLimitsAt is zero = never captured.
	CodexRateLimits   map[string]string
	CodexRateLimitsAt time.Time

	// CodexUsage is the latest snapshot from the chatgpt.com web portal's
	// wham/usage endpoint (FetchCodexUsage). Unlike CodexRateLimits — which
	// is populated reactively from /responses response headers — CodexUsage
	// can be refreshed actively, independent of proxy traffic, so the admin
	// view stays current even when nothing is flowing through. Nil = never
	// fetched. CodexUsageAt mirrors CodexUsage.Updated.
	CodexUsage   *CodexUsageInfo
	CodexUsageAt time.Time

	// CodexSubscription is the latest billing view from the chatgpt.com
	// portal's subscriptions + accounts/check endpoints
	// (FetchCodexSubscription). Where CodexUsage answers "how much quota is
	// left", this answers "what plan was bought, when the term started, and
	// whether it renews". Nil = never fetched; CodexSubscriptionAt mirrors
	// CodexSubscription.Updated.
	CodexSubscription   *CodexSubscriptionInfo
	CodexSubscriptionAt time.Time
}

// healthGrace is how long after an isolated failure we still treat the
// credential as healthy (optimistic recovery). Hard failures and repeated
// failures bypass this.
const healthGrace = 2 * time.Minute

// degradedProbeAfter is how long a repeatedly-failing (but not hard-failed)
// credential stays out of rotation before the pool lets one request through to
// re-probe it.
//
// Without this, ConsecutiveFailures >= 2 is a *terminal* state: the credential
// reads unhealthy, so Acquire never picks it, so no success can ever arrive to
// reset the counter. A brief upstream flap that lands two failures on every
// credential of a provider takes the entire pool dark until an operator clears
// the failures by hand. The probe closes that loop — it either succeeds
// (MarkSuccess resets the counter and the credential is fully back) or fails
// (LastFailure moves forward, re-quarantining it for another interval, and the
// counter climbs toward hardFailureThreshold, which is the intended terminal
// state for a genuinely dead credential).
const degradedProbeAfter = 5 * time.Minute

// hardFailureThreshold is the number of consecutive non-cooldown failures
// after which a credential is marked hard-unhealthy and must be manually
// reset from the admin panel.
const hardFailureThreshold = 5

// rateLimit429HardFailureThreshold is the number of consecutive 429
// responses after which a credential is presumed stealth-banned (Anthropic
// occasionally hides bans behind perpetual 429s rather than a clean 401/403)
// and marked hard-unhealthy. Counter resets on any successful response.
const rateLimit429HardFailureThreshold = 15

// apiKeyQuarantineThreshold is the number of consecutive upstream-side
// failures after which an API-key channel is paused (its circuit opens).
//
// API-key credentials are operator-managed BYOK / relay channels and are
// deliberately exempt from every *sticky* auto-retirement path (see
// MarkFailure, MarkHardFailure): a working channel must never end up pinned
// offline waiting for a human. That exemption, on its own, left the opposite
// failure mode — a channel that is comprehensively broken (revoked key, dead
// relay) stayed in rotation forever, so every single request paid a full
// upstream round-trip to rediscover the same failure before failing over.
//
// The quarantine closes that gap without reintroducing the sticky behaviour:
// it is a *deadline*, so the channel always returns by itself. Three strikes
// rather than one deliberately tolerates the ordinary weather of a shared
// relay (a lone 502, a burst of throttling) before pausing anything.
const apiKeyQuarantineThreshold = 3

// apiKey429QuarantineThreshold is the number of consecutive 429s, with no
// intervening success and with the upstream declining to say when to come
// back, after which an API-key channel is paused.
//
// 429 gets its own threshold — and its own counter, Consecutive429s — instead
// of sharing ConsecutiveFailures with 5xx, because the two signals mean
// opposite things about the channel. A 502 says the relay is broken; a 429
// says it is working and busy. Feeding both into one counter would put a
// merely-throttled channel on the same backoff ladder as a dead one, which is
// the fastest way to turn a burst of load into a self-inflicted outage.
//
// 6 rather than 3: throttling is the ordinary weather of a shared relay and
// costs us only latency, so we tolerate twice as much of it as we do outright
// failure. But it is nothing like OAuth's 15 — that threshold guards a
// *sticky* retirement of a scarce paid subscription, where a false positive
// costs a manual re-login. Here the penalty is a 10-second pause that expires
// on its own, so the cost of being wrong is roughly nil and there is no reason
// to keep paying full round-trips to a channel that has refused six requests
// in a row.
//
// The "with no Retry-After" qualifier is load-bearing: see
// MarkRateLimitedRetryAfter for why an upstream that tells us when to return
// is trusted rather than distrusted.
const apiKey429QuarantineThreshold = 6

// apiKey401QuarantineThreshold is the number of consecutive 401s after which
// an API-key channel is paused.
//
// Deliberately far below OAuth's auth401HardFailureThreshold (8), and the
// asymmetry is not a matter of taste. That threshold is generous for exactly
// one reason: OAuth access tokens rotate, and Anthropic invalidates the old
// token the instant a refresh completes, so every proactive refresh on a busy
// account orphans some in-flight requests into a 401 that means nothing. An
// API key does not rotate. There is no window in which a valid key produces a
// 401. A 401 on an API-key channel means the key is wrong, revoked, or the
// relay is misconfigured — all of which are true of the *next* request too.
//
// 2 rather than 1 buys one round-trip of corroboration against a relay that
// mistranslates an unrelated backend error into 401, which is common enough in
// the wild to be worth a second opinion. Beyond that, waiting costs a
// guaranteed-doomed round-trip per request. (An explicit credential rejection
// routed through MarkHardFailure still trips on the first strike; that path
// carries upstream's own verdict, not our inference from a status code.)
const apiKey401QuarantineThreshold = 2

// apiKeyQuarantineBackoff returns how long an API-key channel stays paused
// after its n-th consecutive quarantine round.
//
// The ceiling matters more than the growth curve: with a single API-key
// channel configured, the backoff is also the maximum time the deployment is
// unable to serve that model at all, so it is capped well short of the point
// where a recovered upstream would sit unused. The first step is short
// because the common case — a relay restarting, a backend rotating — clears
// in seconds.
func apiKeyQuarantineBackoff(n int) time.Duration {
	switch {
	case n <= 1:
		return 10 * time.Second
	case n == 2:
		return 30 * time.Second
	case n == 3:
		return 2 * time.Minute
	case n == 4:
		return 5 * time.Minute
	default:
		return 15 * time.Minute
	}
}

// auth401HardFailureThreshold is the number of consecutive definitive 401s
// (upstream authentication_error) — each with the credential's refresh token
// STILL succeeding — after which the account is presumed genuinely revoked
// (entitlement stripped without invalidating the refresh token) and marked
// hard-unhealthy. Counter resets on any successful response.
//
// Deliberately generous. A single 401 is almost always a token-rotation race,
// not a dead account: EnsureFresh mints a new access token and Anthropic
// invalidates the old one server-side the instant refresh completes, so any
// request that captured the old bearer and is still on the wire during the
// ~1-2s rotation window comes back 401. A busy account (many client tokens,
// always some request in flight) orphans one or a few requests into 401 after
// every proactive refresh — all transient, all followed by successes on the
// fresh token. The cost of hard-failing such an account by mistake (a paying
// subscription pulled offline until a manual re-login) hugely outweighs the
// cost of a few extra hidden retries on a genuinely dead one, so we wait for
// a sustained run with no intervening success before retiring it. A truly
// revoked refresh token is caught earlier and authoritatively by the refresh
// path's invalid_grant hard-failure; this counter only backstops the rarer
// "refresh works but every /v1/messages 401s" case.
const auth401HardFailureThreshold = 8

// clearExpiredQuotaLocked auto-clears the quota cooldown fields once their
// reset time has passed, so stale "quota exceeded" state never lingers in
// admin/UI/routing after the credential has actually recovered. Caller MUST
// hold a.mu write lock. Keeps behavior identical to IsQuotaExceeded's expiry
// rules: known reset → clear when reached; unknown reset → clear after 1h.
func (a *Auth) clearExpiredQuotaLocked(now time.Time) {
	if a.QuotaExceededAt.IsZero() {
		return
	}
	if a.QuotaResetAt.IsZero() {
		if now.Before(a.QuotaExceededAt.Add(time.Hour)) {
			return
		}
	} else if now.Before(a.QuotaResetAt) {
		return
	}
	a.QuotaExceededAt = time.Time{}
	a.QuotaResetAt = time.Time{}
}

func (a *Auth) Snapshot() AuthInfo {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	// healthStateLocked subsumes the old clearExpiredQuotaLocked +
	// quarantinedLocked pair (it performs both expiry side effects) and returns
	// the classification, so the snapshot carries State instead of leaving every
	// consumer to re-derive it from raw fields — which is how three call sites
	// ended up with three different ladders.
	health := a.healthStateLocked(now)
	var mm map[string]string
	if len(a.ModelMap) > 0 {
		mm = make(map[string]string, len(a.ModelMap))
		for k, v := range a.ModelMap {
			mm[k] = v
		}
	}
	var rl map[string]string
	if len(a.CodexRateLimits) > 0 {
		rl = make(map[string]string, len(a.CodexRateLimits))
		for k, v := range a.CodexRateLimits {
			rl[k] = v
		}
	}
	return AuthInfo{
		ID:                  a.ID,
		Kind:                a.Kind,
		Provider:            a.Provider,
		Label:               a.Label,
		Email:               a.Email,
		ExpiresAt:           a.ExpiresAt,
		ProxyURL:            a.ProxyURL,
		MaxConcurrent:       a.MaxConcurrent,
		Disabled:            a.Disabled,
		QuotaExceededAt:     a.QuotaExceededAt,
		QuotaResetAt:        a.QuotaResetAt,
		FilePath:            a.FilePath,
		BaseURL:             a.BaseURL,
		Group:               a.Group,
		Order:               a.Order,
		PriceMultiplier:     a.PriceMultiplier,
		RelayPeer:           a.RelayPeer,
		QuarantineUntil:     a.QuarantineUntil,
		QuarantineStrikes:   a.QuarantineStrikes,
		State:               health.State,
		ConsecutiveFailures: health.ConsecutiveFailures,
		Consecutive429s:     health.Consecutive429s,
		Consecutive401s:     health.Consecutive401s,
		LastFailure:         health.LastFailure,
		LastFailureReason:   health.LastFailureReason,
		LastSuccess:         health.LastSuccess,
		HardFailureAt:       health.HardFailureAt,
		ModelMap:            mm,
		CodexRateLimits:     rl,
		CodexRateLimitsAt:   a.CodexRateLimitsAt,
		CodexUsage:          a.CodexUsage,
		CodexUsageAt:        a.CodexUsageAt,
		CodexSubscription:   a.CodexSubscription,
		CodexSubscriptionAt: a.CodexSubscriptionAt,
	}
}

type AuthInfo struct {
	ID              string
	Kind            Kind
	Provider        string
	Label           string
	Email           string
	ExpiresAt       time.Time
	ProxyURL        string
	MaxConcurrent   int
	Disabled        bool
	QuotaExceededAt time.Time
	QuotaResetAt    time.Time
	FilePath        string
	BaseURL         string
	Group           string
	Order           int
	PriceMultiplier float64
	RelayPeer       bool
	// QuarantineUntil / QuarantineStrikes expose the API-key circuit breaker
	// so the admin panel can show a paused channel instead of leaving it
	// looking healthy while it silently serves no traffic. Zero deadline =
	// circuit closed.
	QuarantineUntil   time.Time
	QuarantineStrikes int
	// Failure counters and timestamps. Exposed because a panel cannot tell a
	// channel that is quietly deteriorating from one that is fine without
	// them: below the quarantine threshold an API key shows no other outward
	// sign at all, and after a pause elapses every quarantine field is cleared
	// while ConsecutiveFailures still carries the history. State is the
	// classification these feed (see HealthState); it is carried here so
	// callers projecting AuthInfo to JSON don't have to re-derive it.
	State               HealthState
	ConsecutiveFailures int
	Consecutive429s     int
	Consecutive401s     int
	LastFailure         time.Time
	LastFailureReason   string
	LastSuccess         time.Time
	HardFailureAt       time.Time
	ModelMap            map[string]string
	CodexRateLimits     map[string]string
	CodexRateLimitsAt   time.Time
	CodexUsage          *CodexUsageInfo
	CodexUsageAt        time.Time
	// CodexSubscription is shared by pointer, like CodexUsage: the snapshot
	// replaces the pointer wholesale on each fetch and never mutates the
	// struct in place, so readers of an old snapshot keep a consistent view.
	CodexSubscription   *CodexSubscriptionInfo
	CodexSubscriptionAt time.Time
}

// IsQuotaExceeded reports true if Anthropic has signalled this auth is out of
// quota and we should skip it until QuotaResetAt (or until manually cleared).
// As a side effect, auto-clears the cooldown fields once their reset time has
// passed so callers don't see stale state.
func (a *Auth) IsQuotaExceeded(now time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.clearExpiredQuotaLocked(now)
	return !a.QuotaExceededAt.IsZero()
}

// MarkQuotaExceeded parks the credential until resetAt. This is the "we were
// told to wait" half of the pair described in MarkRateLimitedRetryAfter — it
// deliberately touches no failure counter and no breaker state, because a
// cooldown is a schedule, not a verdict on the credential.
//
// It composes with the quarantine breaker rather than duplicating it: both are
// deadlines, so a credential carrying both returns at the later one. Nothing
// here is additive, and neither mechanism can extend the other.
func (a *Auth) MarkQuotaExceeded(resetAt time.Time) {
	a.mu.Lock()
	a.QuotaExceededAt = time.Now()
	a.QuotaResetAt = resetAt
	a.mu.Unlock()
}

// IsQuarantined reports whether an API-key channel's circuit is currently
// open (paused). Expired quarantines auto-clear as a side effect, so callers
// and the admin panel never see a stale pause.
//
// Note the deadline is only *cleared* here, not the strike counter: strikes
// must survive the pause so a channel that fails its re-probe backs off
// further instead of retrying at the shortest interval forever. MarkSuccess
// is what resets the count — i.e. only real recovery closes the circuit.
func (a *Auth) IsQuarantined(now time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.quarantinedLocked(now)
}

func (a *Auth) quarantinedLocked(now time.Time) bool {
	if a.QuarantineUntil.IsZero() {
		return false
	}
	if now.Before(a.QuarantineUntil) {
		return true
	}
	// Deadline passed — the circuit goes half-open: the channel is offered to
	// the very next request so a single probe can prove whether the upstream
	// recovered. Success clears the strikes (MarkSuccess); another failure
	// re-opens the circuit at the next backoff step (tripQuarantineLocked).
	a.QuarantineUntil = time.Time{}
	return false
}

// tripQuarantineLocked opens the circuit for an API-key channel once its
// consecutive-failure count reaches the threshold. Caller MUST hold a.mu.
//
// The backoff carries ±20% jitter. Without it, a fleet of keys knocked out by
// one shared upstream fault would come back at the identical instant, hit the
// still-broken upstream together, and re-open together — a self-synchronising
// thundering herd that turns one outage into a periodic stampede.
// threshold is the consecutive-failure count at which the circuit opens:
// apiKeyQuarantineThreshold for ordinary upstream weather, 1 for a
// definitive credential rejection, which needs no corroboration.
func (a *Auth) tripQuarantineLocked(now time.Time, reason string, threshold int) {
	a.openBreakerLocked(now, reason, "consecutive failures", a.ConsecutiveFailures, threshold)
}

// openBreakerLocked is the single entry point to the API-key circuit breaker,
// parameterised by *which* counter is being judged.
//
// The breaker used to read ConsecutiveFailures and nothing else, which meant
// the two most common ways a relay channel dies — an endless run of 429s and
// an endless run of 401s — could never open it: MarkRateLimited and
// MarkAuthRejection deliberately keep their own counters and never touch
// ConsecutiveFailures (they must not, or an OAuth account that merely
// exhausted its 5h window would march toward the hard-fail threshold). The
// result was a key that cycled "try → cooldown → try" forever without ever
// rotating away. Each signal now brings its own counter and its own threshold
// here, while the backoff ladder (QuarantineStrikes) stays shared — a channel
// failing three different ways is not three independently healthy channels.
//
// counterName appears in the log line only.
// Caller MUST hold a.mu.
func (a *Auth) openBreakerLocked(now time.Time, reason, counterName string, count, threshold int) {
	if a.Kind != KindAPIKey {
		return
	}
	if count < threshold {
		return
	}
	if now.Before(a.QuarantineUntil) {
		return // already paused; don't extend on a request already in flight
	}
	a.QuarantineStrikes++
	d := apiKeyQuarantineBackoff(a.QuarantineStrikes)
	jitter := 1 + (rand.Float64()*0.4 - 0.2) //nolint:gosec // jitter spread, not a security decision
	a.QuarantineUntil = now.Add(time.Duration(float64(d) * jitter))
	log.Warnf("auth: api-key %s paused until %s (strike %d, %d %s): %s",
		a.ID, a.QuarantineUntil.Format(time.RFC3339), a.QuarantineStrikes, count, counterName, reason)
}

// QuarantineSnapshot returns the current pause deadline and strike count for
// the admin panel. A zero deadline means the circuit is closed. Auto-clears
// an expired deadline, matching IsQuarantined.
func (a *Auth) QuarantineSnapshot() (until time.Time, strikes int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.quarantinedLocked(time.Now())
	return a.QuarantineUntil, a.QuarantineStrikes
}

func (a *Auth) MarkFailure(reason string) {
	a.mu.Lock()
	a.LastFailure = time.Now()
	a.LastFailureReason = reason
	a.ConsecutiveFailures++
	// API-key credentials are operator-managed BYOK / relay channels: a run
	// of transient upstream errors (500s, gateway hiccups, relay weather)
	// must NOT auto-retire them, or a working key gets pinned offline until
	// someone clears it by hand. Keep the counter for admin visibility, but
	// skip the sticky hard-failure escalation. Only OAuth subscription
	// accounts — scarce and genuinely worth taking out of rotation when they
	// go bad — auto-promote on repeated failure.
	if a.Kind != KindAPIKey && a.ConsecutiveFailures >= hardFailureThreshold && a.HardFailureAt.IsZero() {
		a.HardFailureAt = a.LastFailure
		a.HardFailureReason = fmt.Sprintf("%d consecutive failures: %s", a.ConsecutiveFailures, reason)
	}
	// API keys get the self-healing equivalent instead: a timed pause that
	// takes the channel out of rotation without ever retiring it.
	a.tripQuarantineLocked(a.LastFailure, reason, apiKeyQuarantineThreshold)
	a.mu.Unlock()
}

// MarkRateLimited records a 429 response. 429 alone is not a credential
// fault (rate limit, transient), so it does not increment the generic
// ConsecutiveFailures counter and does not set LastFailure — those drive
// the "degraded" UI state, which is too noisy for normal rate-limiting.
// Instead it bumps a dedicated 429 counter; once it crosses
// rateLimit429HardFailureThreshold, the credential is presumed stealth-
// banned and flipped to sticky hard-failure (Anthropic sometimes serves
// bans as endless 429s rather than a clean 401/403).
//
// Returns the new Consecutive429s value so callers (the pool) can pick a
// backoff length that grows with repeated hits.
//
// Equivalent to MarkRateLimitedRetryAfter with no reset hint, i.e. the
// pessimistic reading: the upstream said "no" without saying when to come
// back, so an API-key channel accrues a breaker strike once the run is long
// enough. Callers that DID receive a Retry-After should use
// MarkRateLimitedRetryAfter and pass it.
func (a *Auth) MarkRateLimited(reason string) int {
	return a.MarkRateLimitedRetryAfter(reason, time.Time{})
}

// MarkRateLimitedRetryAfter records a 429 together with the moment the
// upstream said it would accept traffic again (from Retry-After or an
// equivalent reset header). Pass the zero time when the upstream gave no hint.
//
// This distinction exists to keep the two throttling mechanisms from punishing
// the same failure twice, and the division of labour between them is:
//
//   - The quota cooldown (MarkQuotaExceeded → QuotaResetAt) is an instruction
//     we were given. It is precise, it is the upstream's own number, and it
//     ends exactly when the upstream says it ends.
//   - The quarantine breaker (QuarantineUntil) is an inference we made. It
//     exists for the case where nobody told us anything and we have to guess
//     from a pattern of refusals that the channel is not worth trying.
//
// So when the upstream supplies a reset time we take it at its word and do NOT
// add a strike: a well-behaved relay that answers "429, retry in 12s" on a
// burst is doing its job, and stacking a 15-minute breaker pause on top of its
// 12-second window would retire a healthy channel for being honest. Only the
// silent 429s — the ones that leave us guessing — feed the breaker.
//
// Note this is an overlap, not a sum, in every case: both mechanisms are
// deadlines on the same credential, so when both are set the credential simply
// returns at the later of the two rather than serving them back to back.
//
// The 429 counter itself advances either way, so OAuth's stealth-ban detection
// at rateLimit429HardFailureThreshold is unchanged: a cooperative Retry-After
// is evidence about *this* request's timing, not about whether the account is
// quietly banned.
func (a *Auth) MarkRateLimitedRetryAfter(reason string, retryAfter time.Time) int {
	a.mu.Lock()
	now := time.Now()
	a.Consecutive429s++
	n := a.Consecutive429s
	// API-key channels never auto-retire (see MarkFailure): a relay serving
	// a stretch of 429s is throttling, not stealth-banning a subscription
	// account, and the operator manages disabling manually.
	if a.Kind != KindAPIKey && a.Consecutive429s >= rateLimit429HardFailureThreshold && a.HardFailureAt.IsZero() {
		a.HardFailureAt = now
		a.HardFailureReason = fmt.Sprintf("%d consecutive 429s (suspected stealth ban): %s", a.Consecutive429s, reason)
		a.LastFailure = a.HardFailureAt
		a.LastFailureReason = a.HardFailureReason
	}
	if a.Kind == KindAPIKey {
		// Record the failure timestamp so the panel can see a channel
		// deteriorating (HealthDegraded) before the breaker takes it out, and
		// so that after a pause expires the credential reads HealthHalfOpen
		// rather than jumping straight back to green with nothing verified.
		// Safe for API keys specifically: IsHealthy short-circuits on
		// KindAPIKey, so LastFailure here cannot leak into a routing decision
		// the way it would for OAuth — which is why this stays inside the
		// Kind guard rather than applying to both.
		a.LastFailure = now
		a.LastFailureReason = reason
		if retryAfter.IsZero() {
			a.openBreakerLocked(now, reason, "consecutive 429s", n, apiKey429QuarantineThreshold)
		}
	}
	a.mu.Unlock()
	return n
}

// MarkAuthRejection records a definitive upstream 401 (authentication_error)
// on this credential and returns the running count of consecutive such
// rejections with no intervening success.
//
// A request-time 401 is NOT treated as a terminal signal on its own: it is
// overwhelmingly a token-rotation race (see auth401HardFailureThreshold). Like
// MarkRateLimited, this keeps a dedicated counter rather than touching the
// generic ConsecutiveFailures/LastFailure state, so a burst of post-refresh
// orphan 401s doesn't flip the credential into the noisy "degraded" UI state.
// The caller applies a short cooldown per strike (self-recovering) and only
// promotes to a sticky hard-failure once the count crosses
// auth401HardFailureThreshold — by which point the account has 401'd a
// sustained run of requests with zero successes, i.e. it is genuinely revoked
// rather than briefly racing a refresh.
//
// API-key channels never auto-retire (see MarkFailure): a flaky relay backend
// serving an occasional 401 must not pull the whole operator-managed channel
// out of rotation. The sticky hard-failure escalation is therefore skipped for
// them — but they do get the bounded breaker, at their own much lower
// threshold (apiKey401QuarantineThreshold), because the token-rotation race
// that makes OAuth 401s ambiguous does not exist for a key that never rotates.
// Without that the exemption was total: an API key could 401 forever and never
// leave rotation, which is precisely the loop this path now closes.
func (a *Auth) MarkAuthRejection(reason string) int {
	if len(reason) > 200 {
		reason = reason[:200] + "..."
	}
	a.mu.Lock()
	a.Consecutive401s++
	n := a.Consecutive401s
	if a.Kind == KindAPIKey {
		now := time.Now()
		// See MarkRateLimitedRetryAfter: recording the failure keeps the
		// degraded window visible and makes the post-pause state half-open
		// instead of a falsely-green healthy.
		a.LastFailure = now
		a.LastFailureReason = reason
		a.openBreakerLocked(now, reason, "consecutive 401s", n, apiKey401QuarantineThreshold)
	}
	if a.Kind != KindAPIKey && a.Consecutive401s >= auth401HardFailureThreshold && a.HardFailureAt.IsZero() {
		a.HardFailureAt = time.Now()
		a.HardFailureReason = fmt.Sprintf("%d consecutive 401s (auth rejected, refresh still valid — presumed revoked): %s", a.Consecutive401s, reason)
		a.LastFailure = a.HardFailureAt
		a.LastFailureReason = a.HardFailureReason
	}
	a.mu.Unlock()
	return n
}

// MarkUsageLimitReached records a Claude subscription usage-limit 429 (the
// body carries "Claude AI usage limit reached|<unix-ts>"). This is the
// regular 5h/weekly quota signal and resets exactly when Anthropic says it
// will, so we set a real cooldown and explicitly do NOT touch the
// Consecutive429s counter — it would otherwise tick toward a stealth-ban
// hard-failure for an account that's actually fine.
func (a *Auth) MarkUsageLimitReached(resetAt time.Time) {
	a.mu.Lock()
	a.QuotaExceededAt = time.Now()
	a.QuotaResetAt = resetAt
	a.mu.Unlock()
}

// ModelScopeAnthropicFable is the model-family scope for Anthropic's fable
// models. Anthropic bills fable against an independent weekly allotment that
// rejects on its own while the shared 5h/7d quota stays available, so a fable
// exhaustion must be scoped to the family — never the whole account.
//
// A non-entitled account answers details.error_code=credits_required instead;
// that is also a per-credential fact and belongs in this same scope. What it is
// NOT is a service-wide rule — see AnthropicFableOAuthDisabled.
const ModelScopeAnthropicFable = "anthropic:fable"

// AnthropicModelScope maps a client model string to the model-family rate-limit
// scope it belongs to, or "" if the model has no independent scope (in which
// case any quota signal is account-wide). Matches any fable variant — dated
// (claude-fable-5-2026…), 1M-context ("[1m]") and mixed casing all collapse to
// the same family scope.
func AnthropicModelScope(model string) string {
	normalized := strings.ToLower(strings.TrimSpace(model))
	normalized = strings.TrimPrefix(normalized, "anthropic/")
	if normalized == "claude-fable-5" ||
		strings.HasPrefix(normalized, "claude-fable-5-") ||
		strings.HasPrefix(normalized, "claude-fable-5[") {
		return ModelScopeAnthropicFable
	}
	return ""
}

// AnthropicFableOAuthDisabled restores the historical blanket rule that fable
// never touches subscription OAuth, for deployments whose accounts genuinely
// lack the entitlement. Default false: fable schedules onto OAuth like every
// other model, and a credential that refuses it self-excludes for that family
// alone via MarkModelRateLimited(ModelScopeAnthropicFable, …).
//
// Set once at startup, before the pool takes traffic. It is deliberately a
// plain bool rather than an atomic: flipping it under load would change routing
// mid-request for no operational gain, and the pool lock does not cover it.
var AnthropicFableOAuthDisabled = false

// AnthropicModelRequiresAPIKey reports whether a model must bypass Anthropic
// subscription OAuth credentials under the current policy. It is the predicate
// behind AnthropicFableOAuthDisabled and answers false while that flag is off.
func AnthropicModelRequiresAPIKey(model string) bool {
	return AnthropicFableOAuthDisabled && AnthropicModelScope(model) == ModelScopeAnthropicFable
}

// MarkModelRateLimited records that a specific model-family scope on this
// credential is out of quota until resetAt, WITHOUT touching account-wide
// health. Requests for models in that scope are skipped by the scheduler; every
// other model keeps scheduling normally. Like MarkUsageLimitReached it
// deliberately does NOT advance Consecutive429s — a per-model overage window
// hitting its ceiling is a real quota signal, not a stealth-ban candidate.
func (a *Auth) MarkModelRateLimited(scope string, resetAt time.Time) {
	if scope == "" {
		return
	}
	a.mu.Lock()
	if a.ModelRateLimits == nil {
		a.ModelRateLimits = make(map[string]time.Time, 1)
	}
	a.ModelRateLimits[scope] = resetAt
	a.mu.Unlock()
}

// IsModelRateLimited reports whether the given model-family scope is currently
// cooling down on this credential. Expired entries are pruned as a side effect
// so callers and the admin panel never see stale scoped limits.
func (a *Auth) IsModelRateLimited(scope string, now time.Time) bool {
	if scope == "" {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	resetAt, ok := a.ModelRateLimits[scope]
	if !ok {
		return false
	}
	// Zero reset = manual clear only (mirrors QuotaResetAt semantics).
	if !resetAt.IsZero() && !now.Before(resetAt) {
		delete(a.ModelRateLimits, scope)
		return false
	}
	return true
}

// MarkClientCancel records that a request through this credential was
// aborted by the client (context canceled before upstream responded). This
// is surfaced to the admin panel as a non-fatal hint but never touches
// health state — the credential itself did nothing wrong.
func (a *Auth) MarkClientCancel(reason string) {
	if len(reason) > 200 {
		reason = reason[:200] + "..."
	}
	a.mu.Lock()
	a.LastClientCancel = time.Now()
	a.LastClientCancelReason = reason
	a.mu.Unlock()
}

// ClientCancelSnapshot returns the most recent client-cancel timestamp and
// reason, if any. Zero time means none recorded.
func (a *Auth) ClientCancelSnapshot() (time.Time, string) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.LastClientCancel, a.LastClientCancelReason
}

// MarkHardFailure flags the credential as sticky-unhealthy. The admin panel
// must manually clear it before traffic resumes. Used for obvious terminal
// signals (e.g. account disabled, upstream dead).
//
// API-key credentials are exempt from the *sticky* flag: they are
// operator-managed BYOK / relay channels that must never be auto-retired by
// error detection — a single 401/403 from a flaky relay backend shouldn't
// pull the whole channel out of rotation until someone clears it by hand.
// Operators who genuinely want an API key offline use SetDisabled (the manual
// Disabled flag), which IsHealthy honours independently of this path.
//
// They are NOT exempt from the self-healing quarantine, and here it opens on
// the first strike rather than the third: unlike throttling or a gateway
// error, a rejection of the credential itself is definitive and needs no
// corroboration, and re-presenting a revoked key on every subsequent request
// only buys a guaranteed round-trip before failing over. The pause still
// expires on its own, so a relay that rejected one request spuriously is back
// within seconds.
func (a *Auth) MarkHardFailure(reason string) {
	a.mu.Lock()
	a.LastFailure = time.Now()
	a.LastFailureReason = reason
	if a.Kind != KindAPIKey {
		a.HardFailureAt = a.LastFailure
		a.HardFailureReason = reason
	} else {
		a.ConsecutiveFailures++
		a.tripQuarantineLocked(a.LastFailure, reason, 1)
	}
	a.mu.Unlock()
}

// MarkSuccess records that the most recent upstream request through this
// credential succeeded. Used by the admin panel to compute "healthy" status.
func (a *Auth) MarkSuccess() {
	a.mu.Lock()
	a.LastSuccess = time.Now()
	a.ConsecutiveFailures = 0
	a.Consecutive429s = 0
	a.Consecutive401s = 0
	// Recovery closes the circuit for good: a successful exchange is the only
	// thing that resets the strike count, so the backoff ladder restarts from
	// the bottom next time rather than staying pessimistic forever. This is
	// what makes the half-open probe in quarantinedLocked terminate — the
	// channel returns to full rotation with no operator involvement.
	if !a.QuarantineUntil.IsZero() || a.QuarantineStrikes > 0 {
		log.Infof("auth: api-key %s recovered after %d quarantine strike(s) — back in rotation", a.ID, a.QuarantineStrikes)
	}
	a.QuarantineUntil = time.Time{}
	a.QuarantineStrikes = 0
	a.mu.Unlock()
}

// ClearFailure wipes every piece of state this package inferred about the
// credential's health — counters, the sticky hard-failure flag, and the
// quarantine breaker — returning it to "healthy". This is the admin panel's
// "Mark healthy" button.
//
// Clearing the breaker here is required, not incidental: the breaker is now
// reachable from three counters (failures, 429s, 401s), so a button that reset
// the counters but left QuarantineUntil/QuarantineStrikes standing would
// report the channel healthy while it stayed paused, and the surviving strike
// count would send the next trip straight to a late rung of the backoff
// ladder. LastSuccess is stamped so the credential reads verified rather than
// half-open.
//
// It deliberately does NOT clear the quota cooldown; that is ClearQuota's job.
// The split is the same one the mechanisms have everywhere else: this button
// says "forget what you concluded about this credential", the other says
// "ignore the wait the upstream asked for". An operator who wants both presses
// both.
func (a *Auth) ClearFailure() {
	a.mu.Lock()
	a.LastFailure = time.Time{}
	a.LastFailureReason = ""
	a.ConsecutiveFailures = 0
	a.Consecutive429s = 0
	a.Consecutive401s = 0
	a.HardFailureAt = time.Time{}
	a.HardFailureReason = ""
	a.QuarantineUntil = time.Time{}
	a.QuarantineStrikes = 0
	a.LastSuccess = time.Now()
	a.mu.Unlock()
}

// IsHealthy returns true if the credential is enabled, not in cooldown, and
// the most recent observed upstream attempt either succeeded or there has
// been no failure recorded at all. A credential that has never been used is
// considered healthy.
func (a *Auth) IsHealthy() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.clearExpiredQuotaLocked(time.Now())
	if a.Disabled {
		return false
	}
	if !a.HardFailureAt.IsZero() {
		return false
	}
	if !a.QuotaExceededAt.IsZero() {
		return false
	}
	// API-key channels are never downgraded by the open-ended "degraded"
	// heuristic used for OAuth below: a relay serving a run of 500s would drop
	// out the moment ConsecutiveFailures crossed the threshold and then have no
	// way back in if it were the only channel for a model.
	//
	// They are instead governed by the quarantine circuit breaker, which is
	// bounded rather than open-ended — it always expires, so the channel
	// always gets another probe (see apiKeyQuarantineThreshold). While the
	// circuit is open the key is skipped, which is what lets traffic rotate
	// onto the next key instead of re-paying a doomed round-trip per request.
	if a.Kind == KindAPIKey {
		return !a.quarantinedLocked(time.Now())
	}
	if a.LastFailure.IsZero() {
		return true
	}
	if a.LastSuccess.After(a.LastFailure) {
		return true
	}
	// Optimistic recovery: a single stale failure no longer counts. Repeated
	// failures within the grace window keep the credential red.
	if a.ConsecutiveFailures < 2 && time.Since(a.LastFailure) > healthGrace {
		return true
	}
	// Degraded re-probe: a credential that failed repeatedly is quarantined, but
	// not forever — it gets back into rotation once degradedProbeAfter has passed
	// so a single request can prove whether it recovered. See degradedProbeAfter.
	if time.Since(a.LastFailure) > degradedProbeAfter {
		return true
	}
	return false
}

// HealthSnapshot returns a copy of the fields the admin panel needs to
// render health state. Auto-clears expired quota state as a side effect so
// the panel never shows a "quota exceeded" badge after the cooldown has
// elapsed.
func (a *Auth) HealthSnapshot() (healthy, hardFailure bool, reason string, consecutive int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	a.clearExpiredQuotaLocked(now)
	quarantined := a.quarantinedLocked(now)
	hardFailure = !a.HardFailureAt.IsZero()
	consecutive = a.ConsecutiveFailures
	switch {
	case hardFailure:
		reason = a.HardFailureReason
	case quarantined:
		reason = fmt.Sprintf("paused until %s (strike %d): %s",
			a.QuarantineUntil.Format(time.RFC3339), a.QuarantineStrikes, a.LastFailureReason)
	case !a.LastFailure.IsZero() && !a.LastSuccess.After(a.LastFailure):
		reason = a.LastFailureReason
	}
	// Recompute healthy with the same logic as IsHealthy but without
	// re-acquiring the lock.
	switch {
	case a.Disabled:
		healthy = false
	case hardFailure:
		healthy = false
	case !a.QuotaExceededAt.IsZero():
		healthy = false
	// API keys are governed by the quarantine breaker, never by the
	// open-ended degraded heuristic below — mirroring IsHealthy. Without this
	// case the panel reported an API key unhealthy on rules the router does
	// not apply, so a key that was actively serving traffic could show red.
	case a.Kind == KindAPIKey:
		healthy = !quarantined
	case a.LastFailure.IsZero(), a.LastSuccess.After(a.LastFailure):
		healthy = true
	case a.ConsecutiveFailures < 2 && time.Since(a.LastFailure) > healthGrace:
		healthy = true
	case time.Since(a.LastFailure) > degradedProbeAfter:
		healthy = true
	default:
		healthy = false
	}
	return
}

// Credentials returns a snapshot of the fields needed to authenticate an
// upstream request. Safe for concurrent callers.
func (a *Auth) Credentials() (accessToken string, kind Kind) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.AccessToken, a.Kind
}

// CodexIdentity returns the Codex/OpenAI-specific identity fields
// (account_id + plan_type) under the read lock. Empty strings for
// Anthropic auths.
func (a *Auth) CodexIdentity() (accountID, planType string) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.AccountID, a.PlanType
}

// CaptureCodexRateLimits extracts all x-codex-* response headers from upstream
// and stores them as the latest rate-limit snapshot. Called after every Codex
// upstream response regardless of status — a 403 or 429 also carries these
// fields and keeping the view fresh matters most right when the user is about
// to complain about a limit. Missing headers are simply ignored; we keep the
// prior snapshot intact rather than wiping it.
func (a *Auth) CaptureCodexRateLimits(h map[string][]string) {
	if len(h) == 0 {
		return
	}
	captured := make(map[string]string, 8)
	for k, vs := range h {
		if len(vs) == 0 {
			continue
		}
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "x-codex-") {
			captured[lk] = vs[0]
		}
	}
	if len(captured) == 0 {
		return
	}
	a.mu.Lock()
	a.CodexRateLimits = captured
	a.CodexRateLimitsAt = time.Now()
	a.mu.Unlock()
}

// IsHardFailed reports whether the credential has been flagged sticky-
// unhealthy and must be manually cleared before traffic resumes.
func (a *Auth) IsHardFailed() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return !a.HardFailureAt.IsZero()
}

// ClearQuota drops the account-wide cooldown and every per-model scoped limit
// — the admin panel's "Clear quota" button. It is the counterpart to
// ClearFailure and stops exactly where that one begins: it must NOT clear the
// quarantine breaker.
//
// The two buttons answer different questions. Quota state records a wait the
// upstream imposed; an operator overriding it is saying "I don't believe that
// window applies any more". Breaker state records our own loss of confidence
// after a run of refusals, and silently discarding that while restoring
// quota would put a channel we distrust back into rotation through a button
// whose label promises nothing of the sort. "Mark healthy" is the button that
// means that, and it says so.
func (a *Auth) ClearQuota() {
	a.mu.Lock()
	a.QuotaExceededAt = time.Time{}
	a.QuotaResetAt = time.Time{}
	a.ModelRateLimits = nil
	a.mu.Unlock()
}

// SetDisabled toggles the disabled flag.
func (a *Auth) SetDisabled(v bool) {
	a.mu.Lock()
	a.Disabled = v
	a.mu.Unlock()
}

// SetMaxConcurrent updates the slot cap for this credential.
func (a *Auth) SetMaxConcurrent(n int) {
	if n < 0 {
		n = 0
	}
	a.mu.Lock()
	a.MaxConcurrent = n
	a.mu.Unlock()
}

// SetProxyURL updates the per-credential upstream proxy. Empty string clears it.
func (a *Auth) SetProxyURL(u string) {
	a.mu.Lock()
	a.ProxyURL = u
	a.mu.Unlock()
}

// SetBaseURL updates the per-credential upstream base URL (API-key only).
// Empty string reverts to the server-wide default.
func (a *Auth) SetBaseURL(u string) {
	a.mu.Lock()
	a.BaseURL = u
	a.mu.Unlock()
}

// SetOrder updates the API-key selection priority (lower = used first). No-op
// on routing for OAuth, which load-balances by usage. Re-sorting p.apikeys
// after this is the caller's job (see Pool.ReorderAPIKeys).
func (a *Auth) SetOrder(n int) {
	a.mu.Lock()
	a.Order = n
	a.mu.Unlock()
}

// OrderValue returns the credential's selection priority under the lock.
func (a *Auth) OrderValue() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.Order
}

// SetPriceMultiplier updates the per-key billing override (API-key only).
// A value <= 0 clears the override so billing falls back to the client's
// pricing-group multiplier. Persisting afterwards is the caller's job.
func (a *Auth) SetPriceMultiplier(f float64) {
	a.mu.Lock()
	if f < 0 {
		f = 0
	}
	a.PriceMultiplier = f
	a.mu.Unlock()
}

// PriceMultiplierValue returns the per-key billing override under the lock.
// 0 means unset (use the pricing-group multiplier).
func (a *Auth) PriceMultiplierValue() float64 {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.PriceMultiplier
}

// SetGroup updates the credential's group. Empty string or "public" (case-
// insensitive) means the public pool.
func (a *Auth) SetGroup(g string) {
	a.mu.Lock()
	a.Group = NormalizeGroup(g)
	a.mu.Unlock()
}

// GroupName returns the credential's group under the lock.
func (a *Auth) GroupName() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.Group
}

// SetModelMap replaces the credential's client→upstream model map. Empty/nil
// map clears it (credential becomes wildcard again). API-key only — calling
// on an OAuth credential stores the value but it is ignored at routing time.
func (a *Auth) SetModelMap(m map[string]string) {
	cleaned := make(map[string]string, len(m))
	for k, v := range m {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		cleaned[k] = strings.TrimSpace(v)
	}
	a.mu.Lock()
	if len(cleaned) == 0 {
		a.ModelMap = nil
	} else {
		a.ModelMap = cleaned
	}
	a.mu.Unlock()
}

// ResolveUpstreamModel returns the upstream model name to send for a given
// client-facing model. ok=false means this credential does not accept the
// model (caller should skip it during routing). When ok=true, upstream is
// the model name to put in the request body — empty string means "send the
// client's model name unchanged".
//
// Wildcard credentials (nil/empty ModelMap) always return (clientModel, true).
//
// Lookup order, mirroring pricing.Lookup so a name that finds a price card also
// finds its rewrite:
//
//  1. the client model verbatim;
//  2. the same name with a trailing "[1m]" context-mode label removed, with the
//     label re-attached to whatever the map returns;
//  3. progressively shorter "-"-trimmed prefixes of that base name, so a dated
//     variant (claude-opus-4-8-20260315) resolves through its undated entry
//     (claude-opus-4-8) without the map having to enumerate release dates.
//
// Step 3 is what lets DefaultClaudeOAuthModelMap fold a whole family with one
// entry per generation. It also fixes the long-standing relay case the ModelMap
// doc comment describes: a vendor that registered "claude-haiku-4-5" but is sent
// the dated "claude-haiku-4-5-20251001" now matches instead of passing through.
// The fallback only ever runs on an exact-match MISS, so no existing exact entry
// changes meaning.
func (a *Auth) ResolveUpstreamModel(clientModel string) (upstream string, ok bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	// ModelMap is a rewrite table, not an allow-list. A model listed with a
	// non-empty value is rewritten; anything else (unlisted, or mapped to "")
	// passes through unchanged. ok is always true — the second return is kept
	// for call-site symmetry.
	if len(a.ModelMap) == 0 {
		return clientModel, true
	}
	if mapped, exists := a.ModelMap[clientModel]; exists && mapped != "" {
		return mapped, true
	}
	base, suffix := splitContextModeSuffix(clientModel)
	if suffix != "" {
		if mapped, exists := a.ModelMap[base]; exists && mapped != "" {
			return mapped + suffix, true
		}
	}
	for i := strings.LastIndex(base, "-"); i > 0; i = strings.LastIndex(base[:i], "-") {
		if mapped, exists := a.ModelMap[base[:i]]; exists && mapped != "" {
			return mapped + suffix, true
		}
	}
	return clientModel, true
}

// splitContextModeSuffix splits a trailing "[value]" context-mode label off a
// model name: "claude-opus-5[1m]" → ("claude-opus-5", "[1m]"). Names without
// one return (model, ""). Kept local to auth so the package doesn't take a
// dependency on pricing for one string split; pricing.StripContextModeSuffix is
// the same rule stated for the billing side.
func splitContextModeSuffix(model string) (base, suffix string) {
	if !strings.HasSuffix(model, "]") {
		return model, ""
	}
	i := strings.LastIndex(model, "[")
	if i <= 0 {
		return model, ""
	}
	return model[:i], model[i:]
}

// AcceptsModel reports whether this credential may serve a request for the
// given client-facing model. ModelMap is rewrite-only and never filters, so
// every credential accepts every model; the method is retained for the pool
// selector's call sites and possible future per-key routing.
func (a *Auth) AcceptsModel(clientModel string) bool {
	return true
}
