package auth

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

var (
	ErrDuplicateClaudeAccountUUID    = errors.New("duplicate Anthropic OAuth account_uuid")
	ErrCredentialFileAccountMismatch = errors.New("credential file now belongs to a different account")
)

// Pool holds all credentials (OAuth + API keys) and assigns them to client
// sessions with slot-based concurrency for OAuth and unlimited for API keys.
//
// Concurrency model:
//   - A "client session" (= one slot) is identified by (provider, client
//     access token, sessionID). sessionID is the client-supplied per-window
//     identifier (Claude Code's X-Claude-Code-Session-Id); when it is empty
//     the session degrades to one slot per (provider, client token).
//   - One user with N open CLI windows therefore presents N independent
//     sessions, each sticky-assigned (and load-balanced) on its own — so a
//     single user's windows can be spread across different OAuth credentials.
//   - When a session makes a request, it is sticky-assigned to one OAuth auth.
//   - The OAuth auth holds at most MaxConcurrent distinct active sessions.
//   - A session is considered active if its last request is within ActiveWindow.
//   - When all OAuth auths are saturated or unhealthy, the session falls back
//     to an API key (unlimited).
type Pool struct {
	mu           sync.Mutex
	oauths       []*Auth
	apikeys      []*Auth
	sessions     map[string]*session // slot key (provider|token|sessionID) -> session
	activeWindow time.Duration
	useUTLS      bool
	defaultProxy string
	// usageLoad, when set, returns a cost-weighted token count for the given
	// OAuth auth over the recent rolling window used for load balancing —
	// currently the last ~5h to align with Anthropic's 5-hour quota window.
	// OpenAI/Codex does not expose a comparable rolling quota; the same
	// 5h window still gives a reasonable "recent load" signal for picking
	// the least-used Codex credential
	// (see usage.Counts.WeightedTotal — input 1×, cache_create 1.25×,
	// cache_read 0.1×, output 5×). It is the SECOND ordering key in
	// pickOAuthLocked, applied among candidates of equal client fan-out: the
	// least-used candidate wins, so cache-heavy credentials aren't penalized
	// by the near-free cache_read stream and the scarce output tokens
	// dominate.
	usageLoad func(authID string) int64

	// affinity remembers which OAuth credential last served a slot, and
	// outlives the slot itself. See defaultAffinityTTL for why.
	affinity    map[string]affinityEntry
	affinityTTL time.Duration
}

// defaultAffinityTTL is how long a slot's credential is remembered after the
// slot itself expires.
//
// sessions are GC'd one activeWindow (5 min) after their last request, taking
// the credential binding with them, so the next turn is scheduled from scratch
// by load. For an interactive client that is the common case, not the rare
// one: read the diff, run the tests, think, send the next turn eight minutes
// later — and land on a different account, where the upstream prompt cache for
// this conversation does not exist. A 60k-token context then re-uploads as
// fresh input instead of a near-free cache read, which costs both latency to
// first token and money, every single time.
//
// So the binding is remembered separately and for longer than the slot. An
// hour matches how long the upstream caches an idle prefix at the outside, and
// the WS path's response→account binding (codexRespAccountTTL), so a returning
// conversation is offered its old account for as long as reusing it can still
// pay off.
//
// This is a PREFERENCE, not a pin. The remembered credential is fed back
// through the ordinary sticky path, so health, group, model, exclusion and
// concurrency all still gate it and an unusable one simply falls through to a
// normal pick. It is deliberately kept out of p.sessions: concurrency is
// accounted on live sessions, and an hour-long memory must not make an idle
// conversation occupy a slot it is not using.
const defaultAffinityTTL = time.Hour

type affinityEntry struct {
	authID string
	exp    time.Time
}

type session struct {
	clientToken string
	sessionID   string // client per-window slot id; "" = one slot per token
	provider    string // canonical provider id; sessions are scoped per-provider
	authID      string // empty = never assigned
	kind        Kind
	lastSeen    time.Time
}

// slotKey builds the per-slot sessions-map key. A non-empty sessionID makes
// each client window (one Claude Code CLI session) an independent slot, so one
// user running several windows holds several slots and is load-balanced across
// credentials window-by-window. Empty sessionID collapses to one slot per
// (provider, client token) — the pre-sessionID behaviour, used for raw API
// callers that send no window identifier.
func slotKey(provider, clientToken, sessionID string) string {
	return provider + "|" + clientToken + "|" + sessionID
}

func NewPool(oauths, apikeys []*Auth, activeWindow time.Duration, useUTLS bool, defaultProxy string) *Pool {
	defaultProxy = strings.TrimSpace(defaultProxy)
	p := &Pool{
		oauths:       append([]*Auth(nil), oauths...),
		apikeys:      append([]*Auth(nil), apikeys...),
		sessions:     make(map[string]*session),
		affinity:     make(map[string]affinityEntry),
		affinityTTL:  defaultAffinityTTL,
		activeWindow: activeWindow,
		useUTLS:      useUTLS,
		defaultProxy: defaultProxy,
	}
	// Apply default proxy to OAuths that don't specify one.
	for _, a := range p.oauths {
		if a.ProxyURL == "" && defaultProxy != "" {
			a.ProxyURL = defaultProxy
		}
	}
	// Keep API keys in operator-assigned priority order so Acquire's
	// first-viable scan returns the highest-priority key. Ties (same Order,
	// e.g. all-default 0) preserve load order via the stable sort.
	sortAPIKeysLocked(p.apikeys)
	return p
}

// sortAPIKeysLocked stable-sorts the slice ascending by Order. Stable so equal
// Order values keep their incoming (load / insertion) order. Caller holds p.mu
// (or owns the slice exclusively, as in NewPool before publication).
func sortAPIKeysLocked(keys []*Auth) {
	sort.SliceStable(keys, func(i, j int) bool {
		return keys[i].OrderValue() < keys[j].OrderValue()
	})
}

func (p *Pool) UseUTLS() bool               { return p.useUTLS }
func (p *Pool) ActiveWindow() time.Duration { return p.activeWindow }

// SetUsageLoadFunc installs a callback used as the load-balancing tiebreaker
// when picking an OAuth credential. fn should return weighted token usage
// over the rolling window being used to approximate Anthropic's quota
// window (currently 5h). fn must be safe for concurrent use and should not
// call back into the pool.
func (p *Pool) SetUsageLoadFunc(fn func(authID string) int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.usageLoad = fn
}

// gcLocked expires stale sessions whose lastSeen is older than activeWindow.
// Callers must hold p.mu.
func (p *Pool) gcLocked(now time.Time) {
	cutoff := now.Add(-p.activeWindow)
	for k, s := range p.sessions {
		if s.lastSeen.Before(cutoff) {
			delete(p.sessions, k)
		}
	}
	for k, e := range p.affinity {
		if now.After(e.exp) {
			delete(p.affinity, k)
		}
	}
}

// rememberAffinityLocked records that slotKey was served by an OAuth authID, so
// a later turn of the same conversation can be offered it again after the slot
// has been GC'd. Caller holds p.mu.
func (p *Pool) rememberAffinityLocked(slotKey, authID string, now time.Time) {
	if slotKey == "" || authID == "" || p.affinityTTL <= 0 {
		return
	}
	if p.affinity == nil {
		p.affinity = make(map[string]affinityEntry)
	}
	p.affinity[slotKey] = affinityEntry{authID: authID, exp: now.Add(p.affinityTTL)}
}

// SetAffinityTTL overrides how long a slot's credential is remembered past the
// slot's own lifetime. Zero disables the memory entirely, restoring
// schedule-from-scratch on every re-created slot.
func (p *Pool) SetAffinityTTL(d time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.affinityTTL = d
	if d <= 0 {
		p.affinity = make(map[string]affinityEntry)
	}
}

// activeCountLocked returns how many distinct active sessions are currently
// pinned to the given OAuth auth ID. Caller must hold p.mu.
func (p *Pool) activeCountLocked(authID string, now time.Time) int {
	cutoff := now.Add(-p.activeWindow)
	n := 0
	for _, s := range p.sessions {
		if s.authID == authID && s.kind == KindOAuth && !s.lastSeen.Before(cutoff) {
			n++
		}
	}
	return n
}

// clientFanoutsLocked maps each OAuth auth ID to the set of distinct client
// tokens currently pinned to it inside the active window. Caller must hold
// p.mu.
//
// The unit is the client TOKEN, not the session: one user running several CLI
// windows holds several slots on the same credential, and upstream reads that
// as one device with several concurrent sessions — the shape a real user
// produces. What does not look real is one subscription account serving many
// unrelated users at once, and that is what this counts.
//
// Built in a single pass and handed to pickOAuthLocked, so scheduling stays
// O(sessions) per Acquire rather than O(candidates x sessions). No new state is
// retained: the sessions map is already expired by gcLocked on the same
// activeWindow.
func (p *Pool) clientFanoutsLocked(now time.Time) map[string]map[string]struct{} {
	cutoff := now.Add(-p.activeWindow)
	out := make(map[string]map[string]struct{}, len(p.oauths))
	for _, s := range p.sessions {
		if s.authID == "" || s.kind != KindOAuth || s.lastSeen.Before(cutoff) {
			continue
		}
		set, ok := out[s.authID]
		if !ok {
			set = make(map[string]struct{}, 4)
			out[s.authID] = set
		}
		set[s.clientToken] = struct{}{}
	}
	return out
}

// AcquireOptions tunes credential selection beyond the positional arguments.
type AcquireOptions struct {
	// AllowAPIKeyFallback gates whether, when no OAuth credential in a tier is
	// usable, the pool may fall back to an API-key credential in that tier.
	// It also gates API-key-only models: when false, those models return no
	// credential instead of violating the caller's billing opt-in.
	// The plain Acquire wrapper sets this true (legacy behaviour); the SaaS
	// fork sets it from the client token's opt-in so users who haven't enabled
	// the upstream pool aren't silently served — and billed at a markup — by
	// upstream API keys.
	AllowAPIKeyFallback bool
	// APIKeyOnly skips OAuth selection entirely. It is used when a request was
	// rejected by a local OAuth preparation step and must be replayed from its
	// untouched original body through an API-key credential. The option still
	// requires AllowAPIKeyFallback so callers cannot bypass their billing opt-in.
	APIKeyOnly bool
	// ExcludeIDs are credential IDs to skip because the current request already
	// tried and failed them.
	ExcludeIDs []string
}

// AcquireResult reports how a credential was obtained, for callers that need
// to distinguish "scheduled normally" from "we had nothing left".
//
// It is returned only by AcquireWithResult. Acquire / AcquireWithOptions keep
// their exact historical signatures because both consuming forks call them
// positionally.
type AcquireResult struct {
	// LastResort is true when the returned credential was released by the
	// last-resort scan: every other candidate was gone and this one is still
	// inside a self-expiring cooldown (quota or circuit-breaker pause).
	//
	// The request is expected to have a materially worse success rate. Callers
	// should surface it (status page, log line, response header) but must NOT
	// treat it as an error — the alternative was a 503.
	LastResort bool
	// Reason explains the last-resort release. Empty when LastResort is false.
	Reason string
}

// Acquire is the back-compat entry point: it allows API-key fallback (the
// historical behaviour) and forwards excludeIDs. Callers that need to gate the
// fallback (e.g. per-token opt-in) should use AcquireWithOptions instead.
func (p *Pool) Acquire(ctx context.Context, provider, clientToken, clientGroup, clientModel, sessionID string, excludeIDs ...string) *Auth {
	return p.AcquireWithOptions(ctx, provider, clientToken, clientGroup, clientModel, sessionID, AcquireOptions{
		AllowAPIKeyFallback: true,
		ExcludeIDs:          excludeIDs,
	})
}

// AcquireWithOptions picks an Auth for this client token and stamps the session.
// clientGroup scopes credential selection: group-matching credentials are
// preferred, falling back to public ("") credentials when the group's
// credentials are exhausted. clientGroup == "" means public-only.
// provider restricts selection to credentials of that upstream provider
// (anthropic/openai) — sessions are keyed per (provider, clientToken,
// sessionID) so a token hitting both endpoints maintains independent
// stickiness.
//
// sessionID is the client-supplied per-window identifier (Claude Code's
// X-Claude-Code-Session-Id). Each distinct value is its own slot, so the same
// user opening another CLI window joins as a fresh session and is scheduled
// independently — potentially onto a different credential. Pass "" for clients
// that send no window identifier; the pool then keeps one slot per token.
//
// excludeIDs lets a retrying caller skip credentials it has already tried in
// the current request, so a transient connection error on one credential
// doesn't keep selecting the same one (the sticky-session logic would
// otherwise pin the client to the failing auth until its session times out).
//
// opts.AllowAPIKeyFallback gates the per-tier API-key fallback (see
// AcquireOptions); opts.ExcludeIDs is the retry skip-list.
func (p *Pool) AcquireWithOptions(ctx context.Context, provider, clientToken, clientGroup, clientModel, sessionID string, opts AcquireOptions) *Auth {
	a, _ := p.AcquireWithResult(ctx, provider, clientToken, clientGroup, clientModel, sessionID, opts)
	return a
}

// AcquireWithResult is AcquireWithOptions plus the provenance of the pick.
// It exists because the last-resort release (see the tail of this function)
// deliberately hands back a credential that is still inside a cooldown, and a
// caller that cannot tell that apart from a normal schedule would report a
// degraded pool as healthy.
//
// AcquireWithOptions — and therefore Acquire — delegate here and drop the
// second value, so every entry point shares one implementation.
func (p *Pool) AcquireWithResult(ctx context.Context, provider, clientToken, clientGroup, clientModel, sessionID string, opts AcquireOptions) (*Auth, AcquireResult) {
	provider = NormalizeProvider(provider)
	clientGroup = NormalizeGroup(clientGroup)
	excluded := make(map[string]bool, len(opts.ExcludeIDs))
	for _, id := range opts.ExcludeIDs {
		excluded[id] = true
	}
	sessionKey := slotKey(provider, clientToken, sessionID)

	// Tiers, in preference order:
	//   1. the client's own group, if it's a named non-shared group
	//   2. the shared pool = NEW ∪ public (same priority; load balancer
	//      picks the least-used candidate across both)
	// A client already scoped to "new" or public has only the shared tier.
	// Each tier is a set of allowed auth-group values.
	var tiers []map[string]bool
	if clientGroup != "" && clientGroup != "new" {
		tiers = append(tiers, map[string]bool{clientGroup: true})
	}
	tiers = append(tiers, map[string]bool{"new": true, "": true})
	allowed := func(authGroup string) bool {
		for _, t := range tiers {
			if t[authGroup] {
				return true
			}
		}
		return false
	}

	p.mu.Lock()
	now := time.Now()
	p.gcLocked(now)

	s, ok := p.sessions[sessionKey]
	if !ok {
		s = &session{clientToken: clientToken, sessionID: sessionID, provider: provider}
		// The slot expired but the conversation did not. Offer it the
		// credential it had, so a turn sent after a pause can still read its
		// prefix out of that account's prompt cache instead of re-uploading
		// it. Seeding s.authID rather than picking directly is what keeps this
		// honest: the sticky branch below re-validates health, group, model,
		// exclusion and free capacity exactly as it does for a live slot, and
		// an unusable memory costs nothing but a map lookup.
		if e, hit := p.affinity[sessionKey]; hit && now.Before(e.exp) {
			s.authID, s.kind = e.authID, KindOAuth
		}
		p.sessions[sessionKey] = s
	}

	// If session has a sticky OAuth assignment, it's still healthy, has
	// capacity for us, AND isn't on the exclude list, reuse it — but only
	// when the sticky credential still matches an allowed group AND, when
	// the client is group-scoped and currently sticky on public, no
	// group-scoped OAuth is available to upgrade to. Without that upgrade
	// check a group client stays pinned to public for the whole active
	// window even if its own credentials regain capacity.
	if !opts.APIKeyOnly && s.authID != "" && s.kind == KindOAuth && !excluded[s.authID] {
		if a := p.findOAuthLocked(s.authID); a != nil && allowed(a.Group) && NormalizeProvider(a.Provider) == provider && p.oauthUsableLocked(a, now, clientModel) {
			// Upgrade sticky pick to the client's own group when one becomes
			// available. Covers sticky=public and sticky=NEW both — they
			// live in the shared tier, so a group-scoped client prefers
			// its dedicated pool whenever it has slots. No upgrade for
			// clients already in the shared tier.
			upgrade := clientGroup != "" && clientGroup != "new" && a.Group != clientGroup &&
				p.pickOAuthLocked(now, excluded, map[string]bool{clientGroup: true}, provider, clientModel, clientToken) != nil
			if !upgrade {
				// Reusing an assignment we already hold a slot for: counts us
				// only once because activeCountLocked scans distinct sessions.
				s.lastSeen = now
				p.rememberAffinityLocked(sessionKey, a.ID, now)
				p.mu.Unlock()
				if err := a.EnsureFresh(ctx, 5*time.Minute, p.useUTLS); err != nil {
					log.Warnf("auth: ensure-fresh sticky %s failed, releasing: %v", a.ID, err)
					excluded[a.ID] = true
					p.mu.Lock()
					s.authID = ""
					// fall through to the pick loop below
				} else {
					return a, AcquireResult{}
				}
			} else {
				s.authID = ""
			}
		} else if s.authID != "" {
			// Previous OAuth is unhealthy/gone/group-disallowed; reassign.
			s.authID = ""
		}
	} else if opts.APIKeyOnly {
		// A local request-preparation failure must not bounce through more OAuth
		// credentials: the failure is about the request/identity binding, not an
		// upstream credential. Clear stickiness and proceed to API keys only.
		s.authID = ""
	} else if excluded[s.authID] {
		// Sticky pick was just tried and failed — release it so the next
		// pickOAuthLocked is free to pick anything else.
		s.authID = ""
	}

	// OAuth allocation, then API-key fallback. Each tier iterates: within a
	// tier we try OAuth first (slot-based scheduling), then any API key in
	// that tier. If the tier is empty or saturated, fall through to the
	// next tier (public).
	//
	// lastResortPool accumulates, across every tier, the API keys that were
	// rejected *only* because a self-expiring cooldown is open on them. It is
	// consulted after the loop — i.e. exactly when the pool would otherwise
	// return nil. See the round-two comment below.
	var lastResortPool []apiKeyCandidate
	for _, tier := range tiers {
		if !opts.APIKeyOnly {
			for {
				chosen := p.pickOAuthLocked(now, excluded, tier, provider, clientModel, clientToken)
				if chosen == nil {
					break
				}
				s.authID = chosen.ID
				s.kind = KindOAuth
				s.lastSeen = now
				p.rememberAffinityLocked(sessionKey, chosen.ID, now)
				p.mu.Unlock()
				if err := chosen.EnsureFresh(ctx, 5*time.Minute, p.useUTLS); err != nil {
					log.Warnf("auth: ensure-fresh %s failed, excluding: %v", chosen.ID, err)
					excluded[chosen.ID] = true
					p.mu.Lock()
					s.authID = ""
					continue
				}
				return chosen, AcquireResult{}
			}
		}
		// Per-token opt-in gate: when API-key fallback is disabled, never serve
		// from an API key. continue to the next tier (whose OAuth may still be
		// tried) rather than break — the gate re-applies there too, so no API
		// key is ever selected. OAuth selection above is unaffected.
		if !opts.AllowAPIKeyFallback {
			continue
		}
		// Round one: only fully-usable keys. A key paused by the circuit
		// breaker or sitting in a quota cooldown is skipped here so traffic
		// rotates onto a working channel instead of re-paying a doomed
		// upstream round-trip.
		ready, paused := p.eligibleAPIKeysLocked(now, excluded, tier, provider, clientModel)
		lastResortPool = append(lastResortPool, paused...)
		if k := pickReadyAPIKey(ready); k != nil {
			s.authID = k.ID
			s.kind = KindAPIKey
			s.lastSeen = now
			p.mu.Unlock()
			return k, AcquireResult{}
		}
	}

	// Round two — the last resort. We are here only because no OAuth
	// credential and no fully-usable API key exists for this request, so the
	// alternative to releasing a paused channel is handing the client a 503.
	//
	// Skipping the only channel that can serve a model is self-inflicted
	// downtime: with one key configured, the circuit breaker's ceiling (15m)
	// becomes the deployment's outage length, and the client sees hard errors
	// the whole time even if the upstream recovered a second after the pause
	// began. Backoff must therefore *lower a candidate's priority*, not remove
	// it from the candidate set. The routing layer lets the request through;
	// the health layer (HealthState / PoolHealth) still reports the channel red,
	// and AcquireResult.LastResort tells the caller which kind of pick this was.
	//
	// The exclusions above are NOT relaxed here — disabled is an explicit
	// operator action, hard-failed is a sticky retirement, an excluded ID was
	// already tried and failed in *this* request (relaxing it would make the
	// forks' retry loop hammer one dead key), and provider / tier / group-idle
	// are correctness boundaries, not health ones.
	if k, rep := pickLastResortAPIKey(lastResortPool); k != nil {
		s.authID = k.ID
		s.kind = KindAPIKey
		s.lastSeen = now
		p.mu.Unlock()
		reason := fmt.Sprintf("last-resort: no usable credential for provider %s; releasing paused api-key %s (%s)",
			provider, k.ID, rep.State)
		if rep.RetryAfter > 0 {
			reason += fmt.Sprintf(", %s early", rep.RetryAfter.Truncate(time.Second))
		}
		log.Warnf("auth: %s", reason)
		return k, AcquireResult{LastResort: true, Reason: reason}
	}

	p.mu.Unlock()
	return nil, AcquireResult{}
}

// apiKeyCandidate pairs an API key with the health picture used to rank it and
// its position in the pool's Order-sorted slice (the stable-sort tiebreaker).
type apiKeyCandidate struct {
	k   *Auth
	rep HealthReport
	idx int
}

// eligibleAPIKeysLocked splits the API keys of one tier into the ones that can
// serve right now (ready) and the ones blocked *only* by a self-expiring
// cooldown — quota or circuit-breaker pause (paused).
//
// Everything filtered out entirely is a hard boundary: wrong provider/tier,
// already tried in this request, operator-disabled, sticky hard-failed, group
// sleeping, or model not accepted. Those are never released, not even as a last
// resort. Callers hold p.mu.
func (p *Pool) eligibleAPIKeysLocked(now time.Time, excluded map[string]bool, tier map[string]bool, provider, clientModel string) (ready, paused []apiKeyCandidate) {
	for i, k := range p.apikeys {
		if NormalizeProvider(k.Provider) != provider {
			continue
		}
		if !tier[k.Group] {
			continue
		}
		if excluded[k.ID] {
			continue
		}
		if k.Disabled {
			continue
		}
		if k.IsHardFailed() {
			continue
		}
		if isGroupIdleNow(k.Group, now) {
			continue
		}
		// ModelMap is rewrite-only and never filters, so AcceptsModel
		// always passes here; the call is kept for symmetry in case
		// per-key routing is reintroduced.
		if !k.AcceptsModel(clientModel) {
			continue
		}
		// HealthState folds the quota and quarantine expiry checks (and clears
		// elapsed deadlines) into one locked read, so the two rounds can never
		// disagree about what "usable" means.
		c := apiKeyCandidate{k: k, rep: k.HealthState(), idx: i}
		if c.rep.Serving {
			ready = append(ready, c)
		} else {
			paused = append(paused, c)
		}
	}
	return ready, paused
}

// pickReadyAPIKey returns the highest-priority fully-usable key.
//
// Order is the operator's explicit intent and is never traded away: a key with
// a lower Order always wins. Within one Order value the pool used to return the
// first slice entry every time — API keys have no sticky sessions, so every
// request re-ran the same scan and re-picked the same key, and "several keys at
// the same priority" silently meant "one key plus spares". Ranking equal-Order
// keys by (quarantine strikes, last failure) makes the rotation real and
// self-correcting: the key that just failed sinks to the back of its own tier
// until it either recovers or the others fail too.
func pickReadyAPIKey(cands []apiKeyCandidate) *Auth {
	if len(cands) == 0 {
		return nil
	}
	sort.SliceStable(cands, func(i, j int) bool {
		ai, aj := cands[i], cands[j]
		if oi, oj := ai.k.OrderValue(), aj.k.OrderValue(); oi != oj {
			return oi < oj
		}
		if ai.rep.QuarantineStrikes != aj.rep.QuarantineStrikes {
			return ai.rep.QuarantineStrikes < aj.rep.QuarantineStrikes
		}
		if bi, bj := unverifiedFailureAt(ai.rep), unverifiedFailureAt(aj.rep); !bi.Equal(bj) {
			// Zero time sorts first: nothing outstanding beats an old unverified
			// failure beats one from a moment ago.
			return bi.Before(bj)
		}
		return ai.idx < aj.idx
	})
	return cands[0].k
}

// unverifiedFailureAt is the "when did this channel last look bad, with nothing
// since to say otherwise" timestamp used to rank equal-priority keys. A failure
// that has been followed by a success is not held against the channel at all —
// otherwise a key that recovered would stay demoted behind an untested one
// forever, which is the opposite of the rotation this ordering exists for.
func unverifiedFailureAt(r HealthReport) time.Time {
	if r.LastFailure.IsZero() || r.LastSuccess.After(r.LastFailure) {
		return time.Time{}
	}
	return r.LastFailure
}

// pickLastResortAPIKey chooses which paused channel to release: the one closest
// to coming back on its own — ascending RetryAfter, which is the direct measure
// of that distance. A zero RetryAfter means no deadline was reported (a quota
// flag with no reset time); it sorts first, since an unknown deadline is not
// evidence of a long one and strikes/Order then decide.
//
// Tier preference is already encoded in the append order of the candidate list
// (the caller walks tiers in preference order), and the sort below is stable,
// so a client's own group still outranks the shared pool at equal recovery
// distance.
func pickLastResortAPIKey(cands []apiKeyCandidate) (*Auth, HealthReport) {
	if len(cands) == 0 {
		return nil, HealthReport{}
	}
	sort.SliceStable(cands, func(i, j int) bool {
		ai, aj := cands[i], cands[j]
		if ai.rep.RetryAfter != aj.rep.RetryAfter {
			return ai.rep.RetryAfter < aj.rep.RetryAfter
		}
		if ai.rep.QuarantineStrikes != aj.rep.QuarantineStrikes {
			return ai.rep.QuarantineStrikes < aj.rep.QuarantineStrikes
		}
		if oi, oj := ai.k.OrderValue(), aj.k.OrderValue(); oi != oj {
			return oi < oj
		}
		return ai.idx < aj.idx
	})
	return cands[0].k, cands[0].rep
}

// AcquireMulti walks clientGroups in priority order, calling Acquire for each
// until one returns a non-nil credential. Returns the chosen group AND the
// credential, or ("", nil) if every group is exhausted.
//
// The returned group name tells the caller which group actually served the
// request — important for billing (discount lookup) and for the fork's
// dispatch logic (which upstream to forward to).
//
// excludeIDs propagates unchanged to every attempt, so a credential the caller
// already failed on isn't tried again in another group (rare, but possible when
// groups overlap). It cannot grow as we go: Acquire returning nil says nothing
// about which credentials it considered.
//
// Behavior is identical to Acquire when clientGroups has exactly one entry.
// An empty / nil clientGroups is treated as a single empty-string group
// (public pool).
func (p *Pool) AcquireMulti(ctx context.Context, provider, clientToken string, clientGroups []string, clientModel, sessionID string, excludeIDs ...string) (string, *Auth) {
	if len(clientGroups) == 0 {
		clientGroups = []string{""}
	}
	for _, g := range clientGroups {
		a := p.Acquire(ctx, provider, clientToken, g, clientModel, sessionID, excludeIDs...)
		if a != nil {
			return NormalizeGroup(g), a
		}
	}
	return "", nil
}

// AcquireMultiWithOptions is AcquireMulti with the AcquireOptions gate applied
// to every group attempt (opts.ExcludeIDs seeds the cross-group skip-list).
// Behaviour matches AcquireMulti when opts.AllowAPIKeyFallback is true.
func (p *Pool) AcquireMultiWithOptions(ctx context.Context, provider, clientToken string, clientGroups []string, clientModel, sessionID string, opts AcquireOptions) (string, *Auth) {
	if len(clientGroups) == 0 {
		clientGroups = []string{""}
	}
	for _, g := range clientGroups {
		a := p.AcquireWithOptions(ctx, provider, clientToken, g, clientModel, sessionID, AcquireOptions{
			AllowAPIKeyFallback: opts.AllowAPIKeyFallback,
			// APIKeyOnly must survive the fan-out. Dropping it here handed an
			// OAuth credential back to a caller replaying a request whose
			// identity rewrite had already failed — exactly the case the flag
			// exists to prevent.
			APIKeyOnly: opts.APIKeyOnly,
			ExcludeIDs: opts.ExcludeIDs,
		})
		if a != nil {
			return NormalizeGroup(g), a
		}
	}
	return "", nil
}

// Release stamps the session as seen right now (call at end of request).
// This extends its active window. provider and sessionID must match the ones
// used on the paired Acquire — sessions are scoped per (provider, clientToken,
// sessionID).
func (p *Pool) Release(provider, clientToken, sessionID string) {
	provider = NormalizeProvider(provider)
	p.mu.Lock()
	defer p.mu.Unlock()
	if s, ok := p.sessions[slotKey(provider, clientToken, sessionID)]; ok {
		s.lastSeen = time.Now()
	}
}

// SessionsHeld reports how many live pool slots this client token currently
// occupies for the given provider, and whether sessionID is already one of
// them.
//
// A pool slot is the scarce resource behind a credential's max_concurrent, and
// slots are NOT held for equal durations: an HTTP request holds one for
// seconds, while a long-lived WebSocket session (the real codex-tui transport)
// holds one for as long as the socket is open — up to an hour. A handful of WS
// users can therefore sit on most of a provider's total slot capacity, and
// every other client starts getting "no credentials available" even though the
// fleet is perfectly healthy.
//
// Callers use this to enforce a per-token fair-share cap before acquiring, and
// — because `already` distinguishes a brand-new slot from one this session
// already owns — to let an established session keep working while only new
// ones are refused. The policy and the client-facing message live with the
// caller, since a WS handshake and an HTTP request reject differently.
func (p *Pool) SessionsHeld(provider, clientToken, sessionID string) (held int, already bool) {
	provider = NormalizeProvider(provider)
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	p.gcLocked(now)
	want := slotKey(provider, clientToken, sessionID)
	for k, s := range p.sessions {
		if s.provider != provider || s.clientToken != clientToken {
			continue
		}
		held++
		if k == want {
			already = true
		}
	}
	return held, already
}

// Unstick clears the sticky credential binding for a client session so the
// next Acquire picks a fresh credential. Call this when the current credential
// returned an upstream error — otherwise the client keeps hitting the same
// failing auth until the session expires. provider and sessionID must match
// Acquire.
func (p *Pool) Unstick(provider, clientToken, sessionID string) {
	provider = NormalizeProvider(provider)
	p.mu.Lock()
	defer p.mu.Unlock()
	key := slotKey(provider, clientToken, sessionID)
	if s, ok := p.sessions[key]; ok {
		s.authID = ""
	}
	// Unstick means this credential misbehaved for this conversation. Keeping
	// it in the affinity memory would hand it straight back on the next turn,
	// so the memory has to go with the binding.
	delete(p.affinity, key)
}

func (p *Pool) findOAuthLocked(id string) *Auth {
	for _, a := range p.oauths {
		if a.ID == id {
			return a
		}
	}
	return nil
}

// oauthUsableLocked is the routing-side gate, and it is deliberately NOT
// IsHealthy(). It excludes only the states that make a request certain to fail
// or forbidden to send — disabled, hard-failed, in cooldown, rate-limited for
// this model family, group asleep — and lets a merely *degraded* credential
// (ConsecutiveFailures >= 2, short of the hard-fail threshold) keep taking
// traffic.
//
// That asymmetry is the point. IsHealthy's degraded window is an admin-panel
// and reporting judgement; making it a routing filter is what caused the
// 2026-07-14 outage, where one upstream flap degraded every credential in a
// pool at the same instant and Acquire had nobody left to return. Skipping a
// degraded credential is only safe if some other credential is available, and
// the scheduler cannot know that here. Failing a request on a degraded
// credential costs one retry; returning nil costs the client a 503.
//
// The degraded state still does its job: it feeds HealthSnapshot, and repeated
// failures walk ConsecutiveFailures up to hardFailureThreshold, which this
// function does honour.
func (p *Pool) oauthUsableLocked(a *Auth, now time.Time, clientModel string) bool {
	// Fable on subscription OAuth is a PER-CREDENTIAL entitlement, not a
	// service-wide rule: a claude_max bootstrap lists claude-fable-5[1m] with
	// disabled_reason=null and carries an independent weekly allotment, while a
	// non-entitled account answers credits_required. Both facts belong to one
	// credential, so the correct filter is the model-scoped cooldown below —
	// set on whichever credential actually refused. This blanket check answers
	// false unless AnthropicFableOAuthDisabled is on.
	//
	// It stays on the FIRST line because when it is on it must also break an
	// existing sticky OAuth binding, not just new picks.
	if NormalizeProvider(a.Provider) == ProviderAnthropic && AnthropicModelRequiresAPIKey(clientModel) {
		return false
	}
	if a.Disabled {
		return false
	}
	if a.IsHardFailed() {
		return false
	}
	if a.IsQuotaExceeded(now) {
		return false
	}
	// Per-model overage window (e.g. Anthropic fable's 7d_oi bucket): skip this
	// credential only for the limited model family. The account stays healthy
	// and schedulable for every other model — that's the whole point of a
	// model-scoped limit vs. IsQuotaExceeded's account-wide flag.
	if scope := AnthropicModelScope(clientModel); scope != "" && a.IsModelRateLimited(scope, now) {
		return false
	}
	// Group-level scheduled downtime (e.g. "new" group drops 10 random
	// whole-hour windows per local day). Behaves like a transient quota
	// miss — credential reappears on the next hour boundary.
	if isGroupIdleNow(a.Group, now) {
		return false
	}
	return true
}

// pickOAuthLocked returns the OAuth in the requested group with the lowest
// cost-weighted recent token consumption (default: last ~5h, to match
// Anthropic's rolling quota window) that still has a free slot and isn't
// on the exclude list, or nil if none available. Unlimited credentials
// (cap=0) always have room. excluded may be nil. group is an exact match;
// "" is the public tier.
//
// Candidates are ordered by client fan-out first, then by weighted
// recent-window usage (see usage.Counts.WeightedTotal), then by ID.
//
// Fan-out leads because upstream sheds load per account, and in production the
// shed rate tracked how many distinct client tokens an account was serving far
// more closely than how much traffic it carried: accounts serving 2-5 tokens
// shed ~0% while accounts serving 13-17 shed 40%+, at comparable request
// volume and prompt size. One subscription account fielding 17 unrelated users
// at once is not a shape a real user produces.
//
// This is an ORDERING, deliberately not a cap. A hard per-account fan-out limit
// would return nil once every account reached it, turning a busy minute into a
// 503; ordering can never exhaust the candidate set, it only decides who goes
// first. With N healthy accounts and M active tokens, fan-out converges on
// ceil(M/N) on its own.
//
// Usage remains the tie-break, so among accounts at equal fan-out the load
// balancer still spreads work toward credentials doing less real work —
// cache-heavy clients don't starve a credential out just by racking up
// near-free cache_read volume.
//
// Fan-out is measured as it would be AFTER clientToken joins: a token already
// present on a candidate adds nothing, so a returning user's extra windows
// prefer the account they are already on. That keeps a single user's sessions
// together (and their prompt cache warm) while spreading distinct users apart.
//
// This is reached only when the session has no usable sticky assignment, so
// reordering here never migrates an established session off its credential.
func (p *Pool) pickOAuthLocked(now time.Time, excluded map[string]bool, allowedGroups map[string]bool, provider, clientModel, clientToken string) *Auth {
	fanouts := p.clientFanoutsLocked(now)
	type cand struct {
		a      *Auth
		fanout int   // distinct client tokens this auth would serve with us on it
		load   int64 // weighted tokens consumed in the recent load-balancing window (0 if unknown)
	}
	var cands []cand
	for _, a := range p.oauths {
		if !allowedGroups[a.Group] {
			continue
		}
		if NormalizeProvider(a.Provider) != provider {
			continue
		}
		if excluded[a.ID] {
			continue
		}
		if !p.oauthUsableLocked(a, now, clientModel) {
			continue
		}
		active := p.activeCountLocked(a.ID, now)
		capN := a.MaxConcurrent
		if capN > 0 && active >= capN {
			continue
		}
		var used int64
		if p.usageLoad != nil {
			used = p.usageLoad(a.ID)
		}
		tokens := fanouts[a.ID]
		fanout := len(tokens)
		if _, already := tokens[clientToken]; !already {
			fanout++
		}
		cands = append(cands, cand{a: a, fanout: fanout, load: used})
	}
	if len(cands) == 0 {
		return nil
	}
	sort.SliceStable(cands, func(i, j int) bool {
		if cands[i].fanout != cands[j].fanout {
			return cands[i].fanout < cands[j].fanout
		}
		if cands[i].load != cands[j].load {
			return cands[i].load < cands[j].load
		}
		return cands[i].a.ID < cands[j].a.ID
	})
	return cands[0].a
}

// Status returns a snapshot of all auths and their current active counts.
// ClientTokens holds the raw client tokens currently holding a slot; callers
// decide whether to mask or resolve them to display names.
type Status struct {
	Auth          AuthInfo
	ActiveClients int
	ClientTokens  []string
}

func (p *Pool) Status() []Status {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	p.gcLocked(now)
	out := make([]Status, 0, len(p.oauths)+len(p.apikeys))
	for _, a := range p.oauths {
		active := 0
		var tokens []string
		for _, s := range p.sessions {
			if s.authID == a.ID {
				active++
				tokens = append(tokens, s.clientToken)
			}
		}
		out = append(out, Status{Auth: a.Snapshot(), ActiveClients: active, ClientTokens: tokens})
	}
	for _, a := range p.apikeys {
		active := 0
		var tokens []string
		for _, s := range p.sessions {
			if s.authID == a.ID {
				active++
				tokens = append(tokens, s.clientToken)
			}
		}
		out = append(out, Status{Auth: a.Snapshot(), ActiveClients: active, ClientTokens: tokens})
	}
	return out
}

// AuthLabelInfo carries the current display identity for an auth ID.
// Returned by Pool.LabelIndex so callers can rewrite snapshot labels in
// append-only records to the current value in a single pass.
type AuthLabelInfo struct {
	Label string
	Kind  Kind
}

// LabelIndex returns authID → current (Label, Kind) for every live credential.
// Used to overwrite snapshot labels in request-log entries so renames are
// reflected in display-facing responses. One lock, one pass.
func (p *Pool) LabelIndex() map[string]AuthLabelInfo {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make(map[string]AuthLabelInfo, len(p.oauths)+len(p.apikeys))
	for _, a := range p.oauths {
		out[a.ID] = AuthLabelInfo{Label: a.Label, Kind: a.Kind}
	}
	for _, a := range p.apikeys {
		out[a.ID] = AuthLabelInfo{Label: a.Label, Kind: a.Kind}
	}
	return out
}

// MaskToken returns a display-safe form of a client token. Exposed so admin /
// status consumers can render without leaking the full secret.
func MaskToken(t string) string {
	if len(t) <= 8 {
		return "***"
	}
	return t[:4] + "..." + t[len(t)-4:]
}

// HasAPIKeyFor reports whether any API-key credential in the pool can serve
// this (provider, clientGroup, model) tuple — including as a last resort.
//
// It mirrors AcquireWithResult's two rounds exactly, by running the same
// eligibility split: a key counts when it is fully usable now, and it also
// counts when it is merely paused by a self-expiring cooldown (quota or the
// circuit breaker), because Acquire will release such a key rather than return
// nil once nothing else is left. Only the hard boundaries make the answer
// false: wrong provider, wrong tier, operator-disabled, sticky hard-failed,
// group asleep, or AcceptsModel(model) == false.
//
// Keeping the two in step is the whole point of the function. Previously it
// checked quota but not IsQuarantined, so a quarantined key made this return
// true while Acquire returned nil, and the proxy's fail-fast pre-check
// promised a route it could not serve.
//
// Groups are checked in the same preference order as Acquire: client group
// first (if non-empty), then the shared tier. Used by the proxy to fail-fast on
// routes (e.g. chat/completions) that OAuth credentials cannot serve, rather
// than cycling the retry loop to a misleading 503.
func (p *Pool) HasAPIKeyFor(provider, clientGroup, model string) bool {
	provider = NormalizeProvider(provider)
	clientGroup = NormalizeGroup(clientGroup)
	// Same tiering policy as Acquire — client's named group (if any),
	// then the shared tier = NEW ∪ public.
	var tiers []map[string]bool
	if clientGroup != "" && clientGroup != "new" {
		tiers = append(tiers, map[string]bool{clientGroup: true})
	}
	tiers = append(tiers, map[string]bool{"new": true, "": true})
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	for _, tier := range tiers {
		// nil excluded: this is a pre-flight question about the pool, not about
		// one in-flight request's already-tried set.
		ready, paused := p.eligibleAPIKeysLocked(now, nil, tier, provider, model)
		if len(ready) > 0 || len(paused) > 0 {
			return true
		}
	}
	return false
}

// Health aggregates the per-credential HealthState of every credential of one
// provider — OAuth and API keys together, since a status page asks "can this
// provider serve traffic", and the answer routinely depends on the API keys
// alone (Fable-class models never touch OAuth) or on the OAuth pool alone (no
// keys configured).
//
// Read PoolHealth.Available() for "is the service up" and PoolHealth.ByState
// for what to render. Available() staying true while ByState is all half-open
// is not a contradiction: that is precisely the state a last-resort Acquire
// serves from.
func (p *Pool) Health(provider string) PoolHealth {
	provider = NormalizeProvider(provider)
	p.mu.Lock()
	creds := make([]*Auth, 0, len(p.oauths)+len(p.apikeys))
	for _, a := range p.oauths {
		if NormalizeProvider(a.Provider) == provider {
			creds = append(creds, a)
		}
	}
	for _, a := range p.apikeys {
		if NormalizeProvider(a.Provider) == provider {
			creds = append(creds, a)
		}
	}
	p.mu.Unlock()
	// Reports are taken outside p.mu: HealthState takes the credential's own
	// lock and nothing here needs the two held together.
	reports := make([]HealthReport, 0, len(creds))
	for _, a := range creds {
		reports = append(reports, a.HealthState())
	}
	return NewPoolHealth(provider, reports)
}

// FindByID returns the Auth (OAuth or APIKey) with the given ID, or nil.
func (p *Pool) FindByID(id string) *Auth {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, a := range p.oauths {
		if a.ID == id {
			return a
		}
	}
	for _, a := range p.apikeys {
		if a.ID == id {
			return a
		}
	}
	return nil
}

// AddOAuth registers a newly uploaded OAuth credential into the live pool.
// Any existing auth with the same ID is replaced.
func (p *Pool) AddOAuth(a *Auth) error {
	if a == nil || a.Kind != KindOAuth {
		return errors.New("invalid OAuth credential")
	}
	a.ProxyURL = strings.TrimSpace(a.ProxyURL)
	if err := ValidateProxyURL(a.ProxyURL); err != nil {
		return fmt.Errorf("proxy_url: %w", err)
	}
	if a.ProxyURL == "" && p.defaultProxy != "" {
		a.ProxyURL = strings.TrimSpace(p.defaultProxy)
		if err := ValidateProxyURL(a.ProxyURL); err != nil {
			return fmt.Errorf("default proxy_url: %w", err)
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, existing := range p.oauths {
		if existing.ID != a.ID && sameAnthropicOAuthAccount(existing, a) {
			return fmt.Errorf("%w: %s conflicts with %s", ErrDuplicateClaudeAccountUUID, a.ID, existing.ID)
		}
	}
	for i, existing := range p.oauths {
		if existing.ID == a.ID {
			p.oauths[i] = a
			return nil
		}
	}
	p.oauths = append(p.oauths, a)
	return nil
}

func sameAnthropicOAuthAccount(old, replacement *Auth) bool {
	if old == nil || replacement == nil || old.Kind != KindOAuth || replacement.Kind != KindOAuth ||
		NormalizeProvider(old.Provider) != ProviderAnthropic || NormalizeProvider(replacement.Provider) != ProviderAnthropic {
		return false
	}
	oldUUID := strings.TrimSpace(old.AccountUUIDValue())
	newUUID := strings.TrimSpace(replacement.AccountUUIDValue())
	if oldUUID != "" || newUUID != "" {
		return oldUUID != "" && newUUID != "" && oldUUID == newUUID
	}
	oldEmail := strings.TrimSpace(old.Snapshot().Email)
	newEmail := strings.TrimSpace(replacement.Snapshot().Email)
	return oldEmail != "" && newEmail != "" && strings.EqualFold(oldEmail, newEmail)
}

// AddAPIKey registers an API-key credential into the live pool. Replaces
// any existing entry with the same ID.
func (p *Pool) AddAPIKey(a *Auth) {
	if a == nil || a.Kind != KindAPIKey {
		return
	}
	if a.ProxyURL == "" && p.defaultProxy != "" {
		a.ProxyURL = p.defaultProxy
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, existing := range p.apikeys {
		if existing.ID == a.ID {
			p.apikeys[i] = a
			sortAPIKeysLocked(p.apikeys)
			return
		}
	}
	p.apikeys = append(p.apikeys, a)
	sortAPIKeysLocked(p.apikeys)
}

// ReorderAPIKeys assigns selection priority to API-key credentials by the given
// ID sequence: orderedIDs[0] becomes the highest-priority key, [1] the next,
// and so on. IDs not present in the pool are ignored; API keys whose ID is
// absent from orderedIDs keep their relative order after the listed ones.
// The pool's apikeys slice is re-sorted and each credential whose Order changed
// is persisted to disk. Returns the first persistence error encountered (the
// in-memory order is still updated regardless).
func (p *Pool) ReorderAPIKeys(orderedIDs []string) error {
	rank := make(map[string]int, len(orderedIDs))
	for i, id := range orderedIDs {
		if _, dup := rank[id]; dup {
			continue
		}
		rank[id] = i
	}

	p.mu.Lock()
	// Unlisted keys sort after every listed one, preserving their prior
	// relative order (stable sort + a shared sentinel rank).
	tail := len(orderedIDs)
	var touched []*Auth
	for _, a := range p.apikeys {
		want := tail
		if r, ok := rank[a.ID]; ok {
			want = r
		}
		if a.OrderValue() != want {
			a.SetOrder(want)
			touched = append(touched, a)
		}
	}
	sortAPIKeysLocked(p.apikeys)
	p.mu.Unlock()

	// Persist outside p.mu — saveAuth does file IO and only takes a.mu.
	var firstErr error
	for _, a := range touched {
		if err := a.Persist(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// RemoveOAuth detaches an OAuth credential from the pool and drops any
// sticky sessions assigned to it. Returns the removed auth or nil.
func (p *Pool) RemoveOAuth(id string) *Auth {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, a := range p.oauths {
		if a.ID == id {
			p.oauths = append(p.oauths[:i], p.oauths[i+1:]...)
			for k, s := range p.sessions {
				if s.authID == id {
					delete(p.sessions, k)
				}
			}
			return a
		}
	}
	return nil
}

// RemoveAuth detaches any credential (OAuth or API-key) by ID.
func (p *Pool) RemoveAuth(id string) *Auth {
	p.mu.Lock()
	for i, a := range p.apikeys {
		if a.ID == id {
			p.apikeys = append(p.apikeys[:i], p.apikeys[i+1:]...)
			for k, s := range p.sessions {
				if s.authID == id {
					delete(p.sessions, k)
				}
			}
			p.mu.Unlock()
			return a
		}
	}
	p.mu.Unlock()
	return p.RemoveOAuth(id)
}

// RefreshExpiring proactively refreshes any OAuth credential whose access
// token will expire within `leeway`. Skips disabled and hard-failed creds —
// those need manual intervention. Errors are logged, not returned: this is a
// best-effort background pass.
func (p *Pool) RefreshExpiring(ctx context.Context, leeway time.Duration) {
	p.mu.Lock()
	targets := make([]*Auth, 0, len(p.oauths))
	for _, a := range p.oauths {
		if a.Disabled || a.IsHardFailed() {
			continue
		}
		targets = append(targets, a)
	}
	p.mu.Unlock()
	for _, a := range targets {
		if err := a.EnsureFresh(ctx, leeway, p.useUTLS); err != nil {
			log.Warnf("auth: background refresh %s: %v", a.ID, err)
		}
	}
}

// RunRefresher launches a ticker that periodically calls RefreshExpiring.
// Returns when ctx is cancelled. Intended to run in its own goroutine.
func (p *Pool) RunRefresher(ctx context.Context, interval, leeway time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	if leeway <= 0 {
		leeway = 10 * time.Minute
	}
	// Kick once immediately so a fresh start doesn't wait `interval` before
	// noticing tokens that are already past leeway.
	p.RefreshExpiring(ctx, leeway)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.RefreshExpiring(ctx, leeway)
		}
	}
}

// ResetUnhealthyAnthropicAPIKeys clears hard-failure / transient-failure /
// quota-cooldown state on every Anthropic API-key credential that is
// currently unhealthy (excluding admin-disabled creds — those are an
// explicit operator action). Returns the number of credentials reset.
//
// Intended to be invoked at local midnight by RunDailyAnthropicAPIKeyReset
// so a credential the proxy has parked after consecutive upstream errors
// gets a fresh shot the next day without manual admin intervention. OAuth
// credentials and OpenAI API keys are intentionally left alone.
func (p *Pool) ResetUnhealthyAnthropicAPIKeys() int {
	p.mu.Lock()
	keys := make([]*Auth, 0, len(p.apikeys))
	for _, a := range p.apikeys {
		if NormalizeProvider(a.Provider) != ProviderAnthropic {
			continue
		}
		keys = append(keys, a)
	}
	p.mu.Unlock()
	n := 0
	for _, a := range keys {
		a.mu.RLock()
		disabled := a.Disabled
		a.mu.RUnlock()
		if disabled {
			continue
		}
		if a.IsHealthy() {
			continue
		}
		a.ClearFailure()
		a.ClearQuota()
		log.Infof("auth: midnight reset cleared unhealthy Anthropic api-key %s", a.ID)
		n++
	}
	return n
}

// RunDailyAnthropicAPIKeyReset wakes at the next local-midnight boundary
// and calls ResetUnhealthyAnthropicAPIKeys, then repeats every 24h. Returns
// when ctx is cancelled. Intended to run in its own goroutine.
func (p *Pool) RunDailyAnthropicAPIKeyReset(ctx context.Context) {
	for {
		now := time.Now()
		next := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()).Add(24 * time.Hour)
		timer := time.NewTimer(next.Sub(now))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
			if n := p.ResetUnhealthyAnthropicAPIKeys(); n > 0 {
				log.Infof("auth: midnight reset cleared %d unhealthy Anthropic api-key credential(s)", n)
			}
		}
	}
}

// ReportUpstreamError inspects an upstream HTTP error status and marks the
// credential as temporarily unavailable (so Acquire picks a different auth
// on the next attempt). Only hard quota / auth errors set a cooldown; transient
// gateway errors are recorded without cooldown so the credential remains
// available for immediate retry:
//
//	429  → Retry-After (if given) or 30s   (rate limit — usually transient)
//	403  → Retry-After (if given) or 1m    (could be quota or auth-forbidden)
//	401  → 1m                              (token revoked/invalid)
//	529  → MarkFailure only (no cooldown; Anthropic overloaded, transient)
//	5xx  → MarkFailure only (no cooldown; transient gateway error)
//
// The admin panel's "Clear quota" button lets you drop the flag early.
func (p *Pool) ReportUpstreamError(a *Auth, status int, resetAt time.Time) {
	if a == nil {
		return
	}
	now := time.Now()
	setCooldown := func(d time.Duration) {
		until := resetAt
		if until.IsZero() {
			until = now.Add(d)
		}
		a.MarkQuotaExceeded(until)
		log.Warnf("auth: %s flagged unavailable until %s (status %d)", a.ID, until.Format(time.RFC3339), status)
	}
	switch {
	case status == 429:
		// Track repeated 429s separately: Anthropic occasionally hides
		// bans behind perpetual 429s. After enough back-to-back 429s
		// without any success, MarkRateLimited promotes to sticky
		// hard-failure so the credential stops cycling through cooldown.
		// resetAt is forwarded so the API-key circuit breaker can tell an
		// upstream that told us when to come back from one that simply
		// refused. A relay answering "429, retry in 12s" is working as
		// designed and must not accrue a strike for it; only an unexplained
		// refusal is evidence we should stop trusting the channel. OAuth is
		// unaffected either way — its stealth-ban counter advances on both.
		n := a.MarkRateLimitedRetryAfter(fmt.Sprintf("upstream %d (rate limited)", status), resetAt)
		// Most 429s from Anthropic are transient rate limits (RPM/TPM),
		// NOT true quota exhaustion. A 10-minute freeze is far too
		// aggressive — it takes the credential offline long after the
		// rate window has reset. Use a short default; if the upstream
		// sends a meaningful Retry-After we'll honour it instead.
		//
		// As consecutive 429s pile up without any success, the cooldown
		// grows exponentially so the credential stops being re-routed
		// to within seconds of every 30s "ready now" tick — that
		// rapid-cycle behavior is what makes a stealth-banned account
		// look like a degraded one in the panel until the 15-strike
		// hard-failure finally fires. Capped at 10 minutes.
		setCooldown(rateLimit429Cooldown(n))
	case status == 403:
		setCooldown(1 * time.Minute)
	case status == 401:
		// Don't honor Retry-After for auth failures — it's typically a rate
		// limit hint unrelated to the bad credential.
		resetAt = time.Time{}
		setCooldown(1 * time.Minute)
	case status == 529:
		// Anthropic overloaded — transient, no cooldown needed; just mark
		// the failure so the admin panel can see it.
		a.MarkFailure(fmt.Sprintf("upstream %d (overloaded)", status))
	case status >= 500:
		a.MarkFailure(fmt.Sprintf("upstream %d", status))
	}
}

// rateLimit429Cooldown returns the per-credential cooldown duration after
// the n-th consecutive 429 with no intervening success. Grows from 30s up
// to a 10-minute cap so a stealth-banned credential isn't recycled back
// into rotation within seconds of every "ready now" tick. Used only when
// the upstream did NOT supply a Retry-After header.
//
//	n=1   → 30s
//	n=2   → 1m
//	n=3   → 2m
//	n=4   → 5m
//	n>=5  → 10m
func rateLimit429Cooldown(n int) time.Duration {
	switch {
	case n <= 1:
		return 30 * time.Second
	case n == 2:
		return 1 * time.Minute
	case n == 3:
		return 2 * time.Minute
	case n == 4:
		return 5 * time.Minute
	default:
		return 10 * time.Minute
	}
}
