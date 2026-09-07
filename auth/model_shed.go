package auth

import (
	"strings"
	"time"
)

// Per-(credential, model) memory of upstream capacity shedding, used to order
// the scheduler's candidates rather than to remove any of them.
//
// A capacity shed is upstream saying "the selected model is at capacity" inside
// an otherwise-200 stream. It is emphatically NOT a statement about the
// credential: measured on production, one account shed gpt-6-astra on 5% of
// turns while another shed it on 72% in the same ten minutes, and both served
// gpt-5.6-sol in that window with a 0.7% shed rate. So the signal is real and
// worth acting on, but it is scoped to (account, model, roughly-now).
//
// This is deliberately NOT ModelRateLimits. That is a quota signal and a hard
// skip: a credential out of its fable overage window genuinely cannot serve the
// model, so removing it from the candidate set is correct. A capacity shed is a
// probability, not a fact — during a bad window EVERY account sheds the model,
// and a hard skip would empty the pool and turn a slow-but-working model into a
// 503. Ordering has no such failure mode: with every candidate penalised the
// sort is a no-op and the request still goes somewhere.
//
// The state is process-local and never persisted. It describes upstream's
// capacity a minute ago, which a restart is right to forget.

// modelShedBaseTTL is how long one shed keeps a credential demoted for that
// model. Long enough to outlast the burst that produced it, short enough that a
// credential which recovers is not left in the back of the queue: production
// sheds cluster over minutes, not hours.
const modelShedBaseTTL = 90 * time.Second

// modelShedMaxTTL caps the escalation. Past this the account is not telling us
// anything a longer memory would improve on, and an unbounded window would
// outlive the capacity condition it describes.
const modelShedMaxTTL = 10 * time.Minute

// modelShedState is one (credential, model) scope's shedding history.
type modelShedState struct {
	until  time.Time
	streak int // consecutive sheds without an intervening success
}

// ModelShedScope is the key a shed is remembered under: provider-qualified and
// case-normalised, so "OpenAI/GPT-6-Astra" and "gpt-6-astra" share one entry.
// An empty model yields an empty scope, which every method treats as "no
// opinion" — a caller without a model name must not silently penalise anything.
func ModelShedScope(provider, model string) string {
	normalized := strings.ToLower(strings.TrimSpace(model))
	if i := strings.IndexByte(normalized, '/'); i >= 0 {
		normalized = normalized[i+1:]
	}
	if normalized == "" {
		return ""
	}
	return NormalizeProvider(provider) + ":" + normalized
}

// MarkModelShed records that upstream shed this model on this credential.
//
// Repeat sheds without an intervening success escalate the window
// (90s, 3min, 6min, capped at 10min): an account that sheds a model four times
// running is more informative than one that shed it once, and should stay at
// the back of the queue for longer.
func (a *Auth) MarkModelShed(model string, now time.Time) {
	scope := ModelShedScope(a.Provider, model)
	if scope == "" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.modelSheds == nil {
		a.modelSheds = make(map[string]modelShedState, 1)
	}
	state := a.modelSheds[scope]
	if !state.until.After(now) {
		// The previous window had already lapsed, so this is a fresh burst
		// rather than a continuing one. Escalation restarts.
		state.streak = 0
	}
	state.streak++
	ttl := modelShedBaseTTL * time.Duration(1<<uint(min(state.streak-1, 8)))
	if ttl > modelShedMaxTTL {
		ttl = modelShedMaxTTL
	}
	state.until = now.Add(ttl)
	a.modelSheds[scope] = state
}

// NoteModelServed records that this credential served the model without being
// shed, clearing its penalty immediately.
//
// Clearing on success rather than only on expiry is what keeps this from
// becoming a slow-decaying blocklist. Capacity comes back abruptly — the
// account that shed four turns in a row will serve the fifth normally — and a
// credential that has just demonstrated it can serve the model should compete
// on equal terms for the next one.
func (a *Auth) NoteModelServed(model string) {
	scope := ModelShedScope(a.Provider, model)
	if scope == "" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.modelSheds == nil {
		return
	}
	delete(a.modelSheds, scope)
}

// ModelShedPenalty reports how heavily this credential should be demoted when
// choosing where to send `model` right now: 0 for no recent shed, otherwise the
// consecutive-shed streak. Expired entries are pruned as a side effect.
//
// The scheduler treats this as the FIRST sort key, ahead of fan-out and load.
// It never removes a candidate, so a pool where every credential is shedding
// orders by streak and then behaves exactly as it did before this existed.
func (a *Auth) ModelShedPenalty(model string, now time.Time) int {
	scope := ModelShedScope(a.Provider, model)
	if scope == "" {
		return 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	state, ok := a.modelSheds[scope]
	if !ok {
		return 0
	}
	if !state.until.After(now) {
		delete(a.modelSheds, scope)
		return 0
	}
	return state.streak
}
