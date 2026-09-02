package auth

import (
	"fmt"
	"time"
)

// HealthState is the credential-local health classification that display and
// alerting layers render. It replaces the (healthy, hardFailure) boolean pair
// that HealthSnapshot returns, which could not distinguish four situations
// that demand four different operator reactions:
//
//   - a channel paused by the circuit breaker and due back in 30s,
//   - a channel whose pause just expired and has NOT yet proven it recovered,
//   - a channel failing right now but still taking traffic,
//   - a channel that is genuinely fine.
//
// Collapsing those into one bool is what let the panel paint a channel green
// the instant its quarantine deadline elapsed — before a single successful
// request had confirmed anything. HealthHalfOpen exists specifically to make
// that state visible and un-green.
//
// HealthSnapshot keeps its original signature and behaviour; both consuming
// forks destructure it positionally, so it must not change. Use HealthState()
// for anything new.
type HealthState string

const (
	// HealthDisabled — an operator turned this credential off. Terminal until
	// a human turns it back on.
	HealthDisabled HealthState = "disabled"
	// HealthHardFailed — sticky auto-retirement (OAuth only; API keys are never
	// hard-failed sticky). Needs ClearFailure to return.
	HealthHardFailed HealthState = "hard_failed"
	// HealthQuota — account-wide cooldown from a 429/403/usage-limit signal.
	// Self-clearing at QuotaResetAt.
	HealthQuota HealthState = "quota"
	// HealthCooling — API-key circuit breaker is open; the channel is paused
	// and will be offered again at QuarantineUntil.
	HealthCooling HealthState = "cooling"
	// HealthHalfOpen — the pause elapsed and the channel is routable again, but
	// nothing has succeeded on it since the failure that opened the circuit.
	// It is a candidate, not a recovery. Never render this green.
	HealthHalfOpen HealthState = "half_open"
	// HealthDegraded — failing recently and unverified since, but still below
	// every threshold that would take it out of rotation. Routing deliberately
	// keeps sending traffic here (see Pool.oauthUsableLocked); the state exists
	// so the panel can show the deterioration before it becomes an outage.
	HealthDegraded HealthState = "degraded"
	// HealthHealthy — no failure, or a success after the last failure, or an
	// isolated stale failure past the grace window.
	HealthHealthy HealthState = "healthy"
)

// Severity orders states from best to worst for aggregation ("what is the
// worst thing happening in this pool"). Higher is worse.
//
// HealthDisabled sits just above HealthHealthy rather than at the top, because
// the question this ladder answers is about faults and a disabled credential
// is not one — it is an operator who switched something off on purpose. Ranked
// worst it outranked every real failure, so a pool of {3 healthy, 3
// hard_failed, 2 disabled} reported its worst state as "disabled" and the
// three retired credentials vanished from the headline. That string is
// user-visible in two places, both of them the moment you most need the truth:
// the 503 body when a pool is exhausted ("no credential can serve (worst
// state: …)") and the monitor's per-provider error line.
func (s HealthState) Severity() int {
	switch s {
	case HealthHealthy:
		return 0
	case HealthDisabled:
		return 1
	case HealthHalfOpen:
		return 2
	case HealthDegraded:
		return 3
	case HealthQuota:
		return 4
	case HealthCooling:
		return 5
	case HealthHardFailed:
		return 6
	}
	return 0
}

// HealthReport is the full credential-local health picture. Every field is a
// plain value copied under the lock, so callers may hold it indefinitely.
type HealthReport struct {
	State HealthState

	// Serving reports whether this credential can take a request right now,
	// judged on credential-local state alone.
	//
	// It deliberately does NOT mirror State: HealthDegraded and HealthHalfOpen
	// are both Serving, because routing keeps using them on purpose. Read this
	// for "can the pool serve traffic", read State for "what should the badge
	// say" — conflating the two is what produced a green panel over a dead pool.
	//
	// Pool-level gates (group idle windows, per-model rate limits, free
	// concurrency slots) are NOT visible here; Pool.Status callers must apply
	// those themselves.
	Serving bool

	// Reason is a human-facing explanation, non-empty whenever State is not
	// HealthHealthy.
	Reason string

	// RetryAfter is how long until this credential is expected to become
	// available again, when that is knowable (cooling → QuarantineUntil,
	// quota → QuotaResetAt). Zero when unknown or already serving.
	RetryAfter time.Duration

	ConsecutiveFailures int
	Consecutive429s     int
	Consecutive401s     int
	LastSuccess         time.Time
	LastFailure         time.Time
	LastFailureReason   string
	HardFailureAt       time.Time
	QuotaResetAt        time.Time
	QuarantineUntil     time.Time
	QuarantineStrikes   int

	// UsageLimit qualifies State == HealthQuota: true when the cooldown is
	// the account's window actually filling (a usage-limit rejection with
	// the upstream's own reset stamp — the one LastQuotaHit recorded), false
	// when it is the pool's own escalating pause after a generic 429/401/403
	// (ReportUpstreamError → MarkQuotaExceeded). Both park the credential
	// and both are "quota" to routing; a panel that paints a 30-second
	// throttle pause as "quota exhausted" is what this tells apart. The
	// match is on the reset stamp, so a manual clear followed by a fresh
	// bounce off the same window still reads as the usage limit.
	UsageLimit bool
}

// Healthy reports whether the state is the fully-good one. Provided so callers
// migrating off HealthSnapshot's bool have a direct replacement — but prefer
// switching on State, since "not healthy" spans five very different states.
func (r HealthReport) Healthy() bool { return r.State == HealthHealthy }

// HealthState classifies this credential. Like HealthSnapshot it auto-clears
// expired quota and quarantine deadlines as a side effect, so a caller never
// observes a stale cooldown.
//
// Precedence is strict and matches the order an operator would triage in:
// disabled → hard_failed → quota → cooling → half_open → degraded → healthy.
func (a *Auth) HealthState() HealthReport {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.healthStateLocked(time.Now())
}

// healthStateLocked is HealthState's body, for callers that already hold a.mu
// (Snapshot builds an AuthInfo under the same lock). Caller MUST hold the
// write lock — this mutates expired quota/quarantine deadlines.
func (a *Auth) healthStateLocked(now time.Time) HealthReport {
	a.clearExpiredQuotaLocked(now)
	// quarantinedLocked clears an elapsed deadline as a side effect; that is
	// what puts the breaker into its half-open probe. QuarantineStrikes
	// survives, which is how we detect half-open below.
	cooling := a.quarantinedLocked(now)

	r := HealthReport{
		ConsecutiveFailures: a.ConsecutiveFailures,
		Consecutive429s:     a.Consecutive429s,
		Consecutive401s:     a.Consecutive401s,
		LastSuccess:         a.LastSuccess,
		LastFailure:         a.LastFailure,
		LastFailureReason:   a.LastFailureReason,
		HardFailureAt:       a.HardFailureAt,
		QuotaResetAt:        a.QuotaResetAt,
		QuarantineUntil:     a.QuarantineUntil,
		QuarantineStrikes:   a.QuarantineStrikes,
	}

	// Verified means: something succeeded after the most recent failure. A
	// credential that has never failed is trivially verified.
	verified := a.LastFailure.IsZero() || a.LastSuccess.After(a.LastFailure)

	switch {
	case a.Disabled:
		r.State = HealthDisabled
		r.Reason = "disabled by operator"

	case !a.HardFailureAt.IsZero():
		r.State = HealthHardFailed
		r.Reason = a.HardFailureReason
		if r.Reason == "" {
			r.Reason = "hard-failed; needs manual reset"
		}

	case !a.QuotaExceededAt.IsZero():
		r.State = HealthQuota
		r.UsageLimit = sameQuotaWindow(a.LastQuotaHit.ResetAt, a.QuotaResetAt)
		if a.QuotaResetAt.IsZero() {
			r.Reason = "quota cooldown (no reset time reported)"
		} else {
			r.Reason = fmt.Sprintf("quota cooldown until %s", a.QuotaResetAt.Format(time.RFC3339))
			if d := time.Until(a.QuotaResetAt); d > 0 {
				r.RetryAfter = d
			}
		}

	case cooling:
		r.State = HealthCooling
		r.Reason = fmt.Sprintf("channel paused until %s (strike %d)",
			a.QuarantineUntil.Format(time.RFC3339), a.QuarantineStrikes)
		if a.LastFailureReason != "" {
			r.Reason += ": " + a.LastFailureReason
		}
		if d := time.Until(a.QuarantineUntil); d > 0 {
			r.RetryAfter = d
		}

	// Half-open: the breaker has tripped at least once and the pause has since
	// elapsed, but nothing has succeeded on this credential since the failure
	// that opened it. It is routable — and it is NOT recovered. Reporting this
	// as healthy is the specific bug this state exists to kill.
	case a.QuarantineStrikes > 0 && !verified:
		r.State = HealthHalfOpen
		r.Reason = fmt.Sprintf("unverified after pause (strike %d)", a.QuarantineStrikes)
		if a.LastFailureReason != "" {
			r.Reason += ": " + a.LastFailureReason
		}

	case verified:
		r.State = HealthHealthy

	// Optimistic recovery, mirroring IsHealthy: one stale failure past the
	// grace window is not worth alarming on.
	case a.ConsecutiveFailures < 2 && time.Since(a.LastFailure) > healthGrace:
		r.State = HealthHealthy

	default:
		r.State = HealthDegraded
		r.Reason = fmt.Sprintf("%d consecutive failures", a.ConsecutiveFailures)
		if a.LastFailureReason != "" {
			r.Reason += ": " + a.LastFailureReason
		}
	}

	// Serving mirrors what the router will actually do with this credential.
	// Degraded and half-open both keep taking traffic on purpose.
	switch r.State {
	case HealthDisabled, HealthHardFailed, HealthQuota, HealthCooling:
		r.Serving = false
	default:
		r.Serving = true
	}
	return r
}

// PoolHealth is the aggregate a status page needs in order to say something
// true about the deployment as a whole. It is computed per provider.
//
// The count that matters is Serving: a pool with ten credentials, nine
// hard-failed and one half-open, has Serving == 1 and Healthy == 0. Reporting
// on Healthy alone hides the fact that traffic is still flowing; reporting on
// Serving alone hides that nothing has actually succeeded. Show both.
type PoolHealth struct {
	Provider string
	Total    int
	Serving  int
	ByState  map[HealthState]int
	// Worst is the highest-severity state present, or HealthHealthy when the
	// pool is empty of problems.
	Worst HealthState
}

// Available reports whether any credential in this pool can take a request.
// This is the honest answer to "is the service up" — and it is false while the
// panel's old logic would still have shown green.
func (p PoolHealth) Available() bool { return p.Serving > 0 }

// NewPoolHealth aggregates per-credential reports for one provider.
func NewPoolHealth(provider string, reports []HealthReport) PoolHealth {
	p := PoolHealth{
		Provider: provider,
		Total:    len(reports),
		ByState:  make(map[HealthState]int, 7),
		Worst:    HealthHealthy,
	}
	for _, r := range reports {
		p.ByState[r.State]++
		if r.Serving {
			p.Serving++
		}
		if r.State.Severity() > p.Worst.Severity() {
			p.Worst = r.State
		}
	}
	return p
}
