// Package quotaestimate works out how much a subscription credential's
// rate-limit window is worth, in the units our own ledger keeps (USD at
// catalogue price, tokens), from two things that are individually useless:
//
//   - the upstream's report of the window: how full it is (utilization) and
//     when it reopens (resets_at). Anthropic never says what 100% *is*.
//   - our request log: what this credential consumed, timestamped.
//
// Anthropic's 5h and 7d windows are fixed, not rolling: each opens on the
// account's first request and closes exactly Length later, and resets_at is
// that close. So the window's start is resets_at - Length, and the spend our
// log saw between that start and "now" is the spend that produced the
// reported utilization. Dividing gives the whole window:
//
//	full window ≈ observed spend / utilization
//
// The cleanest measurement is a rejection: when the upstream returned a
// usage-limit 429 at time T, the spend in [resets_at-Length, T] is by
// definition one hundred percent of the allotment — no scaling, no rounding
// of a percentage. That is the case the operator described: parked for two
// hours, "resets in 106h", window is 168h, so the account ran for 60h before
// filling, and the 60h of log rows are the whole weekly budget. The live
// utilization path is the same arithmetic with a denominator below one, and
// it works on a credential that has never been rejected.
//
// What the estimate is NOT:
//
//   - It counts only traffic that went through this proxy. An account also
//     used from a laptop reports a utilization that includes spend we never
//     saw, so the projection is a floor, not the allotment.
//   - It is denominated in our catalogue prices, which is what an operator
//     wants ("this Max plan is worth ~$X/week of API usage") but is not the
//     upstream's own metering unit, which is unpublished.
//   - It is not a routing input and never touches credential health.
package quotaestimate

import (
	"math"
	"sort"
	"strings"
	"time"

	"github.com/wjsoj/cc-core/auth"
	"github.com/wjsoj/cc-core/requestlog"
	"github.com/wjsoj/cc-core/usage"
)

// Window keys, matching the api/oauth/usage body's top-level fields.
const (
	WindowFiveHour = "five_hour"
	WindowSevenDay = "seven_day"
)

// Lengths of the upstream windows. Anthropic documents both as fixed windows
// that open on first use; neither is rolling.
const (
	FiveHourLength = 5 * time.Hour
	SevenDayLength = 7 * 24 * time.Hour
)

// hitMatchSlack is how far a recorded rejection's reset stamp may sit from a
// live window's resets_at and still be the same window. The header carries
// epoch seconds, the body an unrounded stamp; both name one fixed instant.
const hitMatchSlack = 5 * time.Minute

// Window is one upstream rate-limit window as the usage probe reported it.
type Window struct {
	// Key is WindowFiveHour or WindowSevenDay.
	Key string
	// Length is the window's fixed span.
	Length time.Duration
	// ResetsAt is when the upstream will reopen the window; the window began
	// at ResetsAt - Length.
	ResetsAt time.Time
	// Utilization is the reported fill as a fraction (0.62 = 62%). The
	// upstream has shipped both 0..1 and 0..100 encodings; NormalizeUtilization
	// folds them.
	Utilization float64
}

// Start is when the window opened.
func (w Window) Start() time.Time { return w.ResetsAt.Add(-w.Length) }

// NormalizeUtilization folds the two encodings api/oauth/usage has used for
// a percentage into a fraction. Values above 1 are percentages; values in
// [0, 1] are fractions. Exactly 1 is read as 100%, matching what both admin
// UIs already do with the same field, so the panel's bar and this estimate
// never disagree. Negative or NaN input is treated as unknown (0).
func NormalizeUtilization(raw float64) float64 {
	if math.IsNaN(raw) || math.IsInf(raw, 0) || raw < 0 {
		return 0
	}
	if raw > 1 {
		return raw / 100
	}
	return raw
}

// Spend is what our ledger saw a credential consume in an interval.
type Spend struct {
	// CostUSD is the catalogue-price cost of the rows (Record.CostUSD), which
	// is the operator's own valuation of the traffic — not what customers
	// were billed after discounts or multipliers.
	CostUSD float64 `json:"cost_usd"`
	// WeightedTokens is usage.Counts.WeightedTotal scaled back to whole
	// tokens: input-equivalent tokens under the same 1/1.25/0.1/5 weighting
	// the load balancer and pricing share. A single number that moves the way
	// the bill moves, for panels that want tokens rather than dollars.
	WeightedTokens int64 `json:"weighted_tokens"`
	InputTokens    int64 `json:"input_tokens"`
	OutputTokens   int64 `json:"output_tokens"`
	CacheRead      int64 `json:"cache_read_tokens"`
	CacheCreate    int64 `json:"cache_create_tokens"`
	Requests       int64 `json:"requests"`
}

// TotalTokens is every token the upstream metered, unweighted.
func (s Spend) TotalTokens() int64 {
	return s.InputTokens + s.OutputTokens + s.CacheRead + s.CacheCreate
}

func (s Spend) scale(f float64) Spend {
	return Spend{
		CostUSD:        s.CostUSD * f,
		WeightedTokens: int64(math.Round(float64(s.WeightedTokens) * f)),
		InputTokens:    int64(math.Round(float64(s.InputTokens) * f)),
		OutputTokens:   int64(math.Round(float64(s.OutputTokens) * f)),
		CacheRead:      int64(math.Round(float64(s.CacheRead) * f)),
		CacheCreate:    int64(math.Round(float64(s.CacheCreate) * f)),
		Requests:       int64(math.Round(float64(s.Requests) * f)),
	}
}

func (s Spend) minus(o Spend) Spend {
	r := Spend{
		CostUSD:        s.CostUSD - o.CostUSD,
		WeightedTokens: s.WeightedTokens - o.WeightedTokens,
		InputTokens:    s.InputTokens - o.InputTokens,
		OutputTokens:   s.OutputTokens - o.OutputTokens,
		CacheRead:      s.CacheRead - o.CacheRead,
		CacheCreate:    s.CacheCreate - o.CacheCreate,
		Requests:       s.Requests - o.Requests,
	}
	if r.CostUSD < 0 {
		r.CostUSD = 0
	}
	for _, p := range []*int64{&r.WeightedTokens, &r.InputTokens, &r.OutputTokens, &r.CacheRead, &r.CacheCreate, &r.Requests} {
		if *p < 0 {
			*p = 0
		}
	}
	return r
}

// SpendFromAggregate converts a request-log aggregate into a Spend.
func SpendFromAggregate(a requestlog.Aggregate) Spend {
	c := usage.Counts{
		InputTokens:       a.InputTokens,
		OutputTokens:      a.OutputTokens,
		CacheCreateTokens: a.CacheCreateTokens,
		CacheReadTokens:   a.CacheReadTokens,
	}
	return Spend{
		CostUSD:        a.CostUSD,
		WeightedTokens: c.WeightedTotal() / 100,
		InputTokens:    a.InputTokens,
		OutputTokens:   a.OutputTokens,
		CacheRead:      a.CacheReadTokens,
		CacheCreate:    a.CacheCreateTokens,
		Requests:       a.Count,
	}
}

// SpendFunc returns what one credential consumed in [from, to]. Errors are
// reported on the estimate rather than aborting it, because the window
// arithmetic is still worth showing when the ledger is unavailable.
type SpendFunc func(from, to time.Time) (Spend, error)

// RequestLogSpend reads the credential's spend from the request log in dir,
// through the SQLite index when one is open and by scanning otherwise. A dir
// of "" (request logging disabled) yields a SpendFunc that reports no rows.
func RequestLogSpend(dir, authID string) SpendFunc {
	return func(from, to time.Time) (Spend, error) {
		if dir == "" || authID == "" {
			return Spend{}, nil
		}
		m, err := requestlog.AggregateByAuth(dir, from, to)
		if err != nil {
			return Spend{}, err
		}
		return SpendFromAggregate(m[authID]), nil
	}
}

// Basis says what the projection rests on.
type Basis string

const (
	// BasisQuotaHit: the upstream rejected the credential inside this window,
	// so the observed spend up to that rejection is a measured 100%.
	BasisQuotaHit Basis = "quota_hit"
	// BasisUtilization: scaled up from the reported percentage.
	BasisUtilization Basis = "utilization"
	// BasisObservedOnly: utilization is unknown or zero, so only the observed
	// spend is reported and nothing is projected.
	BasisObservedOnly Basis = "observed_only"
)

// Confidence is a coarse reliability grade for panels to colour by.
type Confidence string

const (
	// ConfidenceHigh: measured by a rejection.
	ConfidenceHigh Confidence = "high"
	// ConfidenceMedium: scaled from a utilization of at least
	// mediumUtilization over at least mediumObserved of window.
	ConfidenceMedium Confidence = "medium"
	// ConfidenceLow: everything else — a small percentage multiplied by a
	// large factor, where a single request's rounding dominates.
	ConfidenceLow Confidence = "low"
)

const (
	mediumUtilization = 0.25
	mediumObserved    = time.Hour
)

// Estimate is the result for one window.
type Estimate struct {
	Window         string    `json:"window"`
	WindowHours    float64   `json:"window_hours"`
	WindowStart    time.Time `json:"window_start"`
	WindowResetsAt time.Time `json:"window_resets_at"`
	// Utilization is the fraction the projection divided by: the reported
	// value, or exactly 1 under BasisQuotaHit.
	Utilization float64    `json:"utilization"`
	Basis       Basis      `json:"basis"`
	Confidence  Confidence `json:"confidence"`
	// Observed spans [ObservedFrom, ObservedTo]: the window's start up to now,
	// or up to the rejection under BasisQuotaHit.
	ObservedFrom  time.Time `json:"observed_from"`
	ObservedTo    time.Time `json:"observed_to"`
	ObservedHours float64   `json:"observed_hours"`
	Observed      Spend     `json:"observed"`
	// FullWindow is the projected 100%. Nil under BasisObservedOnly.
	FullWindow *Spend `json:"full_window,omitempty"`
	// Remaining is FullWindow minus Observed, floored at zero. Nil when
	// nothing is projected or the window is already full.
	Remaining *Spend `json:"remaining,omitempty"`
	// QuotaHitAt is the rejection the measurement is anchored on, under
	// BasisQuotaHit only.
	QuotaHitAt *time.Time `json:"quota_hit_at,omitempty"`
	// SpendError is set when the ledger could not be read; Observed is then
	// zero and nothing is projected.
	SpendError string `json:"spend_error,omitempty"`
}

// Project computes the estimate for one window. hit is the credential's last
// account-wide rejection (zero At if none); it anchors the measurement when
// it falls inside w and names the same reset. spend reads the ledger; nil
// means "no ledger", which yields an observed-only estimate.
func Project(w Window, hit auth.QuotaHit, spend SpendFunc, now time.Time) Estimate {
	est := Estimate{
		Window:         w.Key,
		WindowHours:    w.Length.Hours(),
		WindowStart:    w.Start(),
		WindowResetsAt: w.ResetsAt,
		Utilization:    w.Utilization,
		Basis:          BasisUtilization,
		ObservedFrom:   w.Start(),
		ObservedTo:     now,
	}
	if hitAnchors(w, hit) {
		est.Basis = BasisQuotaHit
		est.Utilization = 1
		est.ObservedTo = hit.At
		at := hit.At
		est.QuotaHitAt = &at
	}
	// A window that has not started yet, or a "now" the caller placed before
	// the window (clock skew between our clock and the upstream's reset
	// stamp), observes nothing rather than a negative span.
	if est.ObservedTo.After(w.ResetsAt) {
		est.ObservedTo = w.ResetsAt
	}
	if est.ObservedTo.Before(est.ObservedFrom) {
		est.ObservedTo = est.ObservedFrom
	}
	observed := est.ObservedTo.Sub(est.ObservedFrom)
	est.ObservedHours = observed.Hours()

	if spend != nil {
		s, err := spend(est.ObservedFrom, est.ObservedTo)
		if err != nil {
			est.SpendError = err.Error()
			est.Basis = BasisObservedOnly
			est.Confidence = ConfidenceLow
			return est
		}
		est.Observed = s
	}

	if est.Utilization <= 0 {
		est.Basis = BasisObservedOnly
		est.Confidence = ConfidenceLow
		return est
	}

	full := est.Observed.scale(1 / est.Utilization)
	est.FullWindow = &full
	if est.Utilization < 1 {
		rem := full.minus(est.Observed)
		est.Remaining = &rem
	}

	switch {
	case est.Basis == BasisQuotaHit:
		est.Confidence = ConfidenceHigh
	case est.Utilization >= mediumUtilization && observed >= mediumObserved:
		est.Confidence = ConfidenceMedium
	default:
		est.Confidence = ConfidenceLow
	}
	return est
}

// hitAnchors reports whether a recorded rejection measures window w: it must
// have landed inside the window and name the same reset. A rejection with
// the right reset but a stamp outside the window is a different window that
// happened to share the stamp (impossible upstream, so treat as noise), and
// a rejection inside the window with a different reset was the OTHER window
// filling — a 5h rejection during a 7d window measures nothing about 7d.
func hitAnchors(w Window, hit auth.QuotaHit) bool {
	if hit.At.IsZero() || hit.ResetAt.IsZero() {
		return false
	}
	if hit.At.Before(w.Start()) || hit.At.After(w.ResetsAt) {
		return false
	}
	d := hit.ResetAt.Sub(w.ResetsAt)
	if d < 0 {
		d = -d
	}
	return d <= hitMatchSlack
}

// FromHit reconstructs the window a rejection filled when no live probe is
// available. The rejection says when the window reopens; its length is
// inferred from how far ahead that was: more than five hours means it can
// only have been the weekly window. A rejection whose reset was under five
// hours away is ambiguous (a 5h window at any point, or a 7d window in its
// final hours) and is read as the 5h window, the common case. Utilization is
// 1 by construction. ok is false when the hit is empty or inconsistent.
func FromHit(hit auth.QuotaHit) (Window, bool) {
	if hit.At.IsZero() || hit.ResetAt.IsZero() || !hit.ResetAt.After(hit.At) {
		return Window{}, false
	}
	w := Window{Key: WindowFiveHour, Length: FiveHourLength, ResetsAt: hit.ResetAt, Utilization: 1}
	if hit.ResetAt.Sub(hit.At) > FiveHourLength {
		w.Key, w.Length = WindowSevenDay, SevenDayLength
	}
	return w, true
}

// FromUsageBody extracts the shared windows from a decoded api/oauth/usage
// body. It reads the top-level five_hour / seven_day objects, and falls back
// to the newer limits[] list (kind "session" / "weekly_all") when those are
// absent — model-scoped entries (weekly_scoped) are skipped because the
// ledger would need a per-family filter to match them. Windows without a
// parseable resets_at are dropped: the start cannot be placed without it.
// Output is ordered five_hour then seven_day.
func FromUsageBody(body map[string]any) []Window {
	if body == nil {
		return nil
	}
	found := map[string]Window{}
	for _, key := range []string{WindowFiveHour, WindowSevenDay} {
		obj, ok := body[key].(map[string]any)
		if !ok {
			continue
		}
		resetsAt, ok := parseTime(obj["resets_at"])
		if !ok {
			continue
		}
		util, _ := toFloat(obj["utilization"])
		found[key] = Window{
			Key:         key,
			Length:      lengthFor(key),
			ResetsAt:    resetsAt,
			Utilization: NormalizeUtilization(util),
		}
	}
	if limits, ok := body["limits"].([]any); ok {
		for _, raw := range limits {
			l, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			var key string
			switch kind, _ := l["kind"].(string); strings.ToLower(kind) {
			case "session":
				key = WindowFiveHour
			case "weekly_all":
				key = WindowSevenDay
			default:
				continue
			}
			if _, done := found[key]; done {
				continue
			}
			resetsAt, ok := parseTime(l["resets_at"])
			if !ok {
				continue
			}
			pct, _ := toFloat(l["percent"])
			found[key] = Window{
				Key:         key,
				Length:      lengthFor(key),
				ResetsAt:    resetsAt,
				Utilization: NormalizeUtilization(pct),
			}
		}
	}
	out := make([]Window, 0, len(found))
	for _, w := range found {
		out = append(out, w)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Length < out[j].Length })
	return out
}

func lengthFor(key string) time.Duration {
	if key == WindowSevenDay {
		return SevenDayLength
	}
	return FiveHourLength
}

// ForCredential is the one call a probe handler makes: project every window
// the usage body reports, anchored on the credential's last rejection, and —
// when the body reports nothing usable but a rejection is on record — fall
// back to the window that rejection reconstructs. Returns nil when there is
// nothing to say.
func ForCredential(body map[string]any, hit auth.QuotaHit, spend SpendFunc, now time.Time) []Estimate {
	windows := FromUsageBody(body)
	if len(windows) == 0 {
		w, ok := FromHit(hit)
		if !ok {
			return nil
		}
		windows = []Window{w}
	}
	out := make([]Estimate, 0, len(windows))
	for _, w := range windows {
		out = append(out, Project(w, hit, spend, now))
	}
	return out
}

func parseTime(v any) (time.Time, bool) {
	switch x := v.(type) {
	case string:
		x = strings.TrimSpace(x)
		if x == "" {
			return time.Time{}, false
		}
		for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.999999"} {
			if t, err := time.Parse(layout, x); err == nil {
				return t, true
			}
		}
		return time.Time{}, false
	case float64:
		if x <= 0 {
			return time.Time{}, false
		}
		// Epoch seconds; anything past year 3000 in seconds is milliseconds.
		if x > 32503680000 {
			x /= 1000
		}
		return time.Unix(int64(x), 0), true
	}
	return time.Time{}, false
}

func toFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	}
	return 0, false
}
