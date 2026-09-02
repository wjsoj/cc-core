package quotaestimate

import (
	"errors"
	"math"
	"testing"
	"time"

	"github.com/wjsoj/cc-core/auth"
	"github.com/wjsoj/cc-core/requestlog"
)

func approx(a, b, tol float64) bool { return math.Abs(a-b) <= tol }

// constantRate is a ledger that spent $1 and 1000 weighted tokens per hour,
// so every assertion below can be read off the observed span.
func constantRate(t *testing.T) SpendFunc {
	t.Helper()
	return func(from, to time.Time) (Spend, error) {
		h := to.Sub(from).Hours()
		if h < 0 {
			t.Fatalf("negative observed span %v..%v", from, to)
		}
		return Spend{
			CostUSD:        h,
			WeightedTokens: int64(h * 1000),
			InputTokens:    int64(h * 1000),
			Requests:       int64(h * 10),
		}, nil
	}
}

// The scenario the feature was specified with: parked for two hours,
// "resets in 106h", the window is 168h — so the account ran 60h before
// filling, and those 60h of ledger rows are the whole weekly allotment.
func TestProjectQuotaHitMeasuresTheWholeWindow(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	hitAt := now.Add(-2 * time.Hour)
	resetsAt := now.Add(106 * time.Hour)
	w := Window{Key: WindowSevenDay, Length: SevenDayLength, ResetsAt: resetsAt, Utilization: 1}
	hit := auth.QuotaHit{At: hitAt, ResetAt: resetsAt}

	est := Project(w, hit, constantRate(t), now)

	if est.Basis != BasisQuotaHit {
		t.Fatalf("basis = %q, want quota_hit", est.Basis)
	}
	if est.Confidence != ConfidenceHigh {
		t.Fatalf("confidence = %q, want high", est.Confidence)
	}
	if !est.WindowStart.Equal(resetsAt.Add(-168 * time.Hour)) {
		t.Fatalf("window start = %v", est.WindowStart)
	}
	if !est.ObservedTo.Equal(hitAt) {
		t.Fatalf("observed_to = %v, want the rejection %v, not now", est.ObservedTo, hitAt)
	}
	if !approx(est.ObservedHours, 60, 1e-9) {
		t.Fatalf("observed hours = %v, want 60", est.ObservedHours)
	}
	if est.FullWindow == nil || !approx(est.FullWindow.CostUSD, 60, 1e-9) {
		t.Fatalf("full window = %+v, want $60 (observed spend is the whole window, unscaled)", est.FullWindow)
	}
	if est.Remaining != nil {
		t.Fatalf("remaining = %+v, want nil: the window is full", est.Remaining)
	}
	if est.QuotaHitAt == nil || !est.QuotaHitAt.Equal(hitAt) {
		t.Fatalf("quota_hit_at = %v", est.QuotaHitAt)
	}
	if est.Utilization != 1 {
		t.Fatalf("utilization = %v, want exactly 1 under a rejection regardless of the reported value", est.Utilization)
	}
}

func TestProjectUtilizationScalesUp(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	// Window opened 40h ago, 25% used.
	w := Window{Key: WindowSevenDay, Length: SevenDayLength, ResetsAt: now.Add(128 * time.Hour), Utilization: 0.25}

	est := Project(w, auth.QuotaHit{}, constantRate(t), now)

	if est.Basis != BasisUtilization {
		t.Fatalf("basis = %q", est.Basis)
	}
	if !approx(est.ObservedHours, 40, 1e-9) || !approx(est.Observed.CostUSD, 40, 1e-9) {
		t.Fatalf("observed = %vh $%v", est.ObservedHours, est.Observed.CostUSD)
	}
	if est.FullWindow == nil || !approx(est.FullWindow.CostUSD, 160, 1e-9) {
		t.Fatalf("full window = %+v, want $160", est.FullWindow)
	}
	if est.Remaining == nil || !approx(est.Remaining.CostUSD, 120, 1e-9) {
		t.Fatalf("remaining = %+v, want $120", est.Remaining)
	}
	if est.FullWindow.WeightedTokens != 160000 || est.Remaining.WeightedTokens != 120000 {
		t.Fatalf("weighted tokens full=%d remaining=%d", est.FullWindow.WeightedTokens, est.Remaining.WeightedTokens)
	}
	if est.Confidence != ConfidenceMedium {
		t.Fatalf("confidence = %q, want medium at 25%% over 40h", est.Confidence)
	}
}

func TestProjectLowUtilizationIsLowConfidence(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	w := Window{Key: WindowFiveHour, Length: FiveHourLength, ResetsAt: now.Add(4 * time.Hour), Utilization: 0.03}
	est := Project(w, auth.QuotaHit{}, constantRate(t), now)
	if est.Confidence != ConfidenceLow {
		t.Fatalf("confidence = %q, want low: 3%% × 33 is rounding noise", est.Confidence)
	}
	if est.FullWindow == nil {
		t.Fatal("a low-confidence projection is still a projection")
	}
}

func TestProjectZeroUtilizationIsObservedOnly(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	w := Window{Key: WindowSevenDay, Length: SevenDayLength, ResetsAt: now.Add(100 * time.Hour)}
	est := Project(w, auth.QuotaHit{}, constantRate(t), now)
	if est.Basis != BasisObservedOnly || est.FullWindow != nil || est.Remaining != nil {
		t.Fatalf("zero utilization must not divide: %+v", est)
	}
	if !approx(est.Observed.CostUSD, 68, 1e-9) {
		t.Fatalf("observed spend still reported: %v", est.Observed.CostUSD)
	}
}

func TestProjectLedgerErrorIsReportedNotFatal(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	w := Window{Key: WindowSevenDay, Length: SevenDayLength, ResetsAt: now.Add(100 * time.Hour), Utilization: 0.5}
	failing := func(time.Time, time.Time) (Spend, error) { return Spend{}, errors.New("index locked") }
	est := Project(w, auth.QuotaHit{}, failing, now)
	if est.SpendError != "index locked" || est.FullWindow != nil || est.Basis != BasisObservedOnly {
		t.Fatalf("%+v", est)
	}
	if !approx(est.ObservedHours, 68, 1e-9) {
		t.Fatalf("window arithmetic must survive a ledger failure: %v", est.ObservedHours)
	}
}

func TestProjectNilLedgerObservesNothing(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	w := Window{Key: WindowSevenDay, Length: SevenDayLength, ResetsAt: now.Add(100 * time.Hour), Utilization: 0.5}
	est := Project(w, auth.QuotaHit{}, nil, now)
	if est.FullWindow == nil || est.FullWindow.CostUSD != 0 {
		t.Fatalf("%+v", est)
	}
}

// A 5h rejection that landed during the 7d window measures the 5h window,
// not the 7d one: the hit must name the window's own reset to anchor it.
func TestHitForAnotherWindowDoesNotAnchor(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	weekly := Window{Key: WindowSevenDay, Length: SevenDayLength, ResetsAt: now.Add(100 * time.Hour), Utilization: 0.4}
	fiveHourHit := auth.QuotaHit{At: now.Add(-3 * time.Hour), ResetAt: now.Add(time.Hour)}

	est := Project(weekly, fiveHourHit, constantRate(t), now)
	if est.Basis != BasisUtilization || est.Utilization != 0.4 {
		t.Fatalf("a 5h rejection was taken as the weekly measurement: %+v", est)
	}

	// The same hit against the 5h window it actually filled anchors, with
	// the reset stamps differing by header rounding.
	session := Window{Key: WindowFiveHour, Length: FiveHourLength, ResetsAt: now.Add(time.Hour + 30*time.Second), Utilization: 0.99}
	est = Project(session, fiveHourHit, constantRate(t), now)
	// Window opened at resets_at-5h = now-3h59m30s; the hit at now-3h is
	// 59.5 minutes in.
	if est.Basis != BasisQuotaHit || !approx(est.ObservedHours, 59.5/60, 1e-9) {
		t.Fatalf("%+v", est)
	}
}

// A rejection from a PREVIOUS week is not this week's measurement even if
// the credential has not been rejected since.
func TestStaleHitOutsideWindowDoesNotAnchor(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	w := Window{Key: WindowSevenDay, Length: SevenDayLength, ResetsAt: now.Add(100 * time.Hour), Utilization: 0.4}
	lastWeek := auth.QuotaHit{At: now.Add(-200 * time.Hour), ResetAt: w.ResetsAt.Add(-SevenDayLength)}
	est := Project(w, lastWeek, constantRate(t), now)
	if est.Basis != BasisUtilization {
		t.Fatalf("%+v", est)
	}
}

func TestProjectClampsObservedSpan(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	// Reset already passed (stale probe): observe only up to the reset.
	w := Window{Key: WindowFiveHour, Length: FiveHourLength, ResetsAt: now.Add(-time.Hour), Utilization: 0.5}
	est := Project(w, auth.QuotaHit{}, constantRate(t), now)
	if !est.ObservedTo.Equal(w.ResetsAt) || !approx(est.ObservedHours, 5, 1e-9) {
		t.Fatalf("%+v", est)
	}
	// Window in the future (skew): zero span, never negative.
	w = Window{Key: WindowFiveHour, Length: FiveHourLength, ResetsAt: now.Add(6 * time.Hour), Utilization: 0.5}
	est = Project(w, auth.QuotaHit{}, constantRate(t), now)
	if est.ObservedHours != 0 {
		t.Fatalf("%+v", est)
	}
}

func TestNormalizeUtilization(t *testing.T) {
	cases := map[float64]float64{0: 0, 0.37: 0.37, 1: 1, 37: 0.37, 100: 1, -5: 0, 150: 1.5}
	for in, want := range cases {
		if got := NormalizeUtilization(in); !approx(got, want, 1e-12) {
			t.Errorf("NormalizeUtilization(%v) = %v, want %v", in, got, want)
		}
	}
	if NormalizeUtilization(math.NaN()) != 0 {
		t.Error("NaN must read as unknown")
	}
}

func TestFromHitInfersWindowLength(t *testing.T) {
	at := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	w, ok := FromHit(auth.QuotaHit{At: at, ResetAt: at.Add(106 * time.Hour)})
	if !ok || w.Key != WindowSevenDay || w.Length != SevenDayLength || w.Utilization != 1 {
		t.Fatalf("%+v %v", w, ok)
	}
	if !w.Start().Equal(at.Add(106*time.Hour - SevenDayLength)) {
		t.Fatalf("start = %v", w.Start())
	}
	w, ok = FromHit(auth.QuotaHit{At: at, ResetAt: at.Add(3 * time.Hour)})
	if !ok || w.Key != WindowFiveHour {
		t.Fatalf("%+v %v", w, ok)
	}
	if _, ok := FromHit(auth.QuotaHit{}); ok {
		t.Fatal("empty hit")
	}
	if _, ok := FromHit(auth.QuotaHit{At: at, ResetAt: at.Add(-time.Hour)}); ok {
		t.Fatal("reset before hit is inconsistent")
	}
}

func TestFromUsageBodyTopLevelWindows(t *testing.T) {
	body := map[string]any{
		"five_hour":      map[string]any{"utilization": 12.0, "resets_at": "2026-09-02T15:00:00Z"},
		"seven_day":      map[string]any{"utilization": 0.62, "resets_at": "2026-09-06T22:00:00.123456+00:00"},
		"seven_day_opus": map[string]any{"utilization": 50.0, "resets_at": "2026-09-06T22:00:00Z"},
	}
	ws := FromUsageBody(body)
	if len(ws) != 2 {
		t.Fatalf("got %d windows: %+v", len(ws), ws)
	}
	if ws[0].Key != WindowFiveHour || !approx(ws[0].Utilization, 0.12, 1e-12) {
		t.Fatalf("%+v", ws[0])
	}
	if ws[1].Key != WindowSevenDay || !approx(ws[1].Utilization, 0.62, 1e-12) || ws[1].ResetsAt.Year() != 2026 {
		t.Fatalf("%+v", ws[1])
	}
}

func TestFromUsageBodyLimitsFallback(t *testing.T) {
	body := map[string]any{
		"limits": []any{
			map[string]any{"kind": "session", "percent": 40.0, "resets_at": "2026-09-02T15:00:00Z"},
			map[string]any{"kind": "weekly_all", "percent": 80.0, "resets_at": "2026-09-06T22:00:00Z"},
			map[string]any{"kind": "weekly_scoped", "percent": 10.0, "resets_at": "2026-09-06T22:00:00Z",
				"scope": map[string]any{"model": map[string]any{"display_name": "Fable"}}},
		},
	}
	ws := FromUsageBody(body)
	if len(ws) != 2 || ws[0].Key != WindowFiveHour || ws[1].Key != WindowSevenDay {
		t.Fatalf("%+v", ws)
	}
	if !approx(ws[1].Utilization, 0.8, 1e-12) {
		t.Fatalf("%+v", ws[1])
	}
	// Top-level wins over limits[] when both are present.
	body["seven_day"] = map[string]any{"utilization": 0.5, "resets_at": "2026-09-06T22:00:00Z"}
	ws = FromUsageBody(body)
	if len(ws) != 2 || !approx(ws[1].Utilization, 0.5, 1e-12) {
		t.Fatalf("%+v", ws)
	}
}

func TestFromUsageBodyDropsWindowsWithoutReset(t *testing.T) {
	body := map[string]any{
		"five_hour": map[string]any{"utilization": 12.0},
		"seven_day": map[string]any{"utilization": 0.62, "resets_at": nil},
	}
	if ws := FromUsageBody(body); len(ws) != 0 {
		t.Fatalf("a window whose start cannot be placed must be dropped: %+v", ws)
	}
	if ws := FromUsageBody(nil); ws != nil {
		t.Fatalf("%+v", ws)
	}
}

func TestForCredentialFallsBackToHitWhenProbeIsEmpty(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	hit := auth.QuotaHit{At: now.Add(-2 * time.Hour), ResetAt: now.Add(106 * time.Hour)}
	ests := ForCredential(nil, hit, constantRate(t), now)
	if len(ests) != 1 || ests[0].Window != WindowSevenDay || ests[0].Basis != BasisQuotaHit {
		t.Fatalf("%+v", ests)
	}
	if !approx(ests[0].FullWindow.CostUSD, 60, 1e-9) {
		t.Fatalf("%+v", ests[0].FullWindow)
	}
	if ests := ForCredential(nil, auth.QuotaHit{}, constantRate(t), now); ests != nil {
		t.Fatalf("nothing to say: %+v", ests)
	}
}

func TestForCredentialUsesProbeAndHitTogether(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	resetsAt := now.Add(106 * time.Hour)
	body := map[string]any{
		"five_hour": map[string]any{"utilization": 0.0, "resets_at": now.Add(3 * time.Hour).Format(time.RFC3339)},
		"seven_day": map[string]any{"utilization": 100.0, "resets_at": resetsAt.Format(time.RFC3339)},
	}
	hit := auth.QuotaHit{At: now.Add(-2 * time.Hour), ResetAt: resetsAt}
	ests := ForCredential(body, hit, constantRate(t), now)
	if len(ests) != 2 {
		t.Fatalf("%+v", ests)
	}
	if ests[0].Window != WindowFiveHour || ests[0].Basis != BasisObservedOnly {
		t.Fatalf("5h at 0%%: %+v", ests[0])
	}
	if ests[1].Basis != BasisQuotaHit || !approx(ests[1].ObservedHours, 60, 1e-9) {
		t.Fatalf("7d anchored on the rejection: %+v", ests[1])
	}
}

// End to end against a real request log: rows inside the window count, rows
// before it and rows of another credential do not, and attempt-only rows
// (withheld failovers) are invisible, exactly as every other query treats
// them.
func TestRequestLogSpendReadsOnlyTheWindow(t *testing.T) {
	dir := t.TempDir()
	w, err := requestlog.Open(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	windowStart := now.Add(-60 * time.Hour)
	rows := []requestlog.Record{
		{TS: windowStart.Add(-time.Hour), AuthID: "a", Model: "m", Input: 1000, CostUSD: 1, Status: 200}, // before window
		{TS: windowStart.Add(time.Hour), AuthID: "a", Model: "m", Input: 1000, Output: 100, CostUSD: 2, Status: 200},
		{TS: now.Add(-time.Hour), AuthID: "a", Model: "m", Input: 3000, CacheRead: 5000, CostUSD: 3, Status: 200},
		{TS: now.Add(-time.Hour), AuthID: "a", Model: "m", Input: 999, CostUSD: 99, Status: 429, AttemptOnly: true}, // withheld
		{TS: now.Add(-time.Hour), AuthID: "b", Model: "m", Input: 1000, CostUSD: 50, Status: 200},                   // other credential
	}
	for _, r := range rows {
		r.ClientToken = "sk-mask"
		r.AuthKind = "oauth"
		r.Provider = "anthropic"
		w.Log(r)
	}
	w.Close()

	s, err := RequestLogSpend(dir, "a")(windowStart, now)
	if err != nil {
		t.Fatal(err)
	}
	if !approx(s.CostUSD, 5, 1e-9) || s.Requests != 2 || s.InputTokens != 4000 || s.OutputTokens != 100 || s.CacheRead != 5000 {
		t.Fatalf("%+v", s)
	}
	// 4000×1 + 100×5 + 5000×0.1 = 5000 input-equivalent tokens.
	if s.WeightedTokens != 5000 {
		t.Fatalf("weighted = %d", s.WeightedTokens)
	}

	if s, err := RequestLogSpend("", "a")(windowStart, now); err != nil || s.Requests != 0 {
		t.Fatalf("no log dir must read as no rows: %+v %v", s, err)
	}
}

func TestSpendArithmeticNeverGoesNegative(t *testing.T) {
	full := Spend{CostUSD: 10, Requests: 5}
	rem := full.minus(Spend{CostUSD: 12, Requests: 9})
	if rem.CostUSD != 0 || rem.Requests != 0 {
		t.Fatalf("%+v", rem)
	}
	if s := (Spend{InputTokens: 1, OutputTokens: 2, CacheRead: 3, CacheCreate: 4}).TotalTokens(); s != 10 {
		t.Fatal(s)
	}
}

func TestHitCacheServesWeeklyAndSettles(t *testing.T) {
	var c HitCache
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	calls := 0
	spend := func(from, to time.Time) (Spend, error) {
		calls++
		return constantRate(t)(from, to)
	}

	// A 5h rejection is not a weekly measurement.
	if got := c.Weekly("a", auth.QuotaHit{At: now.Add(-time.Hour), ResetAt: now.Add(time.Hour)}, spend, now); got != nil {
		t.Fatalf("%+v", got)
	}

	// Fresh hit (2 minutes old): computed, but not cached — in-flight rows
	// may still be landing.
	fresh := auth.QuotaHit{At: now.Add(-2 * time.Minute), ResetAt: now.Add(106 * time.Hour)}
	if got := c.Weekly("a", fresh, spend, now); got == nil || got.Basis != BasisQuotaHit {
		t.Fatalf("%+v", got)
	}
	c.Weekly("a", fresh, spend, now)
	if calls != 2 {
		t.Fatalf("unsettled hit must be recomputed: %d calls", calls)
	}

	// Settled: one ledger read, then served from cache.
	later := now.Add(settleAfter)
	c.Weekly("a", fresh, spend, later)
	c.Weekly("a", fresh, spend, later.Add(time.Hour))
	if calls != 3 {
		t.Fatalf("settled hit must be cached: %d calls", calls)
	}

	// A new rejection is a new key.
	next := auth.QuotaHit{At: later.Add(time.Hour), ResetAt: later.Add(150 * time.Hour)}
	if got := c.Weekly("a", next, spend, later.Add(2*time.Hour)); got == nil || !got.QuotaHitAt.Equal(next.At) {
		t.Fatalf("%+v", got)
	}
	if calls != 4 {
		t.Fatalf("%d", calls)
	}
	c.Forget("a")
	c.Weekly("a", next, spend, later.Add(2*time.Hour))
	if calls != 5 {
		t.Fatalf("Forget must drop the entry: %d", calls)
	}
}

func TestHitCacheDoesNotCacheLedgerErrors(t *testing.T) {
	var c HitCache
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	hit := auth.QuotaHit{At: now.Add(-time.Hour), ResetAt: now.Add(106 * time.Hour)}
	calls := 0
	failing := func(time.Time, time.Time) (Spend, error) { calls++; return Spend{}, errors.New("locked") }
	c.Weekly("a", hit, failing, now)
	c.Weekly("a", hit, failing, now)
	if calls != 2 {
		t.Fatalf("a failed read must not be cached: %d", calls)
	}
}
