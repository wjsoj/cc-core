package auth

import (
	"context"
	"testing"
	"time"
)

// lastResortKey builds a bare in-memory API-key credential. No backing file:
// nothing in these tests persists.
func lastResortKey(id string, order int) *Auth {
	return &Auth{
		ID:          id,
		Kind:        KindAPIKey,
		Provider:    ProviderAnthropic,
		Label:       id,
		AccessToken: "sk-ant-" + id,
		Order:       order,
	}
}

func lastResortOAuth(id string) *Auth {
	return &Auth{
		ID:          id,
		Kind:        KindOAuth,
		Provider:    ProviderAnthropic,
		Label:       id,
		AccessToken: "oauth-" + id,
		ExpiresAt:   time.Now().Add(time.Hour),
	}
}

// quarantineNow drives a key into an open circuit the way production does —
// through the public Mark* API, so the test breaks if the threshold moves.
func quarantineNow(t *testing.T, k *Auth) {
	t.Helper()
	for i := 0; i < apiKeyQuarantineThreshold; i++ {
		k.MarkFailure("upstream 502")
	}
	if !k.IsQuarantined(time.Now()) {
		t.Fatalf("setup: %s should be quarantined", k.ID)
	}
}

func acquireResult(p *Pool, session string) (*Auth, AcquireResult) {
	return p.AcquireWithResult(context.Background(), "anthropic", "tok", "", "", session, AcquireOptions{
		AllowAPIKeyFallback: true,
	})
}

// TestLastResortReleasesTheOnlyPausedKey is the core of the A-plan: skipping
// the only channel that can serve a model is self-inflicted downtime. The
// circuit breaker must lower a candidate's priority, never remove it from the
// candidate set entirely.
func TestLastResortReleasesTheOnlyPausedKey(t *testing.T) {
	k := lastResortKey("solo", 0)
	quarantineNow(t, k)
	p := NewPool(nil, []*Auth{k}, time.Minute, false, "")

	got, res := acquireResult(p, "s1")
	if got == nil {
		t.Fatal("a paused sole channel must still be released; returning nil hands the client a 503")
	}
	if got.ID != "solo" {
		t.Fatalf("got %s, want solo", got.ID)
	}
	if !res.LastResort {
		t.Fatal("AcquireResult.LastResort must be true, or the status page reports a paused pool as healthy")
	}
	if res.Reason == "" {
		t.Fatal("a last-resort release must carry a reason")
	}
}

// TestLastResortAlsoCoversQuotaCooldown: quota is the other self-expiring
// deadline, and it blocks exactly like the breaker does.
func TestLastResortAlsoCoversQuotaCooldown(t *testing.T) {
	k := lastResortKey("quota-only", 0)
	k.MarkQuotaExceeded(time.Now().Add(30 * time.Minute))
	p := NewPool(nil, []*Auth{k}, time.Minute, false, "")

	got, res := acquireResult(p, "s1")
	if got == nil || !res.LastResort {
		t.Fatalf("quota-cooled sole key: got %v lastResort=%v, want the key released as last resort", got, res.LastResort)
	}
}

// TestLastResortNeverPreemptsAHealthyKey: last resort must not become the
// normal path. While anything is actually usable, a paused key stays parked.
func TestLastResortNeverPreemptsAHealthyKey(t *testing.T) {
	paused := lastResortKey("paused", 0) // better Order — still must lose
	quarantineNow(t, paused)
	healthy := lastResortKey("healthy", 1)
	p := NewPool(nil, []*Auth{paused, healthy}, time.Minute, false, "")

	for i := 0; i < 3; i++ {
		got, res := acquireResult(p, "s1")
		if got == nil || got.ID != "healthy" {
			t.Fatalf("attempt %d: got %v, want healthy", i, got)
		}
		if res.LastResort {
			t.Fatal("a normal schedule must not be flagged as last-resort")
		}
	}
}

// TestLastResortSkippedWhileOAuthUsable pins the gate: the paused API key is
// only released when the OAuth side has nothing either.
func TestLastResortSkippedWhileOAuthUsable(t *testing.T) {
	o := lastResortOAuth("oauth1")
	k := lastResortKey("paused", 0)
	quarantineNow(t, k)
	p := NewPool([]*Auth{o}, []*Auth{k}, time.Minute, false, "")

	got, res := acquireResult(p, "s1")
	if got == nil || got.ID != "oauth1" {
		t.Fatalf("got %v, want the usable OAuth credential", got)
	}
	if res.LastResort {
		t.Fatal("OAuth was available; this is not a last resort")
	}
}

// TestLastResortPicksClosestToRecovery: among paused keys, the one due back
// soonest wins — that is the whole ranking rule.
func TestLastResortPicksClosestToRecovery(t *testing.T) {
	far := lastResortKey("far", 0) // better Order, but hours away
	far.MarkQuotaExceeded(time.Now().Add(2 * time.Hour))
	near := lastResortKey("near", 5)
	near.MarkQuotaExceeded(time.Now().Add(20 * time.Second))
	p := NewPool(nil, []*Auth{far, near}, time.Minute, false, "")

	got, res := acquireResult(p, "s1")
	if got == nil || got.ID != "near" {
		t.Fatalf("got %v, want near (soonest RetryAfter wins over Order in the last-resort round)", got)
	}
	if !res.LastResort {
		t.Fatal("want LastResort")
	}
}

// TestLastResortHardBoundaries: disabled and hard-failed are operator/sticky
// verdicts, not backoff. Even as the sole candidate they stay out.
func TestLastResortHardBoundaries(t *testing.T) {
	t.Run("disabled", func(t *testing.T) {
		k := lastResortKey("off", 0)
		k.SetDisabled(true)
		p := NewPool(nil, []*Auth{k}, time.Minute, false, "")
		if got, _ := acquireResult(p, "s1"); got != nil {
			t.Fatalf("got %s; an operator-disabled key must never be released", got.ID)
		}
		if p.HasAPIKeyFor("anthropic", "", "") {
			t.Fatal("HasAPIKeyFor must agree: disabled is not available")
		}
	})

	t.Run("hard failed", func(t *testing.T) {
		// API keys are never hard-failed by the Mark* paths, so this models an
		// operator/loader-set sticky retirement directly.
		k := lastResortKey("dead", 0)
		k.HardFailureAt = time.Now()
		k.HardFailureReason = "revoked"
		p := NewPool(nil, []*Auth{k}, time.Minute, false, "")
		if got, _ := acquireResult(p, "s1"); got != nil {
			t.Fatalf("got %s; a hard-failed key must never be released", got.ID)
		}
		if p.HasAPIKeyFor("anthropic", "", "") {
			t.Fatal("HasAPIKeyFor must agree: hard-failed is not available")
		}
	})
}

// TestLastResortHonoursExcludeIDs: the forks retry up to a dozen times with a
// growing exclude list. If last-resort ignored it, every one of those attempts
// would land on the same dead key and the client would wait for all of them.
func TestLastResortHonoursExcludeIDs(t *testing.T) {
	k := lastResortKey("solo", 0)
	quarantineNow(t, k)
	p := NewPool(nil, []*Auth{k}, time.Minute, false, "")

	got, res := p.AcquireWithResult(context.Background(), "anthropic", "tok", "", "", "s1", AcquireOptions{
		AllowAPIKeyFallback: true,
		ExcludeIDs:          []string{"solo"},
	})
	if got != nil {
		t.Fatalf("got %s; an already-tried credential must not come back in the last-resort round", got.ID)
	}
	if res.LastResort {
		t.Fatal("no credential was returned; LastResort must stay false")
	}
}

// TestLastResortRespectsAPIKeyOptIn: the billing opt-in gate outranks
// availability. A client that never enabled the upstream key pool must not be
// served (and billed) by one, even when that is the only thing left.
func TestLastResortRespectsAPIKeyOptIn(t *testing.T) {
	k := lastResortKey("solo", 0)
	quarantineNow(t, k)
	p := NewPool(nil, []*Auth{k}, time.Minute, false, "")

	got, _ := p.AcquireWithResult(context.Background(), "anthropic", "tok", "", "", "s1", AcquireOptions{
		AllowAPIKeyFallback: false,
	})
	if got != nil {
		t.Fatalf("got %s; AllowAPIKeyFallback=false must hold even as a last resort", got.ID)
	}
}

// TestEqualOrderKeysRotate: API keys have no sticky sessions, so every request
// re-runs the scan. Without a secondary sort the first slice entry won every
// time and "three keys at priority 0" really meant "one key plus two spares".
func TestEqualOrderKeysRotate(t *testing.T) {
	a := lastResortKey("a", 0)
	b := lastResortKey("b", 0)
	c := lastResortKey("c", 0)
	p := NewPool(nil, []*Auth{a, b, c}, time.Minute, false, "")

	// Nothing has failed: insertion order decides, deterministically.
	if got, _ := acquireResult(p, "s1"); got.ID != "a" {
		t.Fatalf("first pick %s, want a", got.ID)
	}
	// One failure on `a` — below every threshold, so it stays fully usable —
	// must be enough to move traffic to the next key at the same priority.
	a.MarkFailure("upstream 502")
	if got, _ := acquireResult(p, "s2"); got.ID != "b" {
		t.Fatalf("after a failed: got %s, want b", got.ID)
	}
	b.MarkFailure("upstream 502")
	if got, _ := acquireResult(p, "s3"); got.ID != "c" {
		t.Fatalf("after b failed: got %s, want c", got.ID)
	}
	// All three have failed now; the oldest failure is the least suspect.
	c.MarkFailure("upstream 502")
	if got, _ := acquireResult(p, "s4"); got.ID != "a" {
		t.Fatalf("after c failed: got %s, want a (oldest failure sorts first)", got.ID)
	}
	// A success clears the counters and puts `b` back at the front of its tier.
	b.MarkSuccess()
	if got, _ := acquireResult(p, "s5"); got.ID != "b" {
		t.Fatalf("after b succeeded: got %s, want b", got.ID)
	}
}

// TestRotationNeverCrossesOrderBoundaries: Order is explicit operator intent.
// Rotation is a tiebreaker inside one priority, never a reason to promote a
// lower-priority key.
func TestRotationNeverCrossesOrderBoundaries(t *testing.T) {
	primary := lastResortKey("primary", 0)
	backup := lastResortKey("backup", 1)
	p := NewPool(nil, []*Auth{backup, primary}, time.Minute, false, "")

	// Degrade the primary short of the quarantine threshold.
	for i := 0; i < apiKeyQuarantineThreshold-1; i++ {
		primary.MarkFailure("upstream 502")
	}
	if got, _ := acquireResult(p, "s1"); got.ID != "primary" {
		t.Fatalf("got %s; a degraded-but-usable higher-priority key still wins", got.ID)
	}
	// Only once it is actually paused does the backup take over.
	primary.MarkFailure("upstream 502")
	got, res := acquireResult(p, "s2")
	if got.ID != "backup" {
		t.Fatalf("got %s, want backup", got.ID)
	}
	if res.LastResort {
		t.Fatal("the backup was fully usable; not a last resort")
	}
}

// TestHasAPIKeyForMatchesAcquire is the anti-drift test: the fail-fast
// pre-check and the scheduler must never disagree, in either direction.
func TestHasAPIKeyForMatchesAcquire(t *testing.T) {
	cases := []struct {
		name  string
		setup func(k *Auth)
		want  bool
	}{
		{"healthy", func(*Auth) {}, true},
		{"quarantined", func(k *Auth) { quarantineNowNoT(k) }, true},
		{"quota", func(k *Auth) { k.MarkQuotaExceeded(time.Now().Add(time.Hour)) }, true},
		{"quota and quarantined", func(k *Auth) {
			quarantineNowNoT(k)
			k.MarkQuotaExceeded(time.Now().Add(time.Hour))
		}, true},
		{"disabled", func(k *Auth) { k.SetDisabled(true) }, false},
		{"hard failed", func(k *Auth) { k.HardFailureAt = time.Now() }, false},
		{"disabled and quarantined", func(k *Auth) {
			quarantineNowNoT(k)
			k.SetDisabled(true)
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			k := lastResortKey("k", 0)
			tc.setup(k)
			p := NewPool(nil, []*Auth{k}, time.Minute, false, "")

			has := p.HasAPIKeyFor("anthropic", "", "")
			got, _ := acquireResult(p, "s1")
			if has != tc.want {
				t.Fatalf("HasAPIKeyFor = %v, want %v", has, tc.want)
			}
			if (got != nil) != tc.want {
				t.Fatalf("Acquire returned %v, want non-nil = %v", got, tc.want)
			}
		})
	}
}

func quarantineNowNoT(k *Auth) {
	for i := 0; i < apiKeyQuarantineThreshold; i++ {
		k.MarkFailure("upstream 502")
	}
}

// TestReportUpstreamErrorBranches pins the five documented mappings. None of
// this is obvious from the call sites, and all of it is load-bearing: the
// 401/403/429 paths must not touch ConsecutiveFailures (that counter drives the
// sticky hard-fail, and a credential that merely exhausted its window is not a
// broken credential), while 5xx must not set a cooldown.
func TestReportUpstreamErrorBranches(t *testing.T) {
	p := NewPool(nil, nil, time.Minute, false, "")

	t.Run("429 rate limits without touching failures", func(t *testing.T) {
		a := lastResortOAuth("o429")
		p.ReportUpstreamError(a, 429, time.Time{})
		s := a.Snapshot()
		if s.Consecutive429s != 1 {
			t.Fatalf("Consecutive429s = %d, want 1", s.Consecutive429s)
		}
		if s.ConsecutiveFailures != 0 {
			t.Fatalf("ConsecutiveFailures = %d; 429 must never advance the hard-fail counter", s.ConsecutiveFailures)
		}
		if !a.IsQuotaExceeded(time.Now()) {
			t.Fatal("429 must park the credential in a cooldown")
		}
		// Default backoff for the first 429.
		if d := time.Until(s.QuotaResetAt); d <= 0 || d > 30*time.Second {
			t.Fatalf("first-429 cooldown = %v, want ~30s", d)
		}
	})

	t.Run("429 honours upstream Retry-After", func(t *testing.T) {
		a := lastResortOAuth("o429b")
		reset := time.Now().Add(7 * time.Minute)
		p.ReportUpstreamError(a, 429, reset)
		if got := a.Snapshot().QuotaResetAt; !got.Equal(reset) {
			t.Fatalf("QuotaResetAt = %v, want the supplied %v", got, reset)
		}
	})

	t.Run("429 cooldown escalates", func(t *testing.T) {
		if got := rateLimit429Cooldown(1); got != 30*time.Second {
			t.Fatalf("n=1 → %v, want 30s", got)
		}
		if got := rateLimit429Cooldown(2); got != time.Minute {
			t.Fatalf("n=2 → %v, want 1m", got)
		}
		if got := rateLimit429Cooldown(3); got != 2*time.Minute {
			t.Fatalf("n=3 → %v, want 2m", got)
		}
		if got := rateLimit429Cooldown(4); got != 5*time.Minute {
			t.Fatalf("n=4 → %v, want 5m", got)
		}
		if got := rateLimit429Cooldown(9); got != 10*time.Minute {
			t.Fatalf("n=9 → %v, want the 10m cap", got)
		}
	})

	t.Run("403 cools down for a minute", func(t *testing.T) {
		a := lastResortOAuth("o403")
		p.ReportUpstreamError(a, 403, time.Time{})
		s := a.Snapshot()
		if s.ConsecutiveFailures != 0 {
			t.Fatalf("ConsecutiveFailures = %d, want 0", s.ConsecutiveFailures)
		}
		if d := time.Until(s.QuotaResetAt); d <= 0 || d > time.Minute {
			t.Fatalf("403 cooldown = %v, want ~1m", d)
		}
	})

	t.Run("401 discards the supplied resetAt", func(t *testing.T) {
		a := lastResortOAuth("o401")
		// A Retry-After on a 401 is a rate-limit hint unrelated to the bad
		// credential; honouring it would park the account for hours.
		p.ReportUpstreamError(a, 401, time.Now().Add(6*time.Hour))
		s := a.Snapshot()
		if d := time.Until(s.QuotaResetAt); d <= 0 || d > time.Minute {
			t.Fatalf("401 cooldown = %v, want ~1m regardless of resetAt", d)
		}
		if s.ConsecutiveFailures != 0 {
			t.Fatalf("ConsecutiveFailures = %d, want 0", s.ConsecutiveFailures)
		}
		if s.Consecutive401s != 0 {
			t.Fatalf("Consecutive401s = %d; ReportUpstreamError uses the quota path, not MarkAuthRejection", s.Consecutive401s)
		}
	})

	t.Run("529 marks a failure with no cooldown", func(t *testing.T) {
		a := lastResortOAuth("o529")
		p.ReportUpstreamError(a, 529, time.Now().Add(time.Hour))
		s := a.Snapshot()
		if s.ConsecutiveFailures != 1 {
			t.Fatalf("ConsecutiveFailures = %d, want 1", s.ConsecutiveFailures)
		}
		if a.IsQuotaExceeded(time.Now()) {
			t.Fatal("529 is transient overload; it must not park the credential")
		}
	})

	t.Run("500 marks a failure with no cooldown", func(t *testing.T) {
		a := lastResortOAuth("o500")
		p.ReportUpstreamError(a, 502, time.Time{})
		s := a.Snapshot()
		if s.ConsecutiveFailures != 1 {
			t.Fatalf("ConsecutiveFailures = %d, want 1", s.ConsecutiveFailures)
		}
		if a.IsQuotaExceeded(time.Now()) {
			t.Fatal("5xx must not park the credential")
		}
	})

	t.Run("4xx below 500 that isn't 401/403/429 is ignored", func(t *testing.T) {
		a := lastResortOAuth("o400")
		p.ReportUpstreamError(a, 400, time.Time{})
		s := a.Snapshot()
		if s.ConsecutiveFailures != 0 || !s.LastFailure.IsZero() {
			t.Fatalf("a client-side 400 must not touch credential health: %+v", s)
		}
	})

	t.Run("nil auth is a no-op", func(t *testing.T) {
		p.ReportUpstreamError(nil, 429, time.Time{})
	})
}

// TestPoolHealthCountsServingNotHealthy is the status page's contract: nine
// dead credentials and one half-open channel is a pool that is still serving
// and must not be painted green.
func TestPoolHealthCountsServingNotHealthy(t *testing.T) {
	o1 := lastResortOAuth("o1")
	o1.MarkHardFailure("account disabled")
	o2 := lastResortOAuth("o2")
	o2.MarkHardFailure("account disabled")

	k := lastResortKey("halfopen", 0)
	k.MarkHardFailure("401 from relay") // API key: opens the breaker, strike 1
	// Walk the pause deadline into the past: the circuit is half-open —
	// routable, and unverified until something succeeds on it.
	k.mu.Lock()
	k.QuarantineUntil = time.Now().Add(-time.Second)
	k.mu.Unlock()

	other := lastResortKey("openai-key", 0)
	other.Provider = ProviderOpenAI

	p := NewPool([]*Auth{o1, o2}, []*Auth{k, other}, time.Minute, false, "")

	h := p.Health("anthropic")
	if h.Total != 3 {
		t.Fatalf("Total = %d, want 3 (both OAuth + the anthropic key, not the openai one)", h.Total)
	}
	if h.Serving != 1 {
		t.Fatalf("Serving = %d, want 1", h.Serving)
	}
	if h.ByState[HealthHalfOpen] != 1 {
		t.Fatalf("ByState[half_open] = %d, want 1: a channel whose pause merely elapsed is not recovered", h.ByState[HealthHalfOpen])
	}
	if h.ByState[HealthHardFailed] != 2 {
		t.Fatalf("ByState[hard_failed] = %d, want 2", h.ByState[HealthHardFailed])
	}
	if !h.Available() {
		t.Fatal("Available() must be true while one credential can still take a request")
	}
	if h.Worst != HealthHardFailed {
		t.Fatalf("Worst = %s, want hard_failed", h.Worst)
	}
	// And the half-open channel really is the one Acquire hands back.
	got, res := acquireResult(p, "s1")
	if got == nil || got.ID != "halfopen" {
		t.Fatalf("Acquire returned %v, want the half-open channel Health() reported as serving", got)
	}
	if res.LastResort {
		t.Fatal("a half-open channel is a normal candidate, not a last resort")
	}

	// The other provider is judged independently.
	if oh := p.Health("openai"); oh.Total != 1 || oh.Serving != 1 {
		t.Fatalf("openai pool = %+v, want 1 total / 1 serving", oh)
	}
}
