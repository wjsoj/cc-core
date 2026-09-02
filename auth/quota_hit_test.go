package auth

import (
	"testing"
	"time"
)

// LastQuotaHit is the measurement quotaestimate anchors on. It must survive
// the two things that wipe the live cooldown — the reset time passing and an
// operator clearing it — or the estimate would only ever be computable while
// the credential is still parked.
func TestLastQuotaHitOutlivesTheCooldown(t *testing.T) {
	a := &Auth{ID: "x", Kind: KindOAuth, Provider: ProviderAnthropic}

	resetAt := time.Now().Add(100 * time.Hour)
	a.MarkUsageLimitReached(resetAt)
	if !a.IsQuotaExceeded(time.Now()) {
		t.Fatal("parked")
	}
	hit := a.Snapshot().LastQuotaHit
	if hit.At.IsZero() || !hit.ResetAt.Equal(resetAt) {
		t.Fatalf("hit = %+v", hit)
	}

	a.ClearQuota()
	if a.IsQuotaExceeded(time.Now()) {
		t.Fatal("cleared")
	}
	if got := a.Snapshot().LastQuotaHit; got != hit {
		t.Fatalf("ClearQuota wiped the measurement: %+v", got)
	}

	// Expiry path: a reset already in the past auto-clears on the next read.
	b := &Auth{ID: "y", Kind: KindOAuth, Provider: ProviderAnthropic}
	b.MarkUsageLimitReached(time.Now().Add(-time.Second))
	if b.IsQuotaExceeded(time.Now()) {
		t.Fatal("expired cooldown must self-clear")
	}
	if b.Snapshot().LastQuotaHit.At.IsZero() {
		t.Fatal("expiry wiped the measurement")
	}
}

// The first rejection of a window is the measurement. A second 429 for the
// same window (a stray in-flight request, or an operator clearing quota and
// the next call bouncing) must not move the anchor later and shorten the
// observed run; a rejection naming a NEW reset is a new window and replaces
// it.
func TestLastQuotaHitIsFirstRejectionPerWindow(t *testing.T) {
	a := &Auth{ID: "x", Kind: KindOAuth, Provider: ProviderAnthropic}
	resetAt := time.Now().Add(100 * time.Hour)

	a.MarkUsageLimitReached(resetAt)
	first := a.Snapshot().LastQuotaHit

	time.Sleep(2 * time.Millisecond)
	// Same window: the body stamp differs from the header stamp by rounding.
	a.MarkUsageLimitReached(resetAt.Add(30 * time.Second))
	if got := a.Snapshot().LastQuotaHit; got != first {
		t.Fatalf("second rejection of the same window moved the anchor: %+v -> %+v", first, got)
	}

	nextWeek := resetAt.Add(7 * 24 * time.Hour)
	a.MarkUsageLimitReached(nextWeek)
	got := a.Snapshot().LastQuotaHit
	if !got.ResetAt.Equal(nextWeek) || !got.At.After(first.At) {
		t.Fatalf("new window must replace the anchor: %+v", got)
	}
}

// Generic 429/401/403 cooldowns are schedules, not usage-limit signals, and
// must not masquerade as a window measurement.
func TestGenericCooldownIsNotAQuotaHit(t *testing.T) {
	a := &Auth{ID: "x", Kind: KindOAuth, Provider: ProviderAnthropic}
	a.MarkQuotaExceeded(time.Now().Add(time.Minute))
	if !a.Snapshot().LastQuotaHit.At.IsZero() {
		t.Fatal("MarkQuotaExceeded recorded a hit")
	}
	a.MarkModelRateLimited(ModelScopeAnthropicFable, time.Now().Add(time.Hour))
	if !a.Snapshot().LastQuotaHit.At.IsZero() {
		t.Fatal("a model-scoped limit recorded an account-wide hit")
	}
}

// A panel must be able to tell "the window filled" from "we are pausing
// after a generic 429": both are HealthQuota, only the former is UsageLimit.
func TestQuotaStateDistinguishesUsageLimitFromThrottlePause(t *testing.T) {
	a := &Auth{ID: "x", Kind: KindOAuth, Provider: ProviderAnthropic}
	a.MarkQuotaExceeded(time.Now().Add(30 * time.Second))
	rep := a.HealthState()
	if rep.State != HealthQuota || rep.UsageLimit {
		t.Fatalf("throttle pause: %+v", rep)
	}
	if a.Snapshot().QuotaUsageLimit {
		t.Fatal("snapshot")
	}

	b := &Auth{ID: "y", Kind: KindOAuth, Provider: ProviderAnthropic}
	resetAt := time.Now().Add(100 * time.Hour)
	b.MarkUsageLimitReached(resetAt)
	if rep := b.HealthState(); rep.State != HealthQuota || !rep.UsageLimit {
		t.Fatalf("usage limit: %+v", rep)
	}
	// Operator clears it, the next request bounces off the same window and
	// comes back through the generic path with the upstream's reset stamp:
	// still the usage limit.
	b.ClearQuota()
	b.MarkQuotaExceeded(resetAt.Add(10 * time.Second))
	if rep := b.HealthState(); !rep.UsageLimit {
		t.Fatalf("same window re-bounce: %+v", rep)
	}
	// A generic pause with an unrelated (short) reset is a throttle again.
	b.ClearQuota()
	b.MarkQuotaExceeded(time.Now().Add(time.Minute))
	if rep := b.HealthState(); rep.UsageLimit {
		t.Fatalf("throttle after a usage limit: %+v", rep)
	}
}
