package auth

import (
	"context"
	"testing"
	"time"
)

func quarantineTestKey(id string) *Auth {
	return &Auth{
		ID:          id,
		Kind:        KindAPIKey,
		Provider:    ProviderAnthropic,
		Label:       id,
		AccessToken: "sk-ant-" + id,
	}
}

// TestAPIKeyQuarantineOpensOnlyAtThreshold pins the tolerance: a shared relay
// emits the occasional 502 while working fine, so a channel must survive
// isolated failures and only pause once the failures are sustained.
func TestAPIKeyQuarantineOpensOnlyAtThreshold(t *testing.T) {
	k := quarantineTestKey("relayA")
	now := time.Now()

	for i := 1; i < apiKeyQuarantineThreshold; i++ {
		k.MarkFailure("upstream 502")
		if k.IsQuarantined(now) {
			t.Fatalf("circuit opened after %d failure(s); threshold is %d", i, apiKeyQuarantineThreshold)
		}
		if !k.IsHealthy() {
			t.Fatalf("channel must stay in rotation below the threshold (after %d failures)", i)
		}
	}

	k.MarkFailure("upstream 502")
	if !k.IsQuarantined(time.Now()) {
		t.Fatalf("circuit must open at %d consecutive failures", apiKeyQuarantineThreshold)
	}
	if k.IsHealthy() {
		t.Fatal("a paused channel must read unhealthy so the pool skips it")
	}
	// Never sticky: the whole point is that no operator action is required.
	if k.IsHardFailed() {
		t.Fatal("quarantine must never set the sticky hard-failure flag on an API key")
	}
}

// TestAPIKeyQuarantineExpiresAndProbes covers the half-open transition: once
// the deadline passes the channel is offered again so a single request can
// discover whether the upstream came back.
func TestAPIKeyQuarantineExpiresAndProbes(t *testing.T) {
	k := quarantineTestKey("relayB")
	for i := 0; i < apiKeyQuarantineThreshold; i++ {
		k.MarkFailure("upstream 502")
	}
	until, strikes := k.QuarantineSnapshot()
	if until.IsZero() || strikes != 1 {
		t.Fatalf("QuarantineSnapshot() = (%v, %d), want a deadline and 1 strike", until, strikes)
	}

	// Past the deadline the circuit goes half-open — back in rotation.
	if k.IsQuarantined(until.Add(time.Second)) {
		t.Fatal("an expired quarantine must not keep the channel paused")
	}
	if !k.IsHealthy() {
		t.Fatal("after the pause expires the channel must be offered for a probe")
	}
	// The strike count survives the pause so a failed probe backs off further
	// rather than retrying at the shortest interval forever.
	if _, strikes = k.QuarantineSnapshot(); strikes != 1 {
		t.Fatalf("strikes = %d after expiry, want the count preserved for backoff", strikes)
	}
}

// TestAPIKeyQuarantineBacksOffExponentially proves a failed probe lengthens
// the pause instead of hammering a dead upstream at a fixed interval.
func TestAPIKeyQuarantineBacksOffExponentially(t *testing.T) {
	k := quarantineTestKey("relayC")
	var prev time.Duration
	for round := 1; round <= 4; round++ {
		for i := 0; i < apiKeyQuarantineThreshold; i++ {
			k.MarkFailure("upstream 502")
		}
		until, strikes := k.QuarantineSnapshot()
		if strikes != round {
			t.Fatalf("round %d: strikes = %d, want %d", round, strikes, round)
		}
		d := time.Until(until)
		// ±20% jitter, so compare against the nominal ladder with slack rather
		// than exact equality.
		nominal := apiKeyQuarantineBackoff(round)
		if d < time.Duration(float64(nominal)*0.75) || d > time.Duration(float64(nominal)*1.25) {
			t.Fatalf("round %d: pause %v is outside the jittered band around %v", round, d, nominal)
		}
		if round > 1 && d <= prev {
			t.Fatalf("round %d: pause %v did not grow beyond the previous %v", round, d, prev)
		}
		prev = d

		// Simulate the probe firing after the deadline and failing again.
		k.QuarantineUntil = time.Time{}
	}
}

// TestAPIKeyQuarantineBackoffIsCapped guards the single-key deployment: the
// pause is also the maximum time that model is unservable, so it must not
// grow without bound.
func TestAPIKeyQuarantineBackoffIsCapped(t *testing.T) {
	const cap = 15 * time.Minute
	for n := 1; n <= 50; n++ {
		if got := apiKeyQuarantineBackoff(n); got > cap {
			t.Fatalf("apiKeyQuarantineBackoff(%d) = %v, exceeds the %v ceiling", n, got, cap)
		}
	}
	if apiKeyQuarantineBackoff(99) != cap {
		t.Fatalf("backoff must plateau at %v", cap)
	}
}

// TestAPIKeySuccessClosesCircuit is the auto-recovery contract: one good
// response restores the channel completely, with no operator involvement and
// no lingering pessimism in the backoff ladder.
func TestAPIKeySuccessClosesCircuit(t *testing.T) {
	k := quarantineTestKey("relayD")
	for i := 0; i < apiKeyQuarantineThreshold*2; i++ {
		k.MarkFailure("upstream 502")
	}
	if !k.IsQuarantined(time.Now()) {
		t.Fatal("precondition: circuit should be open")
	}

	k.MarkSuccess()

	if k.IsQuarantined(time.Now()) {
		t.Fatal("a successful exchange must close the circuit immediately")
	}
	if !k.IsHealthy() {
		t.Fatal("a recovered channel must be back in full rotation")
	}
	until, strikes := k.QuarantineSnapshot()
	if !until.IsZero() || strikes != 0 {
		t.Fatalf("recovery must reset the ladder; got (%v, %d)", until, strikes)
	}
}

// TestAPIKeyCredentialRejectionPausesImmediately: a revoked key is definitive,
// so it should stop being re-presented on every request after the first
// rejection rather than waiting for three.
func TestAPIKeyCredentialRejectionPausesImmediately(t *testing.T) {
	k := quarantineTestKey("relayE")
	k.MarkHardFailure("upstream 401")

	if !k.IsQuarantined(time.Now()) {
		t.Fatal("a definitive credential rejection must pause the channel on the first strike")
	}
	if k.IsHardFailed() {
		t.Fatal("an API-key channel must still never be auto-retired")
	}
	// And it is still self-healing — a spuriously-rejected relay returns.
	until, _ := k.QuarantineSnapshot()
	if k.IsQuarantined(until.Add(time.Second)) {
		t.Fatal("even a credential rejection must expire on its own")
	}
}

// TestOAuthUnaffectedByQuarantine: the breaker is API-key-only. OAuth keeps
// its existing sticky-hard-failure semantics, which the ban-detection and
// token-rotation logic both depend on.
func TestOAuthUnaffectedByQuarantine(t *testing.T) {
	o := &Auth{ID: "oauthA", Kind: KindOAuth, Provider: ProviderAnthropic, AccessToken: "t"}
	for i := 0; i < apiKeyQuarantineThreshold*3; i++ {
		o.MarkFailure("upstream 502")
	}
	if o.IsQuarantined(time.Now()) {
		t.Fatal("OAuth credentials must not enter the API-key quarantine")
	}
	if until, strikes := o.QuarantineSnapshot(); !until.IsZero() || strikes != 0 {
		t.Fatalf("OAuth quarantine state must stay empty; got (%v, %d)", until, strikes)
	}
	if !o.IsHardFailed() {
		t.Fatal("OAuth must still auto-hard-fail at its own threshold")
	}
}

// TestPoolSkipsQuarantinedAPIKey is the end-to-end rotation proof: with the
// first-priority key paused, Acquire must hand out the next one instead of
// re-serving the broken channel.
func TestPoolSkipsQuarantinedAPIKey(t *testing.T) {
	first := quarantineTestKey("relay-first")
	first.Order = 1
	second := quarantineTestKey("relay-second")
	second.Order = 2
	p := NewPool(nil, []*Auth{first, second}, 5*time.Minute, false, "")

	got := p.Acquire(context.Background(), ProviderAnthropic, "tok", "", "claude-opus-4-8", "")
	if got == nil || got.ID != first.ID {
		t.Fatalf("expected the highest-priority key first, got %v", got)
	}
	p.Release(ProviderAnthropic, "tok", "")

	// The first channel goes bad.
	for i := 0; i < apiKeyQuarantineThreshold; i++ {
		first.MarkFailure("upstream 502")
	}

	// A fresh session must now be routed to the second key. Unstick first so
	// the sticky assignment doesn't mask the health filter.
	p.Unstick(ProviderAnthropic, "tok", "")
	got = p.Acquire(context.Background(), ProviderAnthropic, "tok", "", "claude-opus-4-8", "")
	if got == nil {
		t.Fatal("a paused channel must fail over to the next key, not exhaust the pool")
	}
	if got.ID != second.ID {
		t.Fatalf("Acquire returned %s, want the un-paused %s", got.ID, second.ID)
	}
}
