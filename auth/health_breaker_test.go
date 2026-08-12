package auth

import (
	"testing"
	"time"
)

// The failure modes below are the ones a relay API key actually dies of. Until
// the breaker learned to read the 429 and 401 counters, none of them could
// open it: MarkRateLimited and MarkAuthRejection keep their own counters and
// never touch ConsecutiveFailures, which was the only thing the breaker
// looked at. A key could therefore refuse every request forever and stay in
// rotation, cycling try → cooldown → try. These tests pin the new behaviour.

func breakerTestKey(id string) *Auth {
	return &Auth{ID: id, Kind: KindAPIKey, Provider: ProviderAnthropic, AccessToken: "sk-" + id}
}

// A sustained run of unexplained 429s must eventually pause the channel so
// traffic rotates away, instead of paying a doomed round-trip per request.
func TestAPIKey429OpensBreaker(t *testing.T) {
	k := breakerTestKey("relay429")

	for i := 1; i < apiKey429QuarantineThreshold; i++ {
		k.MarkRateLimited("upstream 429")
		if k.IsQuarantined(time.Now()) {
			t.Fatalf("breaker opened after %d 429(s); threshold is %d", i, apiKey429QuarantineThreshold)
		}
		if !k.IsHealthy() {
			t.Fatalf("channel must keep serving below the 429 threshold (after %d)", i)
		}
	}

	k.MarkRateLimited("upstream 429")
	if !k.IsQuarantined(time.Now()) {
		t.Fatalf("breaker must open at %d consecutive 429s", apiKey429QuarantineThreshold)
	}
	if k.IsHealthy() {
		t.Fatal("a paused channel must read unhealthy so the pool skips it")
	}
	// Bounded, never sticky — the whole reason API keys are exempt from
	// auto-retirement is that the only route for a model must self-heal.
	if k.IsHardFailed() {
		t.Fatal("429s must never sticky-retire an API-key channel")
	}
	until, _ := k.QuarantineSnapshot()
	if k.IsQuarantined(until.Add(time.Second)) {
		t.Fatal("the 429 pause must expire on its own")
	}
}

// A 401 on a key that cannot rotate is a much stronger signal than a 401 on an
// OAuth account mid-refresh, so it trips far sooner — but still only ever into
// the bounded pause.
func TestAPIKey401OpensBreakerButNeverHardFails(t *testing.T) {
	k := breakerTestKey("relay401")

	for i := 1; i < apiKey401QuarantineThreshold; i++ {
		k.MarkAuthRejection("upstream 401")
		if k.IsQuarantined(time.Now()) {
			t.Fatalf("breaker opened after %d 401(s); threshold is %d", i, apiKey401QuarantineThreshold)
		}
	}

	k.MarkAuthRejection("upstream 401")
	if !k.IsQuarantined(time.Now()) {
		t.Fatalf("breaker must open at %d consecutive 401s", apiKey401QuarantineThreshold)
	}

	// However many more arrive, the sticky flag must stay clear.
	for i := 0; i < auth401HardFailureThreshold*3; i++ {
		k.MarkAuthRejection("upstream 401")
		if k.IsHardFailed() {
			t.Fatal("an API-key channel must never be auto-retired by 401s")
		}
	}

	// The 401 threshold must stay meaningfully below OAuth's: the rationale
	// for OAuth's generosity (the token-rotation race) does not exist here.
	if apiKey401QuarantineThreshold >= auth401HardFailureThreshold {
		t.Fatalf("apiKey401QuarantineThreshold (%d) must be well below auth401HardFailureThreshold (%d)",
			apiKey401QuarantineThreshold, auth401HardFailureThreshold)
	}
}

// 429 is throttling, not brokenness: it must be tolerated more than an
// outright failure, or a busy-but-healthy relay backs off like a dead one.
func TestAPIKey429IsMoreTolerantThanFailure(t *testing.T) {
	if apiKey429QuarantineThreshold <= apiKeyQuarantineThreshold {
		t.Fatalf("429 threshold (%d) must exceed the generic failure threshold (%d)",
			apiKey429QuarantineThreshold, apiKeyQuarantineThreshold)
	}
}

// A 429 that carries an explicit Retry-After is an instruction, not evidence
// of a broken channel. Honour the wait; do not also distrust the key.
func TestAPIKeyRetryAfter429DoesNotStrike(t *testing.T) {
	k := breakerTestKey("relay-polite")
	retryAt := time.Now().Add(12 * time.Second)

	for i := 0; i < apiKey429QuarantineThreshold*3; i++ {
		k.MarkRateLimitedRetryAfter("upstream 429 (Retry-After: 12)", retryAt)
	}
	if k.IsQuarantined(time.Now()) {
		t.Fatal("a cooperative upstream that says when to return must not also earn a breaker pause")
	}
	if _, strikes := k.QuarantineSnapshot(); strikes != 0 {
		t.Fatalf("strikes = %d after Retry-After-bearing 429s, want 0", strikes)
	}

	// Silence is what we infer from. One unexplained 429 on top of an already
	// long run trips immediately, because the run itself is the evidence.
	k.MarkRateLimited("upstream 429 (no Retry-After)")
	if !k.IsQuarantined(time.Now()) {
		t.Fatal("an unexplained 429 past the threshold must open the breaker")
	}

	// The counter itself advances either way — stealth-ban detection must not
	// be blinded by a polite upstream.
	if k.Consecutive429s != apiKey429QuarantineThreshold*3+1 {
		t.Fatalf("Consecutive429s = %d, want every 429 counted regardless of Retry-After", k.Consecutive429s)
	}
}

// Regression guard: OAuth behaviour must be byte-for-byte what it was. Both
// of these thresholds retire a scarce paid subscription until a human
// intervenes, so a change here is a production incident.
func TestOAuth429And401HardFailUnchanged(t *testing.T) {
	o := &Auth{ID: "sub429", Kind: KindOAuth, Provider: ProviderAnthropic}
	for i := 0; i < rateLimit429HardFailureThreshold-1; i++ {
		o.MarkRateLimited("upstream 429")
		if o.IsHardFailed() {
			t.Fatalf("OAuth hard-failed after %d 429s, before the %d threshold", i+1, rateLimit429HardFailureThreshold)
		}
	}
	o.MarkRateLimited("upstream 429")
	if !o.IsHardFailed() {
		t.Fatalf("OAuth must still hard-fail at %d consecutive 429s (suspected stealth ban)", rateLimit429HardFailureThreshold)
	}
	if until, strikes := o.QuarantineSnapshot(); !until.IsZero() || strikes != 0 {
		t.Fatalf("the breaker is API-key-only; OAuth got (%v, %d)", until, strikes)
	}

	a := &Auth{ID: "sub401", Kind: KindOAuth, Provider: ProviderAnthropic}
	for i := 0; i < auth401HardFailureThreshold-1; i++ {
		a.MarkAuthRejection("upstream 401")
		if a.IsHardFailed() {
			t.Fatalf("OAuth hard-failed after %d 401s, before the %d threshold", i+1, auth401HardFailureThreshold)
		}
	}
	a.MarkAuthRejection("upstream 401")
	if !a.IsHardFailed() {
		t.Fatalf("OAuth must still hard-fail at %d consecutive 401s", auth401HardFailureThreshold)
	}
	if until, strikes := a.QuarantineSnapshot(); !until.IsZero() || strikes != 0 {
		t.Fatalf("the breaker is API-key-only; OAuth got (%v, %d)", until, strikes)
	}
}

// A Retry-After-bearing 429 must not weaken OAuth's stealth-ban detection: the
// header describes this request's timing, not the account's standing.
func TestOAuthRetryAfter429StillCountsTowardStealthBan(t *testing.T) {
	o := &Auth{ID: "subpolite", Kind: KindOAuth, Provider: ProviderAnthropic}
	retryAt := time.Now().Add(30 * time.Second)
	for i := 0; i < rateLimit429HardFailureThreshold; i++ {
		o.MarkRateLimitedRetryAfter("upstream 429", retryAt)
	}
	if !o.IsHardFailed() {
		t.Fatal("OAuth stealth-ban detection must count 429s that carried a Retry-After")
	}
}

// One good response is the only thing that closes the circuit, and it must
// clear every counter that can reopen it.
func TestMarkSuccessResetsEveryBreakerInput(t *testing.T) {
	k := breakerTestKey("relay-recover")
	for i := 0; i < apiKey429QuarantineThreshold; i++ {
		k.MarkRateLimited("upstream 429")
	}
	for i := 0; i < apiKey401QuarantineThreshold; i++ {
		k.MarkAuthRejection("upstream 401")
	}
	k.MarkFailure("upstream 502")
	if !k.IsQuarantined(time.Now()) {
		t.Fatal("precondition: the breaker should be open")
	}

	k.MarkSuccess()

	if k.ConsecutiveFailures != 0 || k.Consecutive429s != 0 || k.Consecutive401s != 0 {
		t.Fatalf("counters after MarkSuccess = (%d, %d, %d), want all zero",
			k.ConsecutiveFailures, k.Consecutive429s, k.Consecutive401s)
	}
	until, strikes := k.QuarantineSnapshot()
	if !until.IsZero() || strikes != 0 {
		t.Fatalf("MarkSuccess must reset the ladder; got (%v, %d)", until, strikes)
	}
	if got := k.HealthState(); got.State != HealthHealthy {
		t.Fatalf("state after recovery = %q, want %q", got.State, HealthHealthy)
	}
}

// "Mark healthy" must actually mark it healthy — including releasing a pause
// the operator can see in the panel. "Clear quota" must not, because it makes
// no claim about the credential itself.
func TestClearFailureClearsBreakerAndClearQuotaDoesNot(t *testing.T) {
	k := breakerTestKey("relay-clear")
	for i := 0; i < apiKey429QuarantineThreshold; i++ {
		k.MarkRateLimited("upstream 429")
	}
	k.MarkQuotaExceeded(time.Now().Add(time.Hour))
	if !k.IsQuarantined(time.Now()) {
		t.Fatal("precondition: the breaker should be open")
	}

	k.ClearQuota()
	if k.IsQuotaExceeded(time.Now()) {
		t.Fatal("ClearQuota must drop the cooldown")
	}
	if !k.IsQuarantined(time.Now()) {
		t.Fatal("ClearQuota must NOT silently release a channel the breaker distrusts")
	}

	k.ClearFailure()
	if k.IsQuarantined(time.Now()) {
		t.Fatal("ClearFailure (Mark healthy) must release the breaker pause")
	}
	if _, strikes := k.QuarantineSnapshot(); strikes != 0 {
		t.Fatalf("strikes = %d after ClearFailure; a surviving count would send the next trip to a late backoff rung", strikes)
	}
	if k.Consecutive429s != 0 || k.Consecutive401s != 0 {
		t.Fatal("ClearFailure must reset the counters that feed the breaker")
	}
	if got := k.HealthState(); got.State != HealthHealthy {
		t.Fatalf("state after ClearFailure = %q, want %q", got.State, HealthHealthy)
	}
}

// The half-open window is the reason HealthState exists. An expired pause is
// permission to probe, not proof of recovery; painting it green is the exact
// bug the state was added to kill.
func TestBreakerExpiryIsHalfOpenNotHealthy(t *testing.T) {
	k := breakerTestKey("relay-halfopen")
	for i := 0; i < apiKey429QuarantineThreshold; i++ {
		k.MarkRateLimited("upstream 429")
	}
	if got := k.HealthState(); got.State != HealthCooling {
		t.Fatalf("state while paused = %q, want %q", got.State, HealthCooling)
	}

	// Fast-forward past the deadline without sleeping out the backoff.
	k.mu.Lock()
	k.QuarantineUntil = time.Now().Add(-time.Second)
	k.mu.Unlock()

	got := k.HealthState()
	if got.State != HealthHalfOpen {
		t.Fatalf("state after the pause elapsed = %q, want %q — an expired deadline is not a recovery", got.State, HealthHalfOpen)
	}
	if !got.Serving {
		t.Fatal("a half-open channel must be routable; that is what lets the probe happen")
	}

	k.MarkSuccess()
	if got := k.HealthState(); got.State != HealthHealthy {
		t.Fatalf("state after a successful probe = %q, want %q", got.State, HealthHealthy)
	}
}

// The same half-open contract for the 401 path, which reaches the breaker
// through a different counter.
func TestBreakerExpiryAfter401IsHalfOpen(t *testing.T) {
	k := breakerTestKey("relay-halfopen401")
	for i := 0; i < apiKey401QuarantineThreshold; i++ {
		k.MarkAuthRejection("upstream 401 invalid api key")
	}
	k.mu.Lock()
	k.QuarantineUntil = time.Now().Add(-time.Second)
	k.mu.Unlock()

	if got := k.HealthState(); got.State != HealthHalfOpen {
		t.Fatalf("state after a 401 pause elapsed = %q, want %q", got.State, HealthHalfOpen)
	}
	if k.IsHardFailed() {
		t.Fatal("still never sticky")
	}
}

// Below every threshold a deteriorating credential used to be invisible: the
// panel showed green right up to the moment it dropped out. Degraded is that
// missing window.
func TestSubThresholdFailuresReadDegraded(t *testing.T) {
	o := &Auth{ID: "sub-degraded", Kind: KindOAuth, Provider: ProviderAnthropic}
	o.MarkFailure("upstream 500")
	o.MarkFailure("upstream 500")

	got := o.HealthState()
	if got.State != HealthDegraded {
		t.Fatalf("state after 2 failures = %q, want %q", got.State, HealthDegraded)
	}
	if !got.Serving {
		t.Fatal("degraded credentials keep taking traffic on purpose — skipping them is only safe when someone else is available")
	}
	if got.ConsecutiveFailures != 2 {
		t.Fatalf("report carried %d consecutive failures, want 2", got.ConsecutiveFailures)
	}
	if o.IsHardFailed() {
		t.Fatalf("2 failures must not reach the hard-fail threshold of %d", hardFailureThreshold)
	}
}

// An API key throttling below the breaker threshold is likewise visible now:
// recording LastFailure on the 429 path is what surfaces it.
func TestAPIKeySubThreshold429ReadsDegraded(t *testing.T) {
	k := breakerTestKey("relay-degraded")
	k.MarkRateLimited("upstream 429")

	got := k.HealthState()
	if got.State != HealthDegraded {
		t.Fatalf("state after 1 unexplained 429 = %q, want %q", got.State, HealthDegraded)
	}
	if !got.Serving {
		t.Fatal("a throttled channel below the threshold must keep serving")
	}
	// And it must not have leaked into the routing predicate, which for API
	// keys is the breaker alone.
	if !k.IsHealthy() {
		t.Fatal("IsHealthy for an API key must track the breaker, not the degraded heuristic")
	}
}

// Snapshot is what the admin panel actually renders; the classification must
// survive the trip through AuthInfo.
func TestSnapshotCarriesBreakerState(t *testing.T) {
	k := breakerTestKey("relay-snapshot")
	for i := 0; i < apiKey429QuarantineThreshold; i++ {
		k.MarkRateLimited("upstream 429")
	}
	info := k.Snapshot()
	if info.State != HealthCooling {
		t.Fatalf("AuthInfo.State = %q, want %q", info.State, HealthCooling)
	}
	if info.QuarantineStrikes != 1 || info.QuarantineUntil.IsZero() {
		t.Fatalf("snapshot lost the pause: (%v, %d)", info.QuarantineUntil, info.QuarantineStrikes)
	}
	if info.Consecutive429s != apiKey429QuarantineThreshold {
		t.Fatalf("AuthInfo.Consecutive429s = %d, want %d", info.Consecutive429s, apiKey429QuarantineThreshold)
	}
}
