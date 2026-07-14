package auth

import (
	"testing"
	"time"
)

// A degraded (repeatedly-failing but not hard-failed) OAuth credential must be
// able to recover on its own.
//
// Regression test for the 2026-07-14 prod outage: ConsecutiveFailures >= 2 made
// IsHealthy() return false with no time-based way back. Acquire skips unhealthy
// credentials, so the credential got no traffic, so MarkSuccess never ran, so
// the counter never reset — a terminal state reachable from a transient upstream
// flap. Both codex OAuth credentials landed there within the same minute and the
// entire pool went dark (every client got 503) until an operator cleared the
// failures by hand.
func TestDegradedOAuthRecoversWithoutManualClear(t *testing.T) {
	oauth := &Auth{ID: "sub", Kind: KindOAuth, Provider: ProviderOpenAI}

	// Two failures: enough to degrade, short of hardFailureThreshold.
	oauth.MarkFailure("http2: client connection lost")
	oauth.MarkFailure("http2: client connection lost")

	if oauth.IsHardFailed() {
		t.Fatalf("2 failures should not hard-fail (threshold is %d)", hardFailureThreshold)
	}
	if oauth.IsHealthy() {
		t.Fatalf("a credential that just failed twice should be quarantined")
	}

	// Still quarantined shortly after — the probe must not fire immediately, or
	// a genuinely-broken credential would be hammered.
	oauth.LastFailure = time.Now().Add(-degradedProbeAfter / 2)
	if oauth.IsHealthy() {
		t.Fatalf("credential should stay quarantined before degradedProbeAfter elapses")
	}

	// Once degradedProbeAfter has elapsed it must re-enter rotation so a single
	// request can prove whether the upstream recovered.
	oauth.LastFailure = time.Now().Add(-degradedProbeAfter - time.Second)
	if !oauth.IsHealthy() {
		t.Fatalf("degraded credential never recovers: Acquire will skip it forever, so MarkSuccess can never reset ConsecutiveFailures (%d)", oauth.ConsecutiveFailures)
	}

	// The admin panel must agree with the routing decision.
	healthy, hardFailure, _, _ := oauth.HealthSnapshot()
	if !healthy || hardFailure {
		t.Fatalf("HealthSnapshot disagrees with IsHealthy: healthy=%v hardFailure=%v", healthy, hardFailure)
	}

	// A successful probe fully restores it.
	oauth.MarkSuccess()
	if !oauth.IsHealthy() || oauth.ConsecutiveFailures != 0 {
		t.Fatalf("success after probe should reset the credential (consecutive=%d)", oauth.ConsecutiveFailures)
	}
}

// The probe must not rescue a genuinely dead credential forever: repeated failed
// probes still escalate to the sticky hard-fail, which is the intended terminal
// state and requires an operator to clear.
func TestFailedProbesStillEscalateToHardFail(t *testing.T) {
	oauth := &Auth{ID: "sub", Kind: KindOAuth, Provider: ProviderOpenAI}
	for i := 0; i < hardFailureThreshold; i++ {
		oauth.MarkFailure("upstream 500")
		// Pretend the quarantine elapsed and the probe went out and failed again.
		oauth.LastFailure = time.Now().Add(-degradedProbeAfter - time.Second)
	}
	if !oauth.IsHardFailed() {
		t.Fatalf("a credential failing every probe must still hard-fail after %d consecutive failures", hardFailureThreshold)
	}
	if oauth.IsHealthy() {
		t.Fatalf("hard-failed credential must stay out of rotation regardless of elapsed time")
	}
}
