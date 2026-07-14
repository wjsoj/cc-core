package auth

import "testing"

// A single definitive 401 (the common token-rotation race: a proactive refresh
// invalidates the old access token while a concurrent in-flight request still
// carries it) must NOT hard-fail the credential. It self-recovers on the very
// next success.
func TestSingle401DoesNotHardFail(t *testing.T) {
	a := &Auth{ID: "sub", Kind: KindOAuth, Provider: ProviderAnthropic}

	if n := a.MarkAuthRejection("upstream 401 authentication rejected"); n != 1 {
		t.Fatalf("first 401 count = %d, want 1", n)
	}
	if a.IsHardFailed() {
		t.Fatal("credential hard-failed after a single 401; expected it to stay recoverable")
	}

	// A success (fresh token, race over) resets the counter.
	a.MarkSuccess()
	if a.Consecutive401s != 0 {
		t.Fatalf("MarkSuccess did not reset Consecutive401s (=%d)", a.Consecutive401s)
	}
}

// Post-refresh 401 bursts that are interleaved with successes never accumulate
// toward the hard-fail threshold — a healthy busy account orphans a few
// requests per refresh but keeps succeeding on the fresh token.
func TestInterleaved401sNeverHardFail(t *testing.T) {
	a := &Auth{ID: "sub", Kind: KindOAuth, Provider: ProviderAnthropic}
	for i := 0; i < auth401HardFailureThreshold*3; i++ {
		a.MarkAuthRejection("upstream 401")
		a.MarkSuccess() // a real request succeeds between each orphaned 401
	}
	if a.IsHardFailed() {
		t.Fatal("interleaved 401/success pattern hard-failed a healthy credential")
	}
}

// A sustained run of 401s with NO intervening success — a genuinely revoked
// account whose refresh token still works but whose requests all 401 — does
// eventually promote to a sticky hard-failure so it stops cycling.
func TestSustained401sHardFail(t *testing.T) {
	a := &Auth{ID: "sub", Kind: KindOAuth, Provider: ProviderAnthropic}
	for i := 0; i < auth401HardFailureThreshold-1; i++ {
		a.MarkAuthRejection("upstream 401")
	}
	if a.IsHardFailed() {
		t.Fatalf("hard-failed before reaching the threshold (%d)", auth401HardFailureThreshold)
	}
	a.MarkAuthRejection("upstream 401") // crosses the threshold
	if !a.IsHardFailed() {
		t.Fatalf("did not hard-fail after %d consecutive 401s", auth401HardFailureThreshold)
	}
}

// API-key relay channels never auto-retire on 401s — a flaky relay backend
// must not pull the whole operator-managed channel out of rotation.
func TestAPIKey401NeverHardFails(t *testing.T) {
	a := &Auth{ID: "relay", Kind: KindAPIKey, Provider: ProviderAnthropic}
	for i := 0; i < auth401HardFailureThreshold*3; i++ {
		a.MarkAuthRejection("upstream 401")
	}
	if a.IsHardFailed() {
		t.Fatal("API-key credential auto-hard-failed on repeated 401s; expected it to stay in rotation")
	}
}
