package auth

import (
	"testing"
	"time"
)

// API-key credentials are operator-managed BYOK / relay channels and must
// never be *retired* by error detection — only a manual disable takes them
// offline permanently. OAuth subscription accounts keep the
// consecutive-failure auto hard-fail.
//
// Since the quarantine circuit breaker landed, "never retired" no longer
// means "never paused": a channel that fails repeatedly is taken out of
// rotation for a bounded, self-expiring interval so traffic rotates onto a
// working key. The distinction this test pins is between that pause (always
// temporary, always recovers by itself) and the sticky hard-failure flag
// (needs a human), which must still never be set for an API key.
func TestAPIKeyNeverAutoHardFails(t *testing.T) {
	apikey := &Auth{ID: "relay", Kind: KindAPIKey, Provider: ProviderAnthropic}
	// Far more than hardFailureThreshold consecutive failures.
	for i := 0; i < hardFailureThreshold*4; i++ {
		apikey.MarkFailure("upstream 500")
	}
	if apikey.IsHardFailed() {
		t.Fatalf("API-key credential auto-hard-failed after %d failures; expected it to stay recoverable", apikey.ConsecutiveFailures)
	}
	// Paused, but only until the backoff expires — and one good response
	// restores it completely.
	until, _ := apikey.QuarantineSnapshot()
	if until.IsZero() {
		t.Fatal("a persistently failing API-key channel should be paused so traffic rotates elsewhere")
	}
	if apikey.IsHealthy() {
		t.Fatal("a paused channel must read unhealthy while its circuit is open")
	}
	if !apikey.IsQuarantined(until.Add(-time.Second)) || apikey.IsQuarantined(until.Add(time.Second)) {
		t.Fatal("the pause must expire on its own — it is a deadline, not a flag")
	}
	apikey.MarkSuccess()
	if !apikey.IsHealthy() {
		t.Fatal("a successful response must return the channel to full rotation with no operator action")
	}

	// Explicit MarkHardFailure (e.g. 401/403) also must not stick for API keys.
	apikey.MarkHardFailure("upstream 401")
	if apikey.IsHardFailed() {
		t.Fatalf("MarkHardFailure should not stick for KindAPIKey")
	}
	apikey.ClearFailure()

	// Repeated 429s must not promote to a stealth-ban hard-fail either.
	for i := 0; i < rateLimit429HardFailureThreshold*2; i++ {
		apikey.MarkRateLimited("upstream 429")
	}
	if apikey.IsHardFailed() {
		t.Fatalf("API-key credential auto-hard-failed after repeated 429s; expected it to stay in rotation")
	}

	// Manual disable still works.
	apikey.SetDisabled(true)
	if apikey.IsHealthy() {
		t.Fatalf("manual SetDisabled(true) should make the credential unhealthy")
	}
}

// OAuth credentials keep the consecutive-failure auto hard-fail.
func TestOAuthStillAutoHardFails(t *testing.T) {
	oauth := &Auth{ID: "sub", Kind: KindOAuth, Provider: ProviderAnthropic}
	for i := 0; i < hardFailureThreshold; i++ {
		oauth.MarkFailure("upstream 500")
	}
	if !oauth.IsHardFailed() {
		t.Fatalf("OAuth credential should auto-hard-fail after %d consecutive failures", hardFailureThreshold)
	}
}
