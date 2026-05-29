package auth

import "testing"

// API-key credentials are operator-managed BYOK / relay channels and must
// never be auto-retired by error detection — only a manual disable takes them
// offline. OAuth subscription accounts keep the consecutive-failure auto
// hard-fail.
func TestAPIKeyNeverAutoHardFails(t *testing.T) {
	apikey := &Auth{ID: "relay", Kind: KindAPIKey, Provider: ProviderAnthropic}
	// Far more than hardFailureThreshold consecutive failures.
	for i := 0; i < hardFailureThreshold*4; i++ {
		apikey.MarkFailure("upstream 500")
	}
	if apikey.IsHardFailed() {
		t.Fatalf("API-key credential auto-hard-failed after %d failures; expected it to stay in rotation", apikey.ConsecutiveFailures)
	}
	if !apikey.IsHealthy() {
		t.Fatalf("API-key credential should remain healthy despite repeated transient failures")
	}

	// Explicit MarkHardFailure (e.g. 401/403) also must not stick for API keys.
	apikey.MarkHardFailure("upstream 401")
	if apikey.IsHardFailed() {
		t.Fatalf("MarkHardFailure should not stick for KindAPIKey")
	}

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
