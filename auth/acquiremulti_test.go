package auth

import (
	"context"
	"testing"
	"time"
)

// TestAcquireMultiSingleGroup verifies AcquireMulti behaves identically to
// Acquire when handed exactly one group.
func TestAcquireMultiSingleGroup(t *testing.T) {
	a := mustOAuth(t, "auth-A", "anthropic", "groupA", 1)
	p := NewPool([]*Auth{a}, nil, time.Minute, false, "")

	gotGroup, gotAuth := p.AcquireMulti(context.Background(), "anthropic", "client1", []string{"groupA"}, "", "")
	if gotGroup != "groupA" || gotAuth == nil || gotAuth.ID != "auth-A" {
		t.Fatalf("single-group: got group=%q auth=%v", gotGroup, gotAuth)
	}
}

// TestAcquireMultiFallthrough verifies a missing first group falls through to
// the second.
func TestAcquireMultiFallthrough(t *testing.T) {
	a := mustOAuth(t, "auth-B", "anthropic", "groupB", 1)
	p := NewPool([]*Auth{a}, nil, time.Minute, false, "")

	gotGroup, gotAuth := p.AcquireMulti(context.Background(), "anthropic", "client1", []string{"groupA", "groupB"}, "", "")
	if gotGroup != "groupB" || gotAuth == nil {
		t.Fatalf("expected fallthrough to groupB: got group=%q auth=%v", gotGroup, gotAuth)
	}
}

// TestAcquireMultiAllExhausted returns nil when nothing matches.
func TestAcquireMultiAllExhausted(t *testing.T) {
	p := NewPool(nil, nil, time.Minute, false, "")
	gotGroup, gotAuth := p.AcquireMulti(context.Background(), "anthropic", "client1", []string{"x", "y"}, "", "")
	if gotGroup != "" || gotAuth != nil {
		t.Fatalf("expected empty result: group=%q auth=%v", gotGroup, gotAuth)
	}
}

// TestAcquireMultiEmptyGroupsTreatedAsPublic.
func TestAcquireMultiEmptyGroupsTreatedAsPublic(t *testing.T) {
	a := mustOAuth(t, "auth-pub", "anthropic", "", 1)
	p := NewPool([]*Auth{a}, nil, time.Minute, false, "")
	gotGroup, gotAuth := p.AcquireMulti(context.Background(), "anthropic", "client1", nil, "", "")
	if gotAuth == nil || gotAuth.ID != "auth-pub" {
		t.Fatalf("nil groups should hit public: group=%q auth=%v", gotGroup, gotAuth)
	}
}

// mustOAuth builds a minimal OAuth Auth for tests. Avoids actual TLS / token
// refresh by setting AccessToken in-the-future + skipping EnsureFresh paths.
func mustOAuth(t *testing.T, id, provider, group string, maxConc int) *Auth {
	t.Helper()
	a := &Auth{
		ID:             id,
		Provider:       provider,
		Group:          group,
		Kind:           KindOAuth,
		AccessToken:    "fake-token",
		ExpiresAt:      time.Now().Add(time.Hour),
		MaxConcurrent:  maxConc,
	}
	return a
}

// TestAcquireMultiWithOptionsPropagatesAPIKeyOnly guards a flag that used to be
// silently dropped in the fan-out: AcquireMultiWithOptions rebuilt the per-group
// AcquireOptions and forgot APIKeyOnly, so a caller replaying a request whose
// identity rewrite had already failed got handed an OAuth credential — the one
// outcome the flag exists to prevent.
func TestAcquireMultiWithOptionsPropagatesAPIKeyOnly(t *testing.T) {
	dir := t.TempDir()
	oauth := &Auth{
		ID: "oauth", Kind: KindOAuth, Provider: ProviderAnthropic,
		Group: "g", AccessToken: "oauth-token", MaxConcurrent: 5,
	}
	key := mustAPIKey(t, dir, "key", ProviderAnthropic)
	key.Group = "g"
	p := NewPool([]*Auth{oauth}, []*Auth{key}, time.Minute, false, "")

	group, got := p.AcquireMultiWithOptions(context.Background(), ProviderAnthropic, "tok",
		[]string{"g"}, "claude-haiku-4-5", "session", AcquireOptions{
			AllowAPIKeyFallback: true,
			APIKeyOnly:          true,
		})
	if got == nil || got.Kind != KindAPIKey || got.ID != key.ID {
		t.Fatalf("APIKeyOnly ignored in fan-out: group=%q auth=%+v", group, got)
	}
	if group != "g" {
		t.Fatalf("serving group = %q, want %q", group, "g")
	}
}

// TestAcquireMultiWithOptionsHonoursExcludeIDs verifies the caller's skip-list
// reaches every group attempt, not just the first.
func TestAcquireMultiWithOptionsHonoursExcludeIDs(t *testing.T) {
	first := mustOAuth(t, "auth-1", ProviderAnthropic, "groupA", 1)
	second := mustOAuth(t, "auth-2", ProviderAnthropic, "groupB", 1)
	p := NewPool([]*Auth{first, second}, nil, time.Minute, false, "")

	group, got := p.AcquireMultiWithOptions(context.Background(), ProviderAnthropic, "tok",
		[]string{"groupA", "groupB"}, "", "session", AcquireOptions{ExcludeIDs: []string{"auth-1"}})
	if got == nil || got.ID != "auth-2" || group != "groupB" {
		t.Fatalf("excluded credential leaked into a later group: group=%q auth=%+v", group, got)
	}
}
