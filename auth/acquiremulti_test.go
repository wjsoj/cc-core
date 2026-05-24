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
