package auth

import (
	"context"
	"testing"
	"time"
)

func TestModelShedScope(t *testing.T) {
	for _, tc := range []struct{ provider, model, want string }{
		{"openai", "gpt-6-astra", "openai:gpt-6-astra"},
		{"OpenAI", "OpenAI/GPT-6-Astra", "openai:gpt-6-astra"},
		{"anthropic", "claude-opus-5", "anthropic:claude-opus-5"},
		// No model name means no opinion: a caller that does not know what it
		// is sending must not penalise the credential for everything.
		{"openai", "", ""},
		{"openai", "   ", ""},
	} {
		if got := ModelShedScope(tc.provider, tc.model); got != tc.want {
			t.Errorf("ModelShedScope(%q, %q) = %q want %q", tc.provider, tc.model, got, tc.want)
		}
	}
}

// A shed penalises one model and leaves every sibling alone — the property that
// separates this from an account-wide cooldown, and the reason a Codex account
// shedding gpt-6-astra keeps serving gpt-5.6-sol at full priority.
func TestModelShedIsScopedToOneModel(t *testing.T) {
	a := &Auth{ID: "acct", Provider: ProviderOpenAI}
	now := time.Now()
	a.MarkModelShed("gpt-6-astra", now)
	if got := a.ModelShedPenalty("gpt-6-astra", now); got != 1 {
		t.Fatalf("shed model penalty = %d want 1", got)
	}
	if got := a.ModelShedPenalty("gpt-5.6-sol", now); got != 0 {
		t.Fatalf("sibling model penalty = %d want 0", got)
	}
}

func TestModelShedEscalatesAndExpires(t *testing.T) {
	a := &Auth{ID: "acct", Provider: ProviderOpenAI}
	now := time.Now()
	a.MarkModelShed("gpt-6-astra", now)
	if got := a.ModelShedPenalty("gpt-6-astra", now.Add(modelShedBaseTTL-time.Second)); got != 1 {
		t.Fatalf("within first window penalty = %d want 1", got)
	}
	// A second shed inside the window escalates both the streak and the TTL.
	a.MarkModelShed("gpt-6-astra", now)
	if got := a.ModelShedPenalty("gpt-6-astra", now); got != 2 {
		t.Fatalf("second shed penalty = %d want 2", got)
	}
	if got := a.ModelShedPenalty("gpt-6-astra", now.Add(2*modelShedBaseTTL-time.Second)); got != 2 {
		t.Fatalf("escalated window should still hold just short of 2x base, got %d", got)
	}
	// Past the escalated window the entry lapses entirely.
	if got := a.ModelShedPenalty("gpt-6-astra", now.Add(modelShedMaxTTL+time.Minute)); got != 0 {
		t.Fatalf("expired penalty = %d want 0", got)
	}
	// And the next shed starts a fresh burst rather than continuing the old one.
	later := now.Add(modelShedMaxTTL + 2*time.Minute)
	a.MarkModelShed("gpt-6-astra", later)
	if got := a.ModelShedPenalty("gpt-6-astra", later); got != 1 {
		t.Fatalf("post-expiry shed penalty = %d want 1 (streak restarts)", got)
	}
}

func TestNoteModelServedClearsPenaltyImmediately(t *testing.T) {
	a := &Auth{ID: "acct", Provider: ProviderOpenAI}
	now := time.Now()
	a.MarkModelShed("gpt-6-astra", now)
	a.MarkModelShed("gpt-6-astra", now)
	a.NoteModelServed("gpt-6-astra")
	if got := a.ModelShedPenalty("gpt-6-astra", now); got != 0 {
		t.Fatalf("penalty after a served turn = %d want 0", got)
	}
}

// The scheduler prefers a credential that has not just been shed for this
// model, even when the shedding one looks better on every other axis.
func TestPoolPrefersUnshedCredentialForTheModel(t *testing.T) {
	shedding := &Auth{ID: "aaa-shedding", Kind: KindOAuth, Provider: ProviderOpenAI, AccessToken: "t", ExpiresAt: time.Now().Add(time.Hour)}
	clean := &Auth{ID: "zzz-clean", Kind: KindOAuth, Provider: ProviderOpenAI, AccessToken: "t", ExpiresAt: time.Now().Add(time.Hour)}
	p := NewPool([]*Auth{shedding, clean}, nil, 5*time.Minute, false, "")

	// Tie-broken by ID with no shed history, so the "shedding" one wins first.
	if got := p.Acquire(context.Background(), ProviderOpenAI, "tok", "", "gpt-6-astra", "s1"); got == nil || got.ID != shedding.ID {
		t.Fatalf("baseline pick = %v want %s", got, shedding.ID)
	}
	p.Release(ProviderOpenAI, "tok", "s1")
	p.Unstick(ProviderOpenAI, "tok", "s1")

	shedding.MarkModelShed("gpt-6-astra", time.Now())
	if got := p.Acquire(context.Background(), ProviderOpenAI, "tok2", "", "gpt-6-astra", "s2"); got == nil || got.ID != clean.ID {
		t.Fatalf("after a shed the pick = %v want %s", got, clean.ID)
	}
	p.Release(ProviderOpenAI, "tok2", "s2")
	p.Unstick(ProviderOpenAI, "tok2", "s2")

	// A sibling model is unaffected by the astra shed.
	if got := p.Acquire(context.Background(), ProviderOpenAI, "tok3", "", "gpt-5.6-sol", "s3"); got == nil || got.ID != shedding.ID {
		t.Fatalf("sibling model pick = %v want %s (shed must not leak across models)", got, shedding.ID)
	}
	p.Release(ProviderOpenAI, "tok3", "s3")
	p.Unstick(ProviderOpenAI, "tok3", "s3")
}

// The whole point of ordering rather than filtering: when every credential is
// shedding the model — which is exactly what a bad capacity window looks like —
// the pool must still return one instead of reporting an empty pool.
func TestPoolStillServesWhenEveryCredentialIsShedding(t *testing.T) {
	one := &Auth{ID: "one", Kind: KindOAuth, Provider: ProviderOpenAI, AccessToken: "t", ExpiresAt: time.Now().Add(time.Hour)}
	two := &Auth{ID: "two", Kind: KindOAuth, Provider: ProviderOpenAI, AccessToken: "t", ExpiresAt: time.Now().Add(time.Hour)}
	p := NewPool([]*Auth{one, two}, nil, 5*time.Minute, false, "")
	now := time.Now()
	for i := 0; i < 3; i++ {
		one.MarkModelShed("gpt-6-astra", now)
		two.MarkModelShed("gpt-6-astra", now)
	}
	got := p.Acquire(context.Background(), ProviderOpenAI, "tok", "", "gpt-6-astra", "s1")
	if got == nil {
		t.Fatal("pool returned nothing while every credential was shedding; the penalty must order, never exclude")
	}
}
