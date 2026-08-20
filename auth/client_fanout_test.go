package auth

import (
	"context"
	"testing"
	"time"
)

// Upstream sheds load per account, and in production the shed rate tracked how
// many distinct client tokens an account was serving far more closely than how
// much traffic it carried: accounts serving 2-5 tokens shed ~0% while accounts
// serving 13-17 shed 40%+, at comparable request volume and prompt size. So a
// new client token must land on the account currently serving the fewest
// distinct clients, not merely the least-used one.

// A brand-new client token goes to the credential with the smallest client
// fan-out, even when a busier-by-fan-out credential has consumed fewer tokens.
func TestAcquirePrefersLowestClientFanout(t *testing.T) {
	crowded := mustOAuth(t, "auth-crowded", "openai", "", 0)
	spare := mustOAuth(t, "auth-spare", "openai", "", 0)
	p := NewPool([]*Auth{crowded, spare}, nil, time.Minute, false, "")

	// Make the crowded credential look cheapest by usage, so the only reason
	// to avoid it is fan-out.
	p.SetUsageLoadFunc(func(authID string) int64 {
		if authID == "auth-crowded" {
			return 0
		}
		return 1_000_000
	})

	ctx := context.Background()
	// Three distinct clients pin themselves to the crowded credential by
	// excluding the alternative.
	for _, tok := range []string{"tok-1", "tok-2", "tok-3"} {
		got := p.Acquire(ctx, "openai", tok, "", "", "sess-"+tok, "auth-spare")
		if got == nil || got.ID != "auth-crowded" {
			t.Fatalf("setup: %s landed on %v, want auth-crowded", tok, got)
		}
	}

	got := p.Acquire(ctx, "openai", "tok-new", "", "", "sess-new")
	if got == nil {
		t.Fatal("no credential returned for the new client")
	}
	if got.ID != "auth-spare" {
		t.Errorf("new client landed on %s, want auth-spare — fan-out must outrank usage", got.ID)
	}
}

// Usage stays the tie-break among credentials of equal fan-out, so the existing
// load balancing is intact wherever fan-out cannot distinguish candidates.
func TestAcquireFallsBackToUsageAtEqualFanout(t *testing.T) {
	busy := mustOAuth(t, "auth-busy", "openai", "", 0)
	idle := mustOAuth(t, "auth-idle", "openai", "", 0)
	p := NewPool([]*Auth{busy, idle}, nil, time.Minute, false, "")
	p.SetUsageLoadFunc(func(authID string) int64 {
		if authID == "auth-busy" {
			return 5_000
		}
		return 1
	})

	got := p.Acquire(context.Background(), "openai", "tok-1", "", "", "sess-1")
	if got == nil || got.ID != "auth-idle" {
		t.Fatalf("at equal fan-out the least-used credential must win; got %v", got)
	}
}

// Fan-out counts distinct client tokens, not sessions. One user opening several
// CLI windows is the shape a real user produces — upstream reads it as one
// device with several concurrent sessions — so those windows must be free to
// stay together instead of being scattered across the fleet.
func TestExtraWindowsOfSameClientDoNotInflateFanout(t *testing.T) {
	a := mustOAuth(t, "auth-A", "openai", "", 0)
	b := mustOAuth(t, "auth-B", "openai", "", 0)
	p := NewPool([]*Auth{a, b}, nil, time.Minute, false, "")
	// Equal usage: fan-out alone decides.
	p.SetUsageLoadFunc(func(string) int64 { return 0 })

	ctx := context.Background()
	// One client, three windows, pinned to auth-A.
	for _, sess := range []string{"w1", "w2", "w3"} {
		got := p.Acquire(ctx, "openai", "tok-user", "", "", sess, "auth-B")
		if got == nil || got.ID != "auth-A" {
			t.Fatalf("setup: window %s landed on %v, want auth-A", sess, got)
		}
	}

	// A fourth window from the SAME user adds no new distinct client to auth-A,
	// so auth-A (fan-out 1) must still beat auth-B (fan-out 0 -> 1 with us).
	got := p.Acquire(ctx, "openai", "tok-user", "", "", "w4")
	if got == nil || got.ID != "auth-A" {
		t.Errorf("another window of the same client landed on %v, want auth-A — "+
			"a token already on a credential must not count against it", got)
	}

	// A DIFFERENT user, by contrast, must be pushed to the empty credential.
	got = p.Acquire(ctx, "openai", "tok-other", "", "", "s-other")
	if got == nil || got.ID != "auth-B" {
		t.Errorf("a distinct client landed on %v, want auth-B", got)
	}
}

// Fan-out reordering must never migrate an established session: stickiness is
// what keeps a conversation's prompt cache warm, and it is resolved before the
// picker runs.
func TestFanoutDoesNotBreakStickySessions(t *testing.T) {
	a := mustOAuth(t, "auth-A", "openai", "", 0)
	b := mustOAuth(t, "auth-B", "openai", "", 0)
	p := NewPool([]*Auth{a, b}, nil, time.Minute, false, "")
	p.SetUsageLoadFunc(func(string) int64 { return 0 })

	ctx := context.Background()
	// Pin three distinct clients onto auth-A, making it by far the most
	// crowded credential.
	for _, tok := range []string{"tok-1", "tok-2", "tok-3"} {
		if got := p.Acquire(ctx, "openai", tok, "", "", "sess-"+tok, "auth-B"); got == nil || got.ID != "auth-A" {
			t.Fatalf("setup: %s landed on %v, want auth-A", tok, got)
		}
	}

	// Each of them must keep its credential on the next request even though
	// auth-B now looks far more attractive by fan-out.
	for _, tok := range []string{"tok-1", "tok-2", "tok-3"} {
		got := p.Acquire(ctx, "openai", tok, "", "", "sess-"+tok)
		if got == nil || got.ID != "auth-A" {
			t.Errorf("established session for %s moved to %v; sticky assignments must survive rebalancing", tok, got)
		}
	}
}

// With N credentials and M clients, plain ordering spreads clients evenly on its
// own — no cap needed, and therefore no way for the scheduler to run out of
// candidates the way a hard per-account limit would.
func TestFanoutSpreadsClientsEvenly(t *testing.T) {
	var auths []*Auth
	for _, id := range []string{"auth-1", "auth-2", "auth-3", "auth-4"} {
		auths = append(auths, mustOAuth(t, id, "openai", "", 0))
	}
	p := NewPool(auths, nil, time.Minute, false, "")
	p.SetUsageLoadFunc(func(string) int64 { return 0 })

	ctx := context.Background()
	assigned := map[string]int{}
	for _, tok := range []string{"c1", "c2", "c3", "c4", "c5", "c6", "c7", "c8"} {
		got := p.Acquire(ctx, "openai", tok, "", "", "s-"+tok)
		if got == nil {
			t.Fatalf("no credential for %s", tok)
		}
		assigned[got.ID]++
	}
	for id, n := range assigned {
		if n != 2 {
			t.Errorf("%s serves %d clients, want 2 — 8 clients over 4 credentials must spread evenly", id, n)
		}
	}
	if len(assigned) != 4 {
		t.Errorf("only %d of 4 credentials were used: %v", len(assigned), assigned)
	}
}

// A credential's fan-out must decay with the active window, exactly like the
// active-session count: an account that served many clients an hour ago is not
// crowded now, and no state outlives the sessions map.
func TestFanoutExpiresWithActiveWindow(t *testing.T) {
	a := mustOAuth(t, "auth-A", "openai", "", 0)
	b := mustOAuth(t, "auth-B", "openai", "", 0)
	// A very short window so the sessions below expire during the test.
	p := NewPool([]*Auth{a, b}, nil, 30*time.Millisecond, false, "")
	p.SetUsageLoadFunc(func(authID string) int64 {
		// Keep auth-A the cheapest so only fan-out could push traffic away.
		if authID == "auth-A" {
			return 0
		}
		return 1_000
	})

	ctx := context.Background()
	for _, tok := range []string{"tok-1", "tok-2", "tok-3"} {
		if got := p.Acquire(ctx, "openai", tok, "", "", "sess-"+tok, "auth-B"); got == nil || got.ID != "auth-A" {
			t.Fatalf("setup: %s landed on %v, want auth-A", tok, got)
		}
	}

	time.Sleep(60 * time.Millisecond) // outlive the active window

	got := p.Acquire(ctx, "openai", "tok-new", "", "", "sess-new")
	if got == nil || got.ID != "auth-A" {
		t.Errorf("after the active window expired auth-A should look empty again and win on usage; got %v", got)
	}
}
