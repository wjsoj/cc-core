package auth

import (
	"context"
	"testing"
	"time"
)

func affinityPool(t *testing.T, n int) *Pool {
	t.Helper()
	var oa []*Auth
	for i := 0; i < n; i++ {
		oa = append(oa, mustOAuth(t, string(rune('a'+i))+".json", ProviderOpenAI, "", 4))
	}
	// Short active window so a slot can be expired without a real wait.
	return NewPool(oa, nil, 50*time.Millisecond, false, "")
}

func acquire(t *testing.T, p *Pool, slot string, exclude ...string) string {
	t.Helper()
	a := p.Acquire(context.Background(), ProviderOpenAI, "tok-1", "", "gpt-5.6-sol", slot, exclude...)
	if a == nil {
		t.Fatal("Acquire returned no credential")
	}
	p.Release(ProviderOpenAI, "tok-1", slot)
	return a.ID
}

// naturalPick is where a slot with no memory lands. Every test below forces
// its conversation somewhere ELSE first, so that "came back" cannot be
// confused with "was picked again anyway" — with an idle pool of equal load
// the scheduler is deterministic, and a test that did not do this would pass
// with the whole feature deleted.
func naturalPick(t *testing.T, p *Pool) string {
	t.Helper()
	return acquire(t, p, "probe-natural")
}

// The point of the memory: a conversation that pauses longer than the active
// window must come back to the account holding its prompt cache, not be
// rescheduled from scratch onto a cold one.
func TestConversationReturnsToItsCredentialAfterSlotExpiry(t *testing.T) {
	p := affinityPool(t, 6)
	natural := naturalPick(t, p)

	// Put the conversation somewhere the scheduler would not have chosen.
	first := acquire(t, p, "conv-1", natural)
	if first == natural {
		t.Fatalf("setup: conversation landed on the natural pick %s anyway", natural)
	}

	// Idle past the active window; the slot is GC'd on the next Acquire.
	time.Sleep(80 * time.Millisecond)

	if got := acquire(t, p, "conv-1"); got != first {
		t.Fatalf("returning conversation moved %s → %s (natural pick %s); prompt cache is lost",
			first, got, natural)
	}
}

// Memory must not survive being told the credential is bad for this
// conversation, or the next turn walks straight back into it.
func TestUnstickClearsAffinity(t *testing.T) {
	p := affinityPool(t, 6)
	natural := naturalPick(t, p)
	first := acquire(t, p, "conv-2", natural)
	if first == natural {
		t.Fatal("setup: conversation landed on the natural pick anyway")
	}

	p.Unstick(ProviderOpenAI, "tok-1", "conv-2")
	time.Sleep(80 * time.Millisecond)

	if got := acquire(t, p, "conv-2"); got != natural {
		t.Fatalf("after Unstick the conversation went to %s, want the natural pick %s — "+
			"the memory of %s survived being told it was bad", got, natural, first)
	}
}

// A remembered credential is a preference, never a pin: an unhealthy one must
// fall through to a normal pick rather than fail the request.
func TestAffinityYieldsToHealth(t *testing.T) {
	p := affinityPool(t, 3)
	natural := naturalPick(t, p)
	first := acquire(t, p, "conv-3", natural)
	if first == natural {
		t.Fatal("setup: conversation landed on the natural pick anyway")
	}

	for _, a := range p.oauths {
		if a.ID == first {
			a.MarkHardFailure("revoked")
		}
	}
	time.Sleep(80 * time.Millisecond)
	got := acquire(t, p, "conv-3")
	if got == first {
		t.Fatalf("hard-failed credential %s was handed back", got)
	}
}

// The memory is deliberately NOT a session: an idle conversation must not
// consume the concurrency budget its slot used to hold, or a busy fleet would
// look saturated by conversations nobody is running.
func TestAffinityDoesNotHoldConcurrency(t *testing.T) {
	p := affinityPool(t, 1) // one credential, MaxConcurrent 4
	for i := 0; i < 4; i++ {
		acquire(t, p, "conv-"+string(rune('a'+i)))
	}
	time.Sleep(80 * time.Millisecond) // all four slots go idle

	// A fifth conversation must still fit, because the four idle ones are
	// remembered but no longer active.
	if a := p.Acquire(context.Background(), ProviderOpenAI, "tok-1", "", "gpt-5.6-sol", "conv-e"); a == nil {
		t.Fatal("idle remembered conversations were still counted against MaxConcurrent")
	}
}

// TTL 0 restores the previous behaviour exactly, so the memory can be turned
// off in one place if it ever misbehaves.
func TestAffinityDisabled(t *testing.T) {
	p := affinityPool(t, 6)
	p.SetAffinityTTL(0)
	natural := naturalPick(t, p)
	first := acquire(t, p, "conv-4", natural)
	if first == natural {
		t.Fatal("setup: conversation landed on the natural pick anyway")
	}

	time.Sleep(80 * time.Millisecond)
	if got := acquire(t, p, "conv-4"); got != natural {
		t.Fatalf("TTL 0 still steered the conversation to %s; want schedule-from-scratch (%s)", got, natural)
	}
}

// A capacity refusal must not migrate the conversation.
//
// The pool used to rewrite both the sticky binding and the hour-long affinity
// memory whenever a credential was excluded, so ONE refusal handed the whole
// conversation to an account whose prompt cache had never seen it. During a
// capacity storm — 2.3 refusals per completed request — that shuffled every
// conversation across the pool every turn: production cache hit rate fell from
// 89.1% to 64.4% and the uncached prefill per turn rose from 9k to 25k tokens,
// which is a bigger and more expensive request arriving at a backend that is
// already refusing the expensive ones.
func TestCapacitySpilloverDoesNotMoveTheConversationHome(t *testing.T) {
	p := affinityPool(t, 3)

	home := acquire(t, p, "slot")
	// The turn is refused and retried; the loop excludes the credential it just
	// tried, exactly as forwardWithFailover does.
	spill := acquire(t, p, "slot", home)
	if spill == home {
		t.Fatal("the exclusion was ignored")
	}
	// The NEXT turn carries no exclusion. It must come home.
	if back := acquire(t, p, "slot"); back != home {
		t.Fatalf("conversation migrated to %s after one capacity refusal; it belongs to %s "+
			"and that is where its prompt cache is", back, home)
	}
}

// Repeated refusals must not accumulate into a migration either: a storm is a
// long run of exactly the event the test above covers once.
func TestRepeatedSpilloversStillComeHome(t *testing.T) {
	p := affinityPool(t, 3)

	home := acquire(t, p, "slot")
	for i := 0; i < 5; i++ {
		acquire(t, p, "slot", home)
	}
	if back := acquire(t, p, "slot"); back != home {
		t.Fatalf("five refusals migrated the conversation to %s; it belongs to %s", back, home)
	}
}

// A home that is genuinely gone — not merely stepped around — must be replaced,
// or a dead credential would pin a conversation forever.
func TestAnUnhealthyHomeIsReplacedAndTheReplacementSticks(t *testing.T) {
	p := affinityPool(t, 3)

	home := acquire(t, p, "slot")
	p.FindByID(home).MarkHardFailure("revoked")

	next := acquire(t, p, "slot")
	if next == home {
		t.Fatal("kept a hard-failed credential as the home")
	}
	if again := acquire(t, p, "slot"); again != next {
		t.Fatalf("the new home did not stick: got %s, want %s", again, next)
	}
}
