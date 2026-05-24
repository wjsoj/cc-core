package advisor

import (
	"testing"
)

func TestIsAdvisor(t *testing.T) {
	if !(IterationUsage{Type: "advisor_message"}).IsAdvisor() {
		t.Fatal("advisor_message should be advisor")
	}
	if (IterationUsage{Type: "message"}).IsAdvisor() {
		t.Fatal("message (orchestrator) should NOT be advisor")
	}
	if (IterationUsage{}).IsAdvisor() {
		t.Fatal("empty type should not be advisor")
	}
}

func TestMergeAccumulates(t *testing.T) {
	var s SubUsage
	s.Merge(IterationUsage{Type: "advisor_message", Model: "claude-opus-4-7", InputTokens: 100, OutputTokens: 50})
	s.Merge(IterationUsage{Type: "advisor_message", Model: "claude-opus-4-7", InputTokens: 200, OutputTokens: 80})
	s.Merge(IterationUsage{Type: "message", Model: "claude-sonnet-4-6", InputTokens: 999, OutputTokens: 999}) // orchestrator — must be ignored

	snap := s.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("expected 1 sub-model, got %d (%+v)", len(snap), snap)
	}
	if snap["claude-opus-4-7"].InputTokens != 300 || snap["claude-opus-4-7"].OutputTokens != 130 {
		t.Fatalf("accumulated wrong: %+v", snap["claude-opus-4-7"])
	}
}

func TestReplaceFromOverwrites(t *testing.T) {
	var s SubUsage
	s.Merge(IterationUsage{Type: "advisor_message", Model: "opus", InputTokens: 1000})

	// Cumulative re-emit from the server contains the same iteration once;
	// ReplaceFrom should produce 1000, not 2000.
	s.ReplaceFrom([]IterationUsage{
		{Type: "advisor_message", Model: "opus", InputTokens: 1000},
	})
	if got := s.Snapshot()["opus"].InputTokens; got != 1000 {
		t.Fatalf("ReplaceFrom double-counted: %d want 1000", got)
	}
}

func TestEmptyModelGetsFallback(t *testing.T) {
	var s SubUsage
	s.Merge(IterationUsage{Type: "advisor_message", Model: "", InputTokens: 10})
	if _, ok := s.Snapshot()[FallbackModel]; !ok {
		t.Fatalf("expected fallback key %q in snapshot", FallbackModel)
	}
}

func TestSnapshotIsCopy(t *testing.T) {
	var s SubUsage
	s.Merge(IterationUsage{Type: "advisor_message", Model: "opus", InputTokens: 100})

	snap := s.Snapshot()
	snap["opus"] = snap["opus"] // touch
	// Mutate the snapshot map.
	delete(snap, "opus")
	if _, ok := s.Snapshot()["opus"].InputTokens, true; !ok || s.Snapshot()["opus"].InputTokens != 100 {
		t.Fatal("Snapshot should return an independent copy")
	}
}

func TestIsEmpty(t *testing.T) {
	var s SubUsage
	if !s.IsEmpty() {
		t.Fatal("zero SubUsage should be empty")
	}
	s.Merge(IterationUsage{Type: "message"}) // not an advisor
	if !s.IsEmpty() {
		t.Fatal("after orchestrator-only merge still empty")
	}
	s.Merge(IterationUsage{Type: "advisor_message", Model: "x"})
	if s.IsEmpty() {
		t.Fatal("after advisor merge should NOT be empty")
	}
}

func TestIterationCountsConversion(t *testing.T) {
	it := IterationUsage{InputTokens: 1, OutputTokens: 2, CacheCreationInputTokens: 3, CacheReadInputTokens: 4}
	c := it.Counts()
	if c.InputTokens != 1 || c.OutputTokens != 2 || c.CacheCreateTokens != 3 || c.CacheReadTokens != 4 {
		t.Fatalf("Counts conversion wrong: %+v", c)
	}
	if c.Requests != 0 {
		t.Fatal("Counts.Requests should be 0; caller bumps")
	}
}
