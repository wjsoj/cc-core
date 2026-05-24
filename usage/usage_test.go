package usage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCountsAddAndWeightedTotal(t *testing.T) {
	c := Counts{InputTokens: 10, OutputTokens: 5}
	c.Add(Counts{InputTokens: 3, CacheReadTokens: 100, CacheCreateTokens: 7})
	if c.InputTokens != 13 || c.OutputTokens != 5 || c.CacheReadTokens != 100 || c.CacheCreateTokens != 7 {
		t.Fatalf("Add wrong: %+v", c)
	}
	// 13*100 + 7*125 + 100*10 + 5*500 = 1300+875+1000+2500 = 5675
	if got, want := c.WeightedTotal(), int64(5675); got != want {
		t.Fatalf("WeightedTotal=%d want %d", got, want)
	}
}

func TestOpenInMemoryNoDisk(t *testing.T) {
	s := OpenInMemory()
	defer s.Close()
	s.Record("acc1", "label", Counts{InputTokens: 100, OutputTokens: 50, Requests: 1})
	snap := s.Snapshot()
	if got := snap["acc1"].LastUsed; got.IsZero() {
		t.Fatal("LastUsed should be set")
	}
	if got := snap["acc1"].Label; got != "label" {
		t.Fatalf("Label=%q", got)
	}
	// no Flush behavior — path empty, Flush is no-op
	if err := s.Flush(); err != nil {
		t.Fatalf("in-memory Flush should be nil: %v", err)
	}
}

func TestOpenPersistsAndReloads(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "state.json")
	s1, err := Open(p)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	s1.Record("acc1", "label1", Counts{InputTokens: 1, Requests: 1})
	if err := s1.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	s1.Close()

	s2, err := Open(p)
	if err != nil {
		t.Fatalf("re-Open: %v", err)
	}
	defer s2.Close()
	snap := s2.Snapshot()
	if got := snap["acc1"].Daily; len(got) == 0 {
		t.Fatalf("expected daily rehydrated, got %+v", snap["acc1"])
	}
}

func TestOpenProbeFailsForBadPath(t *testing.T) {
	// /proc is read-only on Linux — opening should fail at the probe-write step.
	if _, err := os.Stat("/proc"); err != nil {
		t.Skip("/proc not available")
	}
	_, err := Open("/proc/cpa-claude-cc-core-usage-test/state.json")
	if err == nil {
		t.Fatal("expected error for unwritable path")
	}
}

func TestFlushRestoresDirtyOnError(t *testing.T) {
	// Manually construct a Store with a path that fails on writeAtomic.
	dir := t.TempDir()
	// Path inside dir then make dir read-only mid-test.
	p := filepath.Join(dir, "state.json")
	s, err := Open(p)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	s.Record("acc1", "", Counts{Requests: 1})

	// Replace path with one whose parent dir we'll chmod away.
	bad := filepath.Join(dir, "subdir", "state.json")
	if err := os.MkdirAll(filepath.Dir(bad), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(bad), 0500); err != nil {
		t.Skip("chmod not honored on this filesystem")
	}
	defer os.Chmod(filepath.Dir(bad), 0700)

	s.path = bad
	s.mu.Lock()
	s.dirty = true
	s.mu.Unlock()

	if err := s.Flush(); err == nil {
		t.Fatal("expected Flush to fail on unwritable dir")
	}
	s.mu.Lock()
	dirty := s.dirty
	s.mu.Unlock()
	if !dirty {
		t.Fatal("dirty flag should be restored after failed flush")
	}
}

func TestRecordClientWeekly(t *testing.T) {
	s := OpenInMemory()
	defer s.Close()
	fixed := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return fixed }
	s.RecordClient("tok", "label", Counts{InputTokens: 100}, 0.50)
	s.RecordClient("tok", "", Counts{InputTokens: 50}, 0.25)
	if got := s.WeeklyCostUSD("tok"); got != 0.75 {
		t.Fatalf("WeeklyCostUSD=%v", got)
	}
	if got := s.CurrentWeekKey(); got != "2026-W18" {
		t.Fatalf("CurrentWeekKey=%q", got)
	}
}

func TestMergeAndRenameClient(t *testing.T) {
	s := OpenInMemory()
	defer s.Close()
	s.RecordClient("a", "", Counts{InputTokens: 10}, 0.1)
	s.RecordClient("b", "", Counts{InputTokens: 20}, 0.2)

	if err := s.MergeClient("a", "b"); err != nil {
		t.Fatalf("Merge: %v", err)
	}
	clients := s.SnapshotClients()
	if _, exists := clients["a"]; exists {
		t.Fatal("a should be gone after merge")
	}
	if got := clients["b"].Total.CostUSD; got < 0.29 || got > 0.31 {
		t.Fatalf("merged Total.CostUSD=%v want ~0.3", got)
	}

	// Rename: b → c. c didn't exist yet so it should succeed.
	if err := s.RenameClient("b", "c"); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if _, exists := s.SnapshotClients()["c"]; !exists {
		t.Fatal("c should exist after rename")
	}

	// Re-record b, then renaming b → c should fail (c has usage).
	s.RecordClient("b", "", Counts{InputTokens: 1}, 0.01)
	if err := s.RenameClient("b", "c"); err == nil {
		t.Fatal("rename onto existing dst should fail")
	}
}

// Smoke: make sure state.json shape matches what callers expect.
func TestStateJSONShape(t *testing.T) {
	s := OpenInMemory()
	defer s.Close()
	s.Record("a", "lbl", Counts{InputTokens: 1, Requests: 1})
	data, err := json.Marshal(s.state)
	if err != nil {
		t.Fatal(err)
	}
	var back State
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := back.Auths["a"]; !ok {
		t.Fatal("Auths[a] missing after roundtrip")
	}
}
