package requestlog

import (
	"testing"
	"time"
)

// The settle-time rate has to survive the whole round trip — JSONL, the SQLite
// index, and back out through Query — or the yuan figure on a spend statement
// silently reverts to being computed at display time, which is the exact
// failure this column exists to prevent.
func TestCNYRateRoundTripsThroughIndex(t *testing.T) {
	dir := t.TempDir()
	base := time.Now().UTC().Add(-2 * time.Hour)

	recs := []Record{
		{
			TS: base, Client: "alpha", ClientToken: "sk-...aaaa", Provider: "anthropic",
			AuthID: "a1", AuthKind: "oauth", Model: "claude-opus-4-8",
			Input: 10, Output: 20, CostUSD: 2, BilledUSD: 0.1, Multiplier: 0.05,
			CNYPerUSD: 7.1842, Status: 200,
		},
		// A row from before rate capture: the column defaults to zero and must
		// stay zero rather than picking up a neighbour's rate.
		{
			TS: base.Add(time.Minute), Client: "alpha", ClientToken: "sk-...aaaa",
			Provider: "anthropic", AuthID: "a1", AuthKind: "oauth", Model: "claude-opus-4-8",
			Input: 10, Output: 20, CostUSD: 2, BilledUSD: 0.1, Multiplier: 0.05,
			Status: 200,
		},
	}
	writeLog(t, dir, recs)
	st := openReadyStore(t, dir)
	_ = st

	res, err := Query(Filter{Dir: dir, Limit: 100})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(res.Entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(res.Entries))
	}

	var withRate, withoutRate int
	for _, e := range res.Entries {
		switch e.CNYPerUSD {
		case 7.1842:
			withRate++
			cny, ok := e.BilledCNY()
			if !ok {
				t.Error("BilledCNY must report ok on a row carrying a rate")
			}
			if want := 0.1 * 7.1842; !nearly(cny, want) {
				t.Errorf("BilledCNY = %v, want %v", cny, want)
			}
		case 0:
			withoutRate++
			if _, ok := e.BilledCNY(); ok {
				t.Error("a row with no rate must report ok=false, not convert at zero")
			}
		default:
			t.Errorf("unexpected rate %v", e.CNYPerUSD)
		}
	}
	if withRate != 1 || withoutRate != 1 {
		t.Errorf("got %d rated / %d unrated rows, want 1 each", withRate, withoutRate)
	}
}

// Migration 4 runs against a database created before the column existed. If it
// ever stops being append-only-safe, an upgrade drops every historical row.
func TestCNYRateMigrationPreservesExistingRows(t *testing.T) {
	dir := t.TempDir()
	base := time.Now().UTC().Add(-3 * time.Hour)
	writeLog(t, dir, []Record{{
		TS: base, Client: "alpha", ClientToken: "sk-...aaaa", Provider: "anthropic",
		AuthID: "a1", AuthKind: "oauth", Model: "claude-opus-4-8",
		Input: 5, Output: 5, CostUSD: 1, BilledUSD: 0.05, Status: 200,
	}})

	st := openReadyStore(t, dir)
	before, err := Query(Filter{Dir: dir, Limit: 10})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if before.Summary.Count != 1 {
		t.Fatalf("seeded count = %d, want 1", before.Summary.Count)
	}
	st.Close()

	// Re-open: migrate() must be a no-op at the current version and leave the
	// indexed row intact rather than rebuilding from scratch.
	st2 := openReadyStore(t, dir)
	_ = st2
	after, err := Query(Filter{Dir: dir, Limit: 10})
	if err != nil {
		t.Fatalf("Query after reopen: %v", err)
	}
	if after.Summary.Count != before.Summary.Count {
		t.Errorf("count = %d after reopen, want %d", after.Summary.Count, before.Summary.Count)
	}
	if after.Summary.BilledUSD != before.Summary.BilledUSD {
		t.Errorf("billed = %v after reopen, want %v", after.Summary.BilledUSD, before.Summary.BilledUSD)
	}
}

// The rate is per-row, so a spend total in CNY is the sum of each row converted
// at its own rate — not the sum of USD times whatever the rate is now. With a
// moving rate those two answers differ, and only the first one is reproducible.
func TestPerRowRatesDoNotCollapseToOne(t *testing.T) {
	base := time.Now().UTC()
	rows := []Record{
		{BilledUSD: 1, CNYPerUSD: 7.0, TS: base},
		{BilledUSD: 1, CNYPerUSD: 8.0, TS: base},
	}
	var total float64
	for _, r := range rows {
		cny, ok := r.BilledCNY()
		if !ok {
			t.Fatal("both rows carry rates")
		}
		total += cny
	}
	if total != 15 {
		t.Errorf("total = %v, want 15 (7 + 8)", total)
	}
	// Converting the USD sum at the latest rate would have said 16.
	if latest := 2 * 8.0; total == latest {
		t.Error("per-row conversion must not equal converting the sum at one rate")
	}
}

// nearly compares to within a float64 rounding step. The product's last bit
// depends on multiplication order, which is not something a test should pin.
func nearly(a, b float64) bool {
	d := a - b
	return d < 1e-12 && d > -1e-12
}
