package requestlog

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWriterRoundTripAndQuery(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t0 := time.Now().UTC()
	w.Log(Record{
		TS: t0, Client: "alice", ClientToken: "sk-mask1", Provider: "anthropic",
		AuthID: "auth-1", AuthKind: "oauth", Model: "claude-opus-4-7",
		Input: 100, Output: 50, CostUSD: 0.01, Status: 200,
	})
	w.Log(Record{
		TS: t0, Client: "alice", ClientToken: "sk-mask1", Provider: "openai",
		AuthID: "auth-2", AuthKind: "apikey", Model: "gpt-5",
		Input: 200, Output: 80, CostUSD: 0.02, Status: 500, Error: "boom",
	})
	w.Close()

	// Verify file on disk has 2 lines.
	files, _ := filepath.Glob(filepath.Join(dir, "requests-*.jsonl"))
	if len(files) != 1 {
		t.Fatalf("expected 1 log file, got %d", len(files))
	}
	f, _ := os.Open(files[0])
	defer f.Close()
	cnt := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		cnt++
		var r Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatalf("decode: %v", err)
		}
	}
	if cnt != 2 {
		t.Fatalf("expected 2 records, got %d", cnt)
	}

	// Query: filter to status=500 should return 1 record.
	res, err := Query(Filter{Dir: dir, Status: 500})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if got := len(res.Entries); got != 1 {
		t.Fatalf("Query Entries=%d want 1", got)
	}
	if res.Summary.Errors != 1 {
		t.Fatalf("Summary.Errors=%d want 1", res.Summary.Errors)
	}
}

func TestQueryFilterByUserIDAndAuthID(t *testing.T) {
	dir := t.TempDir()
	w, _ := Open(dir, 0)
	w.Log(Record{TS: time.Now().UTC(), Model: "x", UserID: 100, AuthID: "auth-A", Status: 200})
	w.Log(Record{TS: time.Now().UTC(), Model: "y", UserID: 200, AuthID: "auth-B", Status: 200})
	w.Close()

	res, _ := Query(Filter{Dir: dir, UserID: 100})
	if len(res.Entries) != 1 || res.Entries[0].UserID != 100 {
		t.Fatalf("UserID filter wrong: %+v", res.Entries)
	}
	res, _ = Query(Filter{Dir: dir, AuthID: "auth-B"})
	if len(res.Entries) != 1 || res.Entries[0].AuthID != "auth-B" {
		t.Fatalf("AuthID filter wrong: %+v", res.Entries)
	}
}

func TestRewriteClientMask(t *testing.T) {
	dir := t.TempDir()
	w, _ := Open(dir, 0)
	for i := 0; i < 5; i++ {
		w.Log(Record{TS: time.Now().UTC(), ClientToken: "old-mask", Model: "m", Status: 200})
	}
	w.Log(Record{TS: time.Now().UTC(), ClientToken: "other", Model: "m", Status: 200})
	w.Close()

	n, err := w.RewriteClientMask("old-mask", "new-mask")
	if err != nil {
		t.Fatalf("Rewrite: %v", err)
	}
	if n != 5 {
		t.Fatalf("rewritten=%d want 5", n)
	}

	// Verify on-disk has new-mask, no old-mask, other unchanged.
	files, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	data, _ := os.ReadFile(files[0])
	body := string(data)
	if strings.Contains(body, "old-mask") {
		t.Fatal("old-mask still present")
	}
	if !strings.Contains(body, "new-mask") {
		t.Fatal("new-mask not written")
	}
	if !strings.Contains(body, "other") {
		t.Fatal("other client lost")
	}
}

func TestAggregateHourlyEmptyDir(t *testing.T) {
	dir := t.TempDir()
	buckets, err := AggregateHourly(dir, 6)
	if err != nil {
		t.Fatal(err)
	}
	if len(buckets) != 6 {
		t.Fatalf("expected 6 buckets, got %d", len(buckets))
	}
	for _, b := range buckets {
		if b.Count != 0 {
			t.Fatal("empty dir should produce zero counts")
		}
	}
}

func TestProviderLegacyTreatedAsAnthropic(t *testing.T) {
	dir := t.TempDir()
	w, _ := Open(dir, 0)
	w.Log(Record{TS: time.Now().UTC(), Provider: "", Model: "x", Status: 200}) // legacy
	w.Log(Record{TS: time.Now().UTC(), Provider: "openai", Model: "x", Status: 200})
	w.Close()

	res, _ := Query(Filter{Dir: dir, Provider: "anthropic"})
	if len(res.Entries) != 1 {
		t.Fatalf("legacy provider record should match 'anthropic' filter; got %d entries", len(res.Entries))
	}
}

func TestBucketLocationDayBoundary(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	// 2026-06-18T21:47Z == 2026-06-19 05:47 in Asia/Shanghai (+08:00).
	ts := time.Date(2026, 6, 18, 21, 47, 0, 0, time.UTC)
	w.Log(Record{TS: ts, Model: "m", Status: 200})
	w.Close()

	// Default (UTC): record buckets under 2026-06-18.
	res, err := Query(Filter{Dir: dir})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if _, ok := res.ByDay["2026-06-18"]; !ok {
		t.Fatalf("UTC: expected ByDay[2026-06-18], got %v", res.ByDay)
	}

	// Shanghai: same record re-buckets under 2026-06-19 with no migration.
	sh, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Skipf("no tzdata: %v", err)
	}
	SetBucketLocation(sh)
	defer SetBucketLocation(time.UTC)
	res, err = Query(Filter{Dir: dir})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if _, ok := res.ByDay["2026-06-19"]; !ok {
		t.Fatalf("Shanghai: expected ByDay[2026-06-19], got %v", res.ByDay)
	}
	if _, ok := res.ByDay["2026-06-18"]; ok {
		t.Fatalf("Shanghai: did not expect ByDay[2026-06-18], got %v", res.ByDay)
	}
}

// TestQueryBoundedPaginationAndPageOnly verifies (a) the bounded min-heap
// collector returns the exact same newest-first page as the old "collect all,
// sort, slice" path across Offset/Limit, and (b) PageOnly returns that same
// page of Entries while leaving the aggregates empty.
func TestQueryBoundedPaginationAndPageOnly(t *testing.T) {
	dir := t.TempDir()
	w, _ := Open(dir, 0)
	base := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	// 6 records spanning 3 day-files, strictly increasing TS so newest-first
	// order is deterministic (r5 newest ... r0 oldest).
	for i := 0; i < 6; i++ {
		w.Log(Record{
			TS:          base.AddDate(0, 0, i/2).Add(time.Duration(i) * time.Minute),
			ClientToken: "sk-mask",
			Model:       "m",
			Input:       int64(i),
			Status:      200,
		})
	}
	w.Close()

	// Full query, newest-first: expect Input sequence 5,4,3,2,1,0.
	full, err := Query(Filter{Dir: dir, Limit: 100})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(full.Entries) != 6 {
		t.Fatalf("full entries=%d want 6", len(full.Entries))
	}
	for i, want := range []int64{5, 4, 3, 2, 1, 0} {
		if full.Entries[i].Input != want {
			t.Fatalf("full[%d].Input=%d want %d", i, full.Entries[i].Input, want)
		}
	}
	if full.Summary.Count != 6 {
		t.Fatalf("Summary.Count=%d want 6 (full scan keeps aggregates)", full.Summary.Count)
	}

	// Paginated: Offset 1, Limit 2 -> the 2nd and 3rd newest -> Input 4,3.
	// Bounded heap (keep=Offset+Limit=3) must yield the identical slice.
	page, _ := Query(Filter{Dir: dir, Limit: 2, Offset: 1})
	if len(page.Entries) != 2 || page.Entries[0].Input != 4 || page.Entries[1].Input != 3 {
		t.Fatalf("paginated page wrong: %+v", page.Entries)
	}
	// Aggregates still full even when only a page of entries is returned.
	if page.Summary.Count != 6 {
		t.Fatalf("paginated Summary.Count=%d want 6", page.Summary.Count)
	}

	// PageOnly returns the same Entries page but skips aggregates.
	po, _ := Query(Filter{Dir: dir, Limit: 2, Offset: 1, PageOnly: true})
	if len(po.Entries) != 2 || po.Entries[0].Input != 4 || po.Entries[1].Input != 3 {
		t.Fatalf("PageOnly page mismatch: %+v", po.Entries)
	}
	if po.Summary.Count != 0 || len(po.ByModel) != 0 {
		t.Fatalf("PageOnly should leave aggregates empty: count=%d byModel=%d", po.Summary.Count, len(po.ByModel))
	}

	// PageOnly first page (Limit 3) must equal full's first 3 newest entries,
	// proving early-stop doesn't drop newer records.
	po1, _ := Query(Filter{Dir: dir, Limit: 3, PageOnly: true})
	for i, want := range []int64{5, 4, 3} {
		if po1.Entries[i].Input != want {
			t.Fatalf("PageOnly p1[%d].Input=%d want %d", i, po1.Entries[i].Input, want)
		}
	}
}
