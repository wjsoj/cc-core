package requestlog

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// The index is only worth having if it is indistinguishable from the scan it
// replaces. Every test here runs a query twice — once against the JSONL
// files, once against SQLite — and demands the same answer.

// withShanghaiBuckets points day/hour bucketing at a non-UTC zone for the
// duration of a test. Production defaults to Asia/Shanghai, and that is
// precisely the case where the UTC file day and the displayed day disagree,
// so testing under UTC would hide the bug class this column exists for.
func withShanghaiBuckets(t *testing.T) {
	t.Helper()
	loc, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Skip("tzdata unavailable")
	}
	prev := bucketLoc
	bucketLoc = loc
	t.Cleanup(func() { bucketLoc = prev })
}

// writeLog appends records to the file for their UTC day, mirroring what
// Writer does, and returns the directory.
func writeLog(t *testing.T, dir string, recs []Record) {
	t.Helper()
	byDay := map[string][]Record{}
	for _, r := range recs {
		day := r.TS.UTC().Format("2006-01-02")
		byDay[day] = append(byDay[day], r)
	}
	for day, rs := range byDay {
		path := filepath.Join(dir, "requests-"+day+".jsonl")
		fh, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatalf("open %s: %v", path, err)
		}
		for _, r := range rs {
			b, err := json.Marshal(r)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if _, err := fh.Write(append(b, '\n')); err != nil {
				t.Fatalf("write: %v", err)
			}
		}
		_ = fh.Close()
	}
}

// sampleRecords spans several days and deliberately exercises every branch
// the query paths have: empty vs set provider, both billing generations,
// attempt-only rows, mixed case in model/client, error rows, SaaS user ids,
// and a ClaudeAudit payload.
func sampleRecords(base time.Time) []Record {
	mk := func(offset time.Duration, f func(*Record)) Record {
		r := Record{
			TS:          base.Add(offset),
			Client:      "alpha",
			ClientToken: "sk-...aaaa",
			Provider:    "anthropic",
			AuthID:      "auth-1.json",
			AuthLabel:   "one@example.com",
			AuthKind:    "oauth",
			Model:       "claude-opus-4-8",
			Input:       10,
			Output:      20,
			CacheRead:   30,
			CacheCreate: 40,
			CostUSD:     0.5,
			Status:      200,
			DurationMs:  100,
			Stream:      true,
			Path:        "/v1/messages",
		}
		f(&r)
		return r
	}
	return []Record{
		mk(0, func(r *Record) {}),
		// 1h-cache axis + the newer billing convention.
		mk(time.Minute, func(r *Record) {
			r.CacheCreate1h = 15
			r.BilledUSD = 0.05
			r.Multiplier = 0.1
		}),
		// Legacy row: charged amount lives in CostUSD, BilledUSD unset.
		mk(2*time.Minute, func(r *Record) { r.BilledUSD = 0 }),
		// Error rows, both flavours the aggregates count.
		mk(3*time.Minute, func(r *Record) { r.Status = 429 }),
		mk(4*time.Minute, func(r *Record) { r.Status = 200; r.Error = "stream broken" }),
		// Attempt-only audit row: must be invisible everywhere.
		mk(5*time.Minute, func(r *Record) { r.AttemptOnly = true; r.CostUSD = 999 }),
		// Second credential + second model + mixed case.
		mk(6*time.Minute, func(r *Record) {
			r.AuthID = "auth-2.json"
			r.Model = "Claude-Sonnet-5"
			r.Client = "Beta"
			r.ClientToken = "sk-...bbbb"
		}),
		// Legacy row with no provider — must match Provider=="anthropic".
		mk(7*time.Minute, func(r *Record) { r.Provider = "" }),
		// Codex side.
		mk(8*time.Minute, func(r *Record) {
			r.Provider = "openai"
			r.Model = "gpt-5.6-sol"
			r.AuthID = "codex-1.json"
			r.RequestedServiceTier = "priority"
			r.UpstreamServiceTier = "default"
			r.ServiceTier = "priority"
		}),
		// SaaS attribution + audit payload.
		mk(9*time.Minute, func(r *Record) {
			r.UserID = 42
			r.ClaudeAudit = &ClaudeAudit{RequestClass: "chat", IdentityMode: "mapped"}
		}),
		// A record with no auth at all: AggregateByAuth skips it.
		mk(10*time.Minute, func(r *Record) { r.AuthID = "" }),
		// Previous days, so day-range pruning and ByDay have something to do.
		mk(-25*time.Hour, func(r *Record) { r.Model = "claude-haiku-4-5" }),
		mk(-49*time.Hour, func(r *Record) { r.AuthID = "auth-2.json" }),
		// Crosses the UTC/Shanghai day boundary: 23:30 UTC is already the
		// next day in +08:00, so ByDay and the file name must disagree.
		mk(-73*time.Hour, func(r *Record) { r.TS = r.TS.UTC().Truncate(24 * time.Hour).Add(23*time.Hour + 30*time.Minute) }),
	}
}

// openReadyStore opens an index and waits for the first pass to land.
func openReadyStore(t *testing.T, dir string) *Store {
	t.Helper()
	st, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(st.Close)
	deadline := time.Now().Add(15 * time.Second)
	for !st.Ready() {
		if time.Now().After(deadline) {
			t.Fatal("index never became ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	return st
}

// assertSameAggregates compares two by-key aggregate maps exactly.
func assertSameAggregates(t *testing.T, what string, want, got map[string]Aggregate) {
	t.Helper()
	if len(want) != len(got) {
		t.Errorf("%s: key count = %d, want %d\n  want %v\n  got  %v", what, len(got), len(want), keysOf(want), keysOf(got))
		return
	}
	for k, w := range want {
		g, ok := got[k]
		if !ok {
			t.Errorf("%s: missing key %q", what, k)
			continue
		}
		if !reflect.DeepEqual(w, g) {
			t.Errorf("%s[%q]:\n  want %+v\n  got  %+v", what, k, w, g)
		}
	}
}

func keysOf(m map[string]Aggregate) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// assertSameEntries compares record pages. Timestamps are compared as
// instants: the index stores nanoseconds and renders them in the display
// zone, so the wall-clock offset can differ from the writer's original even
// though the moment is identical.
func assertSameEntries(t *testing.T, want, got []Record) {
	t.Helper()
	if len(want) != len(got) {
		t.Fatalf("entries: len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		w, g := want[i], got[i]
		if !w.TS.Equal(g.TS) {
			t.Errorf("entries[%d].TS = %v, want %v", i, g.TS, w.TS)
		}
		w.TS, g.TS = time.Time{}, time.Time{}
		if !reflect.DeepEqual(w, g) {
			t.Errorf("entries[%d]:\n  want %+v\n  got  %+v", i, w, g)
		}
	}
}

// filterCases enumerates the shapes the two forks actually issue.
func filterCases(dir string, base time.Time) []struct {
	name string
	f    Filter
} {
	return []struct {
		name string
		f    Filter
	}{
		{"all", Filter{Dir: dir}},
		{"paged", Filter{Dir: dir, Limit: 3}},
		{"paged-offset", Filter{Dir: dir, Limit: 3, Offset: 4}},
		{"offset-past-end", Filter{Dir: dir, Limit: 5, Offset: 1000}},
		{"page-only", Filter{Dir: dir, Limit: 4, PageOnly: true}},
		{"by-model", Filter{Dir: dir, Model: "claude-opus-4-8"}},
		{"by-model-mixed-case", Filter{Dir: dir, Model: "CLAUDE-OPUS-4-8"}},
		{"by-client-name", Filter{Dir: dir, Client: "beta"}},
		{"by-client-token", Filter{Dir: dir, ClientToken: "sk-...bbbb"}},
		{"client-token-wins", Filter{Dir: dir, ClientToken: "sk-...aaaa", Client: "beta"}},
		{"by-provider-anthropic", Filter{Dir: dir, Provider: "anthropic"}},
		{"by-provider-openai", Filter{Dir: dir, Provider: "openai"}},
		{"by-status", Filter{Dir: dir, Status: 429}},
		{"by-auth", Filter{Dir: dir, AuthID: "auth-2.json"}},
		{"by-user", Filter{Dir: dir, UserID: 42}},
		{"from", Filter{Dir: dir, From: base.Add(-time.Hour)}},
		{"to", Filter{Dir: dir, To: base.Add(-time.Hour)}},
		{"window", Filter{Dir: dir, From: base.Add(-50 * time.Hour), To: base.Add(-24 * time.Hour)}},
		{"combo", Filter{Dir: dir, Provider: "anthropic", Status: 200, Limit: 2}},
		{"no-match", Filter{Dir: dir, Model: "does-not-exist"}},
		// Dims, on both aggregate paths: an unbounded filter and a
		// day-labelled one, which is what routes to req vs the cube. The
		// scanning path has no such split, so running the same dims through
		// both is how a dims bug that only lives in one of them shows up.
		{"dims-summary", Filter{Dir: dir, Dims: DimSummary}},
		{"dims-by-client", Filter{Dir: dir, Dims: DimByClient}},
		{"dims-model-day", Filter{Dir: dir, Dims: DimByModel | DimByDay}},
		{"dims-all-explicit", Filter{Dir: dir, Dims: DimAll}},
		{"dims-with-filter", Filter{Dir: dir, Provider: "anthropic", Dims: DimSummary | DimByModel}},
		{"dims-no-match", Filter{Dir: dir, Model: "does-not-exist", Dims: DimSummary}},
		{"dims-page-only-wins", Filter{Dir: dir, Limit: 4, PageOnly: true, Dims: DimAll}},
		{"dims-cube-summary", Filter{
			Dir: dir, FromDay: dayLabel(base.Add(-73 * time.Hour)), ToDay: dayLabel(base),
			Dims: DimSummary,
		}},
		{"dims-cube-by-client", Filter{
			Dir: dir, FromDay: dayLabel(base.Add(-73 * time.Hour)), ToDay: dayLabel(base),
			Dims: DimByClient,
		}},
		{"dims-cube-model-day", Filter{
			Dir: dir, FromDay: dayLabel(base.Add(-73 * time.Hour)), ToDay: dayLabel(base),
			Dims: DimByModel | DimByDay,
		}},
		{"dims-cube-default", Filter{
			Dir: dir, FromDay: dayLabel(base.Add(-73 * time.Hour)), ToDay: dayLabel(base),
		}},
	}
}

// TestZeroDimsIsEveryDimension is the regression nail for the one rule the
// whole design rests on: existing callers construct Filter as a struct
// literal and have never heard of Dims, so a zero value must produce exactly
// what an explicit DimAll produces — on both the cube and the req path, and
// with the index on and off.
func TestZeroDimsIsEveryDimension(t *testing.T) {
	withShanghaiBuckets(t)
	dir := t.TempDir()
	base := time.Now().UTC().Add(-6 * time.Hour).Truncate(time.Second)
	writeLog(t, dir, sampleRecords(base))

	shapes := []struct {
		name string
		f    Filter
	}{
		{"unbounded", Filter{Dir: dir, Limit: 50}},
		{"day-labelled", Filter{
			Dir: dir, Limit: 50,
			FromDay: dayLabel(base.Add(-73 * time.Hour)), ToDay: dayLabel(base),
		}},
		{"timestamp-window", Filter{
			Dir: dir, Limit: 50,
			From: base.Add(-50 * time.Hour), To: base.Add(-24 * time.Hour),
		}},
	}

	check := func(t *testing.T, stage string) {
		t.Helper()
		for _, sh := range shapes {
			zero, err := Query(sh.f)
			if err != nil {
				t.Fatalf("%s/%s zero dims: %v", stage, sh.name, err)
			}
			explicit := sh.f
			explicit.Dims = DimAll
			all, err := Query(explicit)
			if err != nil {
				t.Fatalf("%s/%s DimAll: %v", stage, sh.name, err)
			}
			// Scanned counts work done, which differs between the two paths
			// but not between two runs of the same one — so it is compared
			// here, unlike in the cross-path tests.
			if !reflect.DeepEqual(zero, all) {
				t.Errorf("%s/%s: zero Dims != DimAll\n  zero %+v\n  all  %+v", stage, sh.name, zero, all)
			}
		}
	}

	check(t, "scan")
	openReadyStore(t, dir)
	check(t, "index")
}

// TestDimsLeaveUnrequestedAggregatesEmpty pins the other half of the
// contract: asking for one grouping must actually skip the others rather
// than quietly computing them anyway, which is what makes the whole change
// worth an API field.
func TestDimsLeaveUnrequestedAggregatesEmpty(t *testing.T) {
	withShanghaiBuckets(t)
	dir := t.TempDir()
	base := time.Now().UTC().Add(-6 * time.Hour).Truncate(time.Second)
	writeLog(t, dir, sampleRecords(base))

	day := dayLabel(base)
	cases := []struct {
		name string
		f    Filter
	}{
		{"req-path", Filter{Dir: dir, Limit: 50, Dims: DimByModel}},
		{"cube-path", Filter{Dir: dir, Limit: 50, FromDay: day, ToDay: day, Dims: DimByModel}},
	}

	check := func(t *testing.T, stage string) {
		t.Helper()
		for _, c := range cases {
			res, err := Query(c.f)
			if err != nil {
				t.Fatalf("%s/%s: %v", stage, c.name, err)
			}
			if len(res.ByModel) == 0 {
				t.Errorf("%s/%s: ByModel empty, the one grouping that was asked for", stage, c.name)
			}
			if len(res.ByClient) != 0 || len(res.ByDay) != 0 {
				t.Errorf("%s/%s: unrequested groupings populated: by_client=%v by_day=%v",
					stage, c.name, res.ByClient, res.ByDay)
			}
			if res.Summary != (Aggregate{}) {
				t.Errorf("%s/%s: unrequested summary populated: %+v", stage, c.name, res.Summary)
			}
			// Entries are orthogonal to dims — a caller that wants a page and
			// one grouping must still get the page.
			if len(res.Entries) == 0 {
				t.Errorf("%s/%s: entries empty", stage, c.name)
			}
		}
	}

	check(t, "scan")
	openReadyStore(t, dir)
	check(t, "index")
}

func TestStoreQueryMatchesScan(t *testing.T) {
	withShanghaiBuckets(t)
	dir := t.TempDir()
	base := time.Now().UTC().Add(-6 * time.Hour).Truncate(time.Second)
	writeLog(t, dir, sampleRecords(base))

	cases := filterCases(dir, base)
	want := make([]*Result, len(cases))
	for i, c := range cases {
		res, err := Query(c.f)
		if err != nil {
			t.Fatalf("scan Query(%s): %v", c.name, err)
		}
		want[i] = res
	}

	openReadyStore(t, dir)

	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Query(c.f)
			if err != nil {
				t.Fatalf("index Query: %v", err)
			}
			w := want[i]
			assertSameEntries(t, w.Entries, got.Entries)
			if !reflect.DeepEqual(w.Summary, got.Summary) {
				t.Errorf("summary:\n  want %+v\n  got  %+v", w.Summary, got.Summary)
			}
			assertSameAggregates(t, "by_client", w.ByClient, got.ByClient)
			assertSameAggregates(t, "by_model", w.ByModel, got.ByModel)
			assertSameAggregates(t, "by_day", w.ByDay, got.ByDay)
			// Scanned is deliberately not compared: it reports how much work
			// the implementation did (lines read vs rows matched), which is
			// exactly the thing the index changes.
		})
	}
}

func TestStoreAggregateByAuthMatchesScan(t *testing.T) {
	withShanghaiBuckets(t)
	dir := t.TempDir()
	base := time.Now().UTC().Add(-6 * time.Hour).Truncate(time.Second)
	writeLog(t, dir, sampleRecords(base))

	windows := []struct {
		name     string
		from, to time.Time
	}{
		{"lifetime", time.Time{}, time.Time{}},
		{"last-24h", time.Now().Add(-24 * time.Hour), time.Time{}},
		{"bounded", base.Add(-50 * time.Hour), base.Add(-24 * time.Hour)},
		{"empty-window", base.Add(time.Hour), base.Add(2 * time.Hour)},
	}
	want := make([]map[string]Aggregate, len(windows))
	for i, w := range windows {
		m, err := AggregateByAuth(dir, w.from, w.to)
		if err != nil {
			t.Fatalf("scan AggregateByAuth(%s): %v", w.name, err)
		}
		want[i] = m
	}

	openReadyStore(t, dir)

	for i, w := range windows {
		t.Run(w.name, func(t *testing.T) {
			got, err := AggregateByAuth(dir, w.from, w.to)
			if err != nil {
				t.Fatalf("index AggregateByAuth: %v", err)
			}
			assertSameAggregates(t, "by_auth", want[i], got)
		})
	}
}

func TestStoreAggregateHourlyMatchesScan(t *testing.T) {
	withShanghaiBuckets(t)
	dir := t.TempDir()
	// Spread records over the last few hours so buckets are non-trivial.
	now := time.Now().UTC()
	var recs []Record
	for i := 0; i < 12; i++ {
		r := Record{
			TS: now.Add(-time.Duration(i) * 90 * time.Minute).Truncate(time.Second),
			// Alternate an attempt-only row in: hourly must ignore them.
			AttemptOnly: i%4 == 3,
			AuthID:      "auth-1.json",
			Model:       "claude-opus-4-8",
			Input:       int64(i + 1),
			Output:      int64(i * 2),
			CacheRead:   int64(i * 3),
			CacheCreate: int64(i * 4),
			CostUSD:     float64(i) * 0.25,
			Status:      200,
		}
		if i%5 == 2 {
			r.Status = 500
		}
		recs = append(recs, r)
	}
	writeLog(t, dir, recs)

	want, err := AggregateHourly(dir, 24)
	if err != nil {
		t.Fatalf("scan AggregateHourly: %v", err)
	}

	openReadyStore(t, dir)

	got, err := AggregateHourly(dir, 24)
	if err != nil {
		t.Fatalf("index AggregateHourly: %v", err)
	}
	if len(want) != len(got) {
		t.Fatalf("buckets = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if !want[i].Hour.Equal(got[i].Hour) {
			t.Errorf("bucket[%d].Hour = %v, want %v", i, got[i].Hour, want[i].Hour)
		}
		w, g := want[i], got[i]
		w.Hour, g.Hour = time.Time{}, time.Time{}
		if !reflect.DeepEqual(w, g) {
			t.Errorf("bucket[%d]:\n  want %+v\n  got  %+v", i, w, g)
		}
	}
}

// TestStoreSelfHeal covers the three ways the archive changes underneath the
// index, plus retention deletion. Each step re-runs catch-up synchronously
// and demands the index still agrees with a fresh scan.
func TestStoreSelfHeal(t *testing.T) {
	withShanghaiBuckets(t)
	dir := t.TempDir()
	base := time.Now().UTC().Add(-6 * time.Hour).Truncate(time.Second)
	writeLog(t, dir, sampleRecords(base))

	st := openReadyStore(t, dir)

	// A Writer declaring the archive on is what licenses step 4 below: the
	// index only treats a vanished file as a retention delete when something
	// has told it the files are authoritative. Production always has one; a
	// Store on its own genuinely does not know, and must not guess in the
	// destructive direction. See store_stale_ledger_test.go.
	w, err := OpenWithOptions(dir, Options{JSONLArchive: true})
	if err != nil {
		t.Fatalf("OpenWithOptions: %v", err)
	}
	defer w.Close()

	check := func(what string) {
		t.Helper()
		// Compare against the scanning path by asking the store directly,
		// so the package-level dispatch can't mask a stale index.
		wantRes, err := scanQuery(Filter{Dir: dir})
		if err != nil {
			t.Fatalf("%s: scan: %v", what, err)
		}
		gotRes, err := st.storeQuery(Filter{Dir: dir, Limit: 50})
		if err != nil {
			t.Fatalf("%s: index: %v", what, err)
		}
		if !reflect.DeepEqual(wantRes.Summary, gotRes.Summary) {
			t.Errorf("%s summary:\n  want %+v\n  got  %+v", what, wantRes.Summary, gotRes.Summary)
		}
		assertSameAggregates(t, what+" by_day", wantRes.ByDay, gotRes.ByDay)
		assertSameAggregates(t, what+" by_model", wantRes.ByModel, gotRes.ByModel)
	}
	check("baseline")

	today := filepath.Join(dir, "requests-"+base.UTC().Format("2006-01-02")+".jsonl")

	// 1. Append — the steady state.
	writeLog(t, dir, []Record{{
		TS: base.Add(30 * time.Minute), AuthID: "auth-1.json",
		Model: "claude-opus-4-8", Input: 7, CostUSD: 1.5, Status: 200,
	}})
	if err := st.catchUp(false); err != nil {
		t.Fatalf("catchUp after append: %v", err)
	}
	check("after append")

	// 2. In-place rewrite of a rotated file at identical size — what
	// RewriteClientMask does. Only mtime moves, so that is the only signal
	// the index can key on.
	oldDay := base.Add(-25 * time.Hour).UTC().Format("2006-01-02")
	oldFile := filepath.Join(dir, "requests-"+oldDay+".jsonl")
	data, err := os.ReadFile(oldFile)
	if err != nil {
		t.Fatalf("read rotated file: %v", err)
	}
	rewritten := replaceAll(data, "sk-...aaaa", "sk-...zzzz")
	if len(rewritten) != len(data) {
		t.Fatalf("test bug: rewrite changed size %d -> %d", len(data), len(rewritten))
	}
	if err := os.WriteFile(oldFile, rewritten, 0o600); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	future := time.Now().Add(time.Second)
	if err := os.Chtimes(oldFile, future, future); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	if err := st.catchUp(false); err != nil {
		t.Fatalf("catchUp after rewrite: %v", err)
	}
	check("after in-place rewrite")
	byClient, err := st.storeQuery(Filter{Dir: dir, ClientToken: "sk-...zzzz", Limit: 10})
	if err != nil {
		t.Fatalf("query rewritten token: %v", err)
	}
	if byClient.Summary.Count == 0 {
		t.Error("rewritten client token not visible in the index")
	}

	// 3. Truncation.
	if err := os.Truncate(today, 0); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	if err := st.catchUp(false); err != nil {
		t.Fatalf("catchUp after truncate: %v", err)
	}
	check("after truncate")

	// 4. Retention deleted a rotated file.
	if err := os.Remove(oldFile); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if err := st.catchUp(false); err != nil {
		t.Fatalf("catchUp after removal: %v", err)
	}
	check("after retention delete")
}

// TestStorePartialLine makes sure a half-written trailing line (the writer
// mid-append) is neither indexed nor skipped: the offset must stay before it
// so the next pass reads the completed line.
func TestStorePartialLine(t *testing.T) {
	withShanghaiBuckets(t)
	dir := t.TempDir()
	base := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	rec := Record{TS: base, AuthID: "auth-1.json", Model: "m", Input: 1, Status: 200}
	writeLog(t, dir, []Record{rec})

	st := openReadyStore(t, dir)

	path := filepath.Join(dir, "requests-"+base.UTC().Format("2006-01-02")+".jsonl")
	full, err := json.Marshal(Record{TS: base.Add(time.Minute), AuthID: "auth-1.json", Model: "m", Input: 5, Status: 200})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	fh, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// Write the record without its newline: a torn line.
	if _, err := fh.Write(full[:len(full)-5]); err != nil {
		t.Fatalf("write partial: %v", err)
	}
	_ = fh.Close()

	if err := st.catchUp(false); err != nil {
		t.Fatalf("catchUp with partial line: %v", err)
	}
	res, err := st.storeQuery(Filter{Dir: dir, Limit: 10})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if res.Summary.Count != 1 {
		t.Fatalf("partial line was indexed: count = %d, want 1", res.Summary.Count)
	}

	// Complete the line; the record must now appear.
	fh, err = os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if _, err := fh.Write(append(full[len(full)-5:], '\n')); err != nil {
		t.Fatalf("finish line: %v", err)
	}
	_ = fh.Close()

	if err := st.catchUp(false); err != nil {
		t.Fatalf("catchUp after completion: %v", err)
	}
	res, err = st.storeQuery(Filter{Dir: dir, Limit: 10})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if res.Summary.Count != 2 {
		t.Fatalf("completed line missing: count = %d, want 2", res.Summary.Count)
	}
	if res.Summary.InputTokens != 6 {
		t.Errorf("input tokens = %d, want 6", res.Summary.InputTokens)
	}
}

// TestStoreBucketLocationChange asserts a display-zone change rebuilds the
// derived rows rather than serving labels computed under the old zone.
func TestStoreBucketLocationChange(t *testing.T) {
	shanghai, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Skip("tzdata unavailable")
	}
	prev := bucketLoc
	t.Cleanup(func() { bucketLoc = prev })

	dir := t.TempDir()
	// 23:30 UTC is the next calendar day in +08:00.
	ts := time.Now().UTC().Add(-48 * time.Hour).Truncate(24 * time.Hour).Add(23*time.Hour + 30*time.Minute)
	writeLog(t, dir, []Record{{TS: ts, AuthID: "auth-1.json", Model: "m", Input: 1, Status: 200}})

	bucketLoc = time.UTC
	st := openReadyStore(t, dir)
	utcRes, err := st.storeQuery(Filter{Dir: dir, Limit: 10})
	if err != nil {
		t.Fatalf("query utc: %v", err)
	}
	st.Close()

	bucketLoc = shanghai
	st2 := openReadyStore(t, dir)
	shRes, err := st2.storeQuery(Filter{Dir: dir, Limit: 10})
	if err != nil {
		t.Fatalf("query shanghai: %v", err)
	}

	utcDay := ts.UTC().Format("2006-01-02")
	shDay := ts.In(shanghai).Format("2006-01-02")
	if utcDay == shDay {
		t.Fatal("test bug: the two zones agree on the day")
	}
	if _, ok := utcRes.ByDay[utcDay]; !ok {
		t.Errorf("UTC run: ByDay missing %q, has %v", utcDay, keysOf(utcRes.ByDay))
	}
	if _, ok := shRes.ByDay[shDay]; !ok {
		t.Errorf("Shanghai run: ByDay missing %q, has %v", shDay, keysOf(shRes.ByDay))
	}
}

// scanQuery runs the JSONL implementation regardless of any registered
// index, so tests can compare the two directly.
func scanQuery(f Filter) (*Result, error) {
	key := storeKey(f.Dir)
	storesMu.Lock()
	saved := stores[key]
	delete(stores, key)
	storesMu.Unlock()
	defer func() {
		storesMu.Lock()
		if saved != nil {
			stores[key] = saved
		}
		storesMu.Unlock()
	}()
	return Query(f)
}

func replaceAll(b []byte, old, new string) []byte {
	if len(old) != len(new) {
		panic(fmt.Sprintf("replaceAll needs equal lengths, got %d and %d", len(old), len(new)))
	}
	out := make([]byte, len(b))
	copy(out, b)
	o := []byte(old)
	n := []byte(new)
	for i := 0; i+len(o) <= len(out); i++ {
		if string(out[i:i+len(o)]) == string(o) {
			copy(out[i:i+len(n)], n)
		}
	}
	return out
}
