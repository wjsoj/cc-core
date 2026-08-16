package requestlog

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

// A window stated in whole days is answered from the pre-summed cube instead
// of a row-by-row pass over req. That is only sound if the two produce the
// same numbers, so every test here is a parity test: the fast path has to
// agree with the slow one, not merely be fast.
//
// The stakes are concrete. On the production archive (1M rows) the panel's
// default 7-day window cost 1.8s through req and 48ms through the cube, and
// the panel re-issues it on every filter change.

// dayLabel renders an instant the way bday does — in the bucketing zone,
// which is what makes these labels comparable to the cube's.
func dayLabel(t time.Time) string { return t.In(bucketLoc).Format("2006-01-02") }

func TestDayBoundedQueryMatchesTheScan(t *testing.T) {
	withShanghaiBuckets(t)
	dir := t.TempDir()
	base := time.Now().UTC().Add(-6 * time.Hour).Truncate(time.Second)
	writeLog(t, dir, sampleRecords(base))
	st := openReadyStore(t, dir)

	// Deliberately wide enough to include the record that lands on a
	// different day in +08:00 than it does in UTC.
	from := dayLabel(base.Add(-73 * time.Hour))
	to := dayLabel(base)
	f := Filter{Dir: dir, FromDay: from, ToDay: to, Limit: 50}

	if !cubeEligible(f.resolveDays()) {
		t.Fatal("a day-bounded filter did not reach the cube; the whole point is lost")
	}

	want, err := scanQuery(f)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	got, err := st.storeQuery(f)
	if err != nil {
		t.Fatalf("cube: %v", err)
	}
	if !reflect.DeepEqual(want.Summary, got.Summary) {
		t.Errorf("summary:\n  scan %+v\n  cube %+v", want.Summary, got.Summary)
	}
	assertSameAggregates(t, "by_day", want.ByDay, got.ByDay)
	assertSameAggregates(t, "by_model", want.ByModel, got.ByModel)
	assertSameAggregates(t, "by_client", want.ByClient, got.ByClient)
}

// The cube groups on bday and the req path compares timestamps. Stating the
// same window both ways must give the same answer, or the speed-up would be
// a silent change of meaning — the panel's numbers would shift the moment
// the query got faster.
func TestDayBoundsAgreeWithTheEquivalentTimestamps(t *testing.T) {
	withShanghaiBuckets(t)
	dir := t.TempDir()
	base := time.Now().UTC().Add(-6 * time.Hour).Truncate(time.Second)
	writeLog(t, dir, sampleRecords(base))
	st := openReadyStore(t, dir)

	from := dayLabel(base.Add(-49 * time.Hour))
	to := dayLabel(base)
	byDays := Filter{Dir: dir, FromDay: from, ToDay: to, Limit: 50}

	// The same window as instants: midnight to midnight in the display zone.
	start, err := time.ParseInLocation("2006-01-02", from, bucketLoc)
	if err != nil {
		t.Fatal(err)
	}
	end, err := time.ParseInLocation("2006-01-02", to, bucketLoc)
	if err != nil {
		t.Fatal(err)
	}
	byStamps := Filter{
		Dir: dir, From: start, To: end.AddDate(0, 0, 1).Add(-time.Nanosecond), Limit: 50,
	}
	if cubeEligible(byStamps.resolveDays()) {
		t.Fatal("a raw timestamp window claimed cube eligibility; alignment must not be inferred")
	}

	cube, err := st.storeQuery(byDays)
	if err != nil {
		t.Fatalf("cube: %v", err)
	}
	req, err := st.storeQuery(byStamps)
	if err != nil {
		t.Fatalf("req: %v", err)
	}
	if !reflect.DeepEqual(cube.Summary, req.Summary) {
		t.Errorf("summary:\n  cube %+v\n  req  %+v", cube.Summary, req.Summary)
	}
	assertSameAggregates(t, "by_day", req.ByDay, cube.ByDay)
	assertSameAggregates(t, "by_model", req.ByModel, cube.ByModel)

	// Entries come from req either way, so the page must be identical too:
	// the day labels have to resolve into the same timestamp bounds.
	if len(cube.Entries) != len(req.Entries) {
		t.Fatalf("entries: cube %d, req %d", len(cube.Entries), len(req.Entries))
	}
	for i := range cube.Entries {
		if !cube.Entries[i].TS.Equal(req.Entries[i].TS) {
			t.Errorf("entry %d: cube %v, req %v", i, cube.Entries[i].TS, req.Entries[i].TS)
		}
	}
}

// Filtering narrows an already-fast query; it must not quietly send it back
// to the slow path, and it must still agree with the scan.
func TestDayBoundedQueryStillFiltersOnEveryDimension(t *testing.T) {
	withShanghaiBuckets(t)
	dir := t.TempDir()
	base := time.Now().UTC().Add(-6 * time.Hour).Truncate(time.Second)
	writeLog(t, dir, sampleRecords(base))
	st := openReadyStore(t, dir)

	from := dayLabel(base.Add(-73 * time.Hour))
	to := dayLabel(base)

	for _, tc := range []struct {
		name   string
		mutate func(*Filter)
	}{
		{"model", func(f *Filter) { f.Model = "claude-opus-4-8" }},
		{"model is case-insensitive", func(f *Filter) { f.Model = "CLAUDE-OPUS-4-8" }},
		{"client token", func(f *Filter) { f.ClientToken = "sk-...bbbb" }},
		{"provider", func(f *Filter) { f.Provider = "openai" }},
		{"legacy rows count as anthropic", func(f *Filter) { f.Provider = "anthropic" }},
		{"auth id", func(f *Filter) { f.AuthID = "auth-2.json" }},
		{"status", func(f *Filter) { f.Status = 429 }},
		{"saas user", func(f *Filter) { f.UserID = 42 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := Filter{Dir: dir, FromDay: from, ToDay: to, Limit: 50}
			tc.mutate(&f)
			if !cubeEligible(f.resolveDays()) {
				t.Fatal("filtering dropped the query off the cube path")
			}
			want, err := scanQuery(f)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			got, err := st.storeQuery(f)
			if err != nil {
				t.Fatalf("cube: %v", err)
			}
			if !reflect.DeepEqual(want.Summary, got.Summary) {
				t.Errorf("summary:\n  scan %+v\n  cube %+v", want.Summary, got.Summary)
			}
			assertSameAggregates(t, "by_model", want.ByModel, got.ByModel)
			assertSameAggregates(t, "by_day", want.ByDay, got.ByDay)
		})
	}
}

// One open end is still a whole-days window.
func TestOneSidedDayBounds(t *testing.T) {
	withShanghaiBuckets(t)
	dir := t.TempDir()
	base := time.Now().UTC().Add(-6 * time.Hour).Truncate(time.Second)
	writeLog(t, dir, sampleRecords(base))
	st := openReadyStore(t, dir)

	for _, f := range []Filter{
		{Dir: dir, FromDay: dayLabel(base.Add(-25 * time.Hour)), Limit: 50},
		{Dir: dir, ToDay: dayLabel(base.Add(-25 * time.Hour)), Limit: 50},
	} {
		if !cubeEligible(f.resolveDays()) {
			t.Fatalf("%+v did not reach the cube", f)
		}
		want, err := scanQuery(f)
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		got, err := st.storeQuery(f)
		if err != nil {
			t.Fatalf("cube: %v", err)
		}
		if !reflect.DeepEqual(want.Summary, got.Summary) {
			t.Errorf("from=%q to=%q summary:\n  scan %+v\n  cube %+v",
				f.FromDay, f.ToDay, want.Summary, got.Summary)
		}
	}
}

func TestResolveDays(t *testing.T) {
	withShanghaiBuckets(t)
	day := "2026-08-02"
	start, err := time.ParseInLocation("2006-01-02", day, bucketLoc)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("labels become exact day boundaries in the bucketing zone", func(t *testing.T) {
		f := Filter{FromDay: day, ToDay: day}.resolveDays()
		if !f.From.Equal(start) {
			t.Errorf("From = %v, want %v", f.From, start)
		}
		if want := start.AddDate(0, 0, 1).Add(-time.Nanosecond); !f.To.Equal(want) {
			t.Errorf("To = %v, want %v", f.To, want)
		}
		if !f.dayBounds {
			t.Error("dayBounds not set, so the cube will be skipped")
		}
	})

	t.Run("resolving twice changes nothing", func(t *testing.T) {
		once := Filter{FromDay: day, ToDay: day}.resolveDays()
		twice := once.resolveDays()
		if !reflect.DeepEqual(once, twice) {
			t.Errorf("not idempotent:\n  once  %+v\n  twice %+v", once, twice)
		}
	})

	// Two windows in one filter is a contradiction, not a refinement. The
	// timestamps are the more specific statement, so they win — and the
	// labels must go, or the cube would answer a window req never saw.
	t.Run("explicit timestamps beat labels and drop them", func(t *testing.T) {
		other := start.AddDate(0, 0, -10)
		f := Filter{FromDay: day, ToDay: day, From: other}.resolveDays()
		if !f.From.Equal(other) {
			t.Errorf("From = %v, want the explicit %v", f.From, other)
		}
		if f.FromDay != "" || f.ToDay != "" {
			t.Errorf("labels survived as %q..%q", f.FromDay, f.ToDay)
		}
		if cubeEligible(f) {
			t.Error("the cube claimed a window it cannot express")
		}
	})

	t.Run("an unparseable label constrains nothing rather than everything", func(t *testing.T) {
		f := Filter{FromDay: "last tuesday"}.resolveDays()
		if !f.From.IsZero() || f.FromDay != "" {
			t.Errorf("garbage label leaked through as %q / %v", f.FromDay, f.From)
		}
		if !cubeEligible(f) {
			t.Error("an unbounded filter should still reach the cube")
		}
	})

	t.Run("no labels is left untouched", func(t *testing.T) {
		in := Filter{From: start}
		if got := in.resolveDays(); !reflect.DeepEqual(in, got) {
			t.Errorf("mutated a filter with no labels: %+v", got)
		}
	})
}

// A per-member window must seek into the cube, not scan it.
//
// The cube's key leads with (day, bday, model, client, …), so a filter that
// only names a token and a day range constrains none of the prefix and the
// key is unusable. That is affordable when the panel asks one question; the
// workspace usage endpoint asks it once per member, and the price of a scan
// is then (members × groupings × whole cube) — a cost driven by the cube's
// dimension cardinality rather than by how much the member actually spent.
// idx_cube_ct is what keeps that proportional to the member's own rows.
func TestMemberFilteredCubeQuerySeeksRatherThanScans(t *testing.T) {
	withShanghaiBuckets(t)
	dir := t.TempDir()
	base := time.Now().UTC().Add(-6 * time.Hour).Truncate(time.Second)
	writeLog(t, dir, sampleRecords(base))
	st := openReadyStore(t, dir)

	f := Filter{
		ClientToken: "sk-...aaaa",
		FromDay:     dayLabel(base.Add(-73 * time.Hour)),
		ToDay:       dayLabel(base),
	}.resolveDays()
	where, args := cubeWhere(f)

	// Every grouping aggregatesFromCube can issue, since they are separate
	// statements and the planner decides each one on its own.
	for _, dim := range []string{`''`, `model`, `bday`,
		`CASE WHEN client_token != '' THEN client_token ELSE client END`} {
		plan := explainPlan(t, st, `SELECT `+dim+`, `+rollupSelect+
			` FROM agg_cube WHERE `+where+` GROUP BY `+dim, args...)
		if !strings.Contains(plan, "idx_cube_ct") {
			t.Errorf("GROUP BY %s did not use the token index:\n%s", dim, plan)
		}
		if strings.Contains(plan, "SCAN agg_cube") {
			t.Errorf("GROUP BY %s still scans the whole cube:\n%s", dim, plan)
		}
	}
}

func explainPlan(t *testing.T, st *Store, q string, args ...any) string {
	t.Helper()
	rows, err := st.db.Query("EXPLAIN QUERY PLAN "+q, args...)
	if err != nil {
		t.Fatalf("explain: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id, parent, notused int
		var detail string
		if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
			t.Fatalf("explain scan: %v", err)
		}
		out = append(out, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("explain rows: %v", err)
	}
	return strings.Join(out, "\n")
}
