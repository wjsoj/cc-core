package requestlog

import (
	"testing"
	"time"
)

// setBuckets swaps the display zone for the duration of a test.
func setBuckets(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(name)
	if err != nil {
		t.Skip("tzdata unavailable")
	}
	prev := bucketLoc
	bucketLoc = loc
	t.Cleanup(func() { bucketLoc = prev })
	return loc
}

// relabelRecords straddle a UTC midnight so that a UTC -> UTC+8 switch is
// guaranteed to move labels: 20:00Z on 03-01 is 04:00 on 03-02 in Shanghai.
// sampleRecords spreads its entries over a range of offsets, so they do NOT
// all share one label — which is the point: the expectation is computed per
// record rather than assumed.
func relabelRecords() []Record {
	base := time.Date(2026, 3, 1, 20, 0, 0, 0, time.UTC)
	return sampleRecords(base)
}

// labelCounts is how many records land on each day label in zone, counting
// only the rows that reach the cube (attempt_only is excluded everywhere).
func labelCounts(recs []Record, zone string, billableOnly bool) map[string]int64 {
	loc, err := time.LoadLocation(zone)
	if err != nil {
		return nil
	}
	out := map[string]int64{}
	for _, r := range recs {
		if billableOnly && r.AttemptOnly {
			continue
		}
		out[r.TS.In(loc).Format("2006-01-02")]++
	}
	return out
}

// assertLabelCounts compares a bday/day histogram in the index against want.
func assertLabelCounts(t *testing.T, st *Store, column, table string, want map[string]int64) {
	t.Helper()
	agg := "COUNT(*)"
	if table == "agg_cube" {
		agg = "SUM(count)"
	}
	rows, err := st.db.Query(`SELECT ` + column + `, ` + agg + ` FROM ` + table + ` GROUP BY ` + column)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := map[string]int64{}
	for rows.Next() {
		var label string
		var n int64
		if err := rows.Scan(&label, &n); err != nil {
			t.Fatal(err)
		}
		got[label] = n
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for label, n := range want {
		if got[label] != n {
			t.Errorf("%s.%s[%s] = %d, want %d", table, column, label, got[label], n)
		}
	}
	for label, n := range got {
		if _, ok := want[label]; !ok {
			t.Errorf("%s.%s has unexpected label %s with %d row(s)", table, column, label, n)
		}
	}
}

// A display-zone change must RELABEL history, never delete it.
//
// The old behaviour dropped req/agg_cube/ingest and let the file scanner
// rebuild from the archive. With JSONLArchive:false there is no archive, so
// that path silently destroyed every record the box had — and the next backup
// would have shipped the empty result. This is the regression test for that.
func TestZoneChangeRelabelsWithoutArchive(t *testing.T) {
	dir := t.TempDir()
	recs := relabelRecords()

	// Ingest under UTC, index-only.
	func() {
		setBuckets(t, "UTC")
		st := openReadyStore(t, dir)
		w, err := OpenWithOptions(dir, Options{JSONLArchive: false})
		if err != nil {
			t.Fatalf("OpenWithOptions: %v", err)
		}
		for _, r := range recs {
			w.Log(r)
		}
		drainWriter(t, w, st)

		if got := countRows(t, st, `SELECT COUNT(*) FROM req`); got != int64(len(recs)) {
			t.Fatalf("req rows = %d, want %d", got, len(recs))
		}
		assertLabelCounts(t, st, "bday", "req", labelCounts(recs, "UTC", false))
		st.Close()
	}()

	// Reopen in Asia/Shanghai — the zone change fires at OpenStore.
	setBuckets(t, "Asia/Shanghai")
	st := openReadyStore(t, dir)

	if got := countRows(t, st, `SELECT COUNT(*) FROM req`); got != int64(len(recs)) {
		t.Fatalf("rows after zone change = %d, want %d — history was destroyed", got, len(recs))
	}
	assertLabelCounts(t, st, "bday", "req", labelCounts(recs, "Asia/Shanghai", false))
	// `day` is the source file's UTC day and must NOT move with the zone.
	assertLabelCounts(t, st, "day", "req", labelCounts(recs, "UTC", false))
	// The cube is keyed on bday, so it has to have been rebuilt from the
	// relabelled rows rather than left pointing at the old label.
	assertLabelCounts(t, st, "bday", "agg_cube", labelCounts(recs, "Asia/Shanghai", true))

	// And the zone is recorded, so a second open is a no-op.
	var got string
	if err := st.db.QueryRow(`SELECT value FROM meta WHERE key = 'bucket_loc'`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != "Asia/Shanghai" {
		t.Errorf("bucket_loc = %q, want Asia/Shanghai", got)
	}
}

// ingest must survive a relabel: the rows are already folded in correctly, and
// dropping it would make the scanner re-read every file it had already done.
func TestZoneChangeKeepsIngestLedger(t *testing.T) {
	dir := t.TempDir()
	recs := relabelRecords()

	func() {
		setBuckets(t, "UTC")
		st := openReadyStore(t, dir)
		writeLog(t, dir, recs)
		if err := st.catchUp(false); err != nil {
			t.Fatalf("catchUp: %v", err)
		}
		if got := countRows(t, st, `SELECT COUNT(*) FROM ingest`); got == 0 {
			t.Fatal("no ingest rows to begin with")
		}
		st.Close()
	}()

	setBuckets(t, "Asia/Shanghai")
	st := openReadyStore(t, dir)
	if got := countRows(t, st, `SELECT COUNT(*) FROM ingest`); got == 0 {
		t.Error("ingest ledger was cleared by the zone change; the archive will be re-read in full")
	}
	if got := countRows(t, st, `SELECT COUNT(*) FROM req`); got != int64(len(recs)) {
		t.Errorf("req rows = %d, want %d", got, len(recs))
	}
}

// Re-opening in the same zone must not touch anything.
func TestSameZoneIsNoOp(t *testing.T) {
	dir := t.TempDir()
	recs := relabelRecords()
	setBuckets(t, "Asia/Shanghai")

	st := openReadyStore(t, dir)
	w, err := OpenWithOptions(dir, Options{JSONLArchive: false})
	if err != nil {
		t.Fatalf("OpenWithOptions: %v", err)
	}
	for _, r := range recs {
		w.Log(r)
	}
	drainWriter(t, w, st)
	st.Close()

	st2 := openReadyStore(t, dir)
	if got := countRows(t, st2, `SELECT COUNT(*) FROM req`); got != int64(len(recs)) {
		t.Errorf("req rows = %d, want %d", got, len(recs))
	}
	assertLabelCounts(t, st2, "bday", "req", labelCounts(recs, "Asia/Shanghai", false))
}
