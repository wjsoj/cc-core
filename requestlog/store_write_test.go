package requestlog

// Tests for the writer-side half of the index: records inserted as they are
// logged, rather than re-read from the archive afterwards.
//
// The property that matters throughout is that the two producers — the writer
// and the file scanner — are interchangeable and can both run over the same
// line without double-counting it.

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// drainWriter closes the writer (flushing its pending batch) and folds
// anything still only on disk into the index.
func drainWriter(t *testing.T, w *Writer, st *Store) {
	t.Helper()
	w.Close()
	if err := st.catchUp(false); err != nil {
		t.Fatalf("catchUp: %v", err)
	}
}

func countRows(t *testing.T, st *Store, q string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := st.db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatalf("count (%s): %v", q, err)
	}
	return n
}

// TestWriterDualWriteMatchesScan is the headline equivalence check: records
// that reached the index through the writer must be indistinguishable from
// records that reached it through the scanner, for every filter shape.
func TestWriterDualWriteMatchesScan(t *testing.T) {
	withShanghaiBuckets(t)
	dir := t.TempDir()
	base := time.Now().UTC().Add(-6 * time.Hour).Truncate(time.Second)
	recs := sampleRecords(base)

	st := openReadyStore(t, dir)
	w, err := Open(dir, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	for _, r := range recs {
		w.Log(r)
	}
	drainWriter(t, w, st)

	// Each record must exist exactly once even though both producers saw it.
	if got, want := countRows(t, st, `SELECT COUNT(*) FROM req`), int64(len(recs)); got != want {
		t.Fatalf("req rows = %d, want %d (double-counted?)", got, want)
	}

	// ingest.rows counts lines folded in, not inserts won. Under dual write
	// the writer usually gets there first, so counting inserts would report
	// ~0 for a file full of records and break the one cheap consistency check
	// this index has against the archive.
	if got, want := countRows(t, st, `SELECT COALESCE(SUM(rows),0) FROM ingest`), int64(len(recs)); got != want {
		t.Errorf("ingest.rows total = %d, want %d (line count, not insert count)", got, want)
	}

	for _, tc := range filterCases(dir, base) {
		t.Run(tc.name, func(t *testing.T) {
			want, err := scanQuery(tc.f)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			got, err := Query(tc.f)
			if err != nil {
				t.Fatalf("index: %v", err)
			}
			assertSameEntries(t, want.Entries, got.Entries)
			if want.Summary != got.Summary {
				t.Errorf("summary:\n  want %+v\n  got  %+v", want.Summary, got.Summary)
			}
			assertSameAggregates(t, "ByClient", want.ByClient, got.ByClient)
			assertSameAggregates(t, "ByModel", want.ByModel, got.ByModel)
			assertSameAggregates(t, "ByDay", want.ByDay, got.ByDay)
		})
	}
}

// TestWriterDualWriteDedup forces the scanner to re-read a file the writer
// already indexed, which is what happens after any repair that resets a file's
// ingest offset.
func TestWriterDualWriteDedup(t *testing.T) {
	withShanghaiBuckets(t)
	dir := t.TempDir()
	base := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)
	recs := sampleRecords(base)

	st := openReadyStore(t, dir)
	w, err := Open(dir, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	for _, r := range recs {
		w.Log(r)
	}
	drainWriter(t, w, st)
	before := countRows(t, st, `SELECT COUNT(*) FROM req`)

	// Rewind every file to the start without touching req: the next pass
	// re-offers every line the writer already inserted.
	if _, err := st.db.Exec(`UPDATE ingest SET offset = 0, rows = 0`); err != nil {
		t.Fatalf("rewind: %v", err)
	}
	if err := st.catchUp(false); err != nil {
		t.Fatalf("catchUp: %v", err)
	}
	if after := countRows(t, st, `SELECT COUNT(*) FROM req`); after != before {
		t.Fatalf("re-ingest duplicated rows: %d -> %d", before, after)
	}

	// The cube is rebuilt from req, so a duplicate would have shown up as
	// doubled money as well; check it directly rather than inferring.
	// Compared against the visible rows, not `before`: attempt-only rows are
	// stored but never counted.
	res, err := Query(Filter{Dir: dir})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	visible := countRows(t, st, `SELECT COUNT(*) FROM req WHERE attempt_only = 0`)
	if res.Summary.Count != visible {
		t.Errorf("summary count = %d, want %d", res.Summary.Count, visible)
	}
}

// TestWriterCrashBeforeIndexFlush covers the window the archive exists for:
// lines are on disk but the process died before they reached the index.
func TestWriterCrashBeforeIndexFlush(t *testing.T) {
	withShanghaiBuckets(t)
	dir := t.TempDir()
	base := time.Now().UTC().Add(-3 * time.Hour).Truncate(time.Second)
	recs := sampleRecords(base)

	// Simulate the crash: the file holds everything, the index holds nothing.
	writeLog(t, dir, recs)
	st := openReadyStore(t, dir)
	if got, want := countRows(t, st, `SELECT COUNT(*) FROM req`), int64(len(recs)); got != want {
		t.Fatalf("recovered %d rows, want %d", got, want)
	}

	// A writer that starts against the same day must not reuse offsets the
	// recovered rows already claim.
	w, err := Open(dir, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	extra := recs[0]
	extra.TS = base.Add(time.Minute)
	extra.Model = "post-restart-model"
	w.Log(extra)
	drainWriter(t, w, st)

	if got, want := countRows(t, st, `SELECT COUNT(*) FROM req`), int64(len(recs)+1); got != want {
		t.Fatalf("after restart rows = %d, want %d", got, want)
	}
	if got := countRows(t, st, `SELECT COUNT(*) FROM req WHERE model = 'post-restart-model'`); got != 1 {
		t.Fatalf("post-restart record landed %d times, want 1", got)
	}
}

// TestWriterArchiveOff is the end state: SQLite is the only copy.
func TestWriterArchiveOff(t *testing.T) {
	withShanghaiBuckets(t)
	dir := t.TempDir()
	base := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	recs := sampleRecords(base)

	st := openReadyStore(t, dir)
	w, err := OpenWithOptions(dir, Options{JSONLArchive: false})
	if err != nil {
		t.Fatalf("OpenWithOptions: %v", err)
	}
	for _, r := range recs {
		w.Log(r)
	}
	drainWriter(t, w, st)

	files, err := filepath.Glob(filepath.Join(dir, "requests-*.jsonl"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(files) != 0 {
		t.Fatalf("archive disabled but %d jsonl file(s) written: %v", len(files), files)
	}
	if got, want := countRows(t, st, `SELECT COUNT(*) FROM req`), int64(len(recs)); got != want {
		t.Fatalf("req rows = %d, want %d", got, want)
	}

	// Aggregates must still be complete — nothing scanned them into place.
	res, err := Query(Filter{Dir: dir})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	var wantCount int64
	for _, r := range recs {
		if !r.AttemptOnly {
			wantCount++
		}
	}
	if res.Summary.Count != wantCount {
		t.Errorf("summary count = %d, want %d", res.Summary.Count, wantCount)
	}
}

// TestWriterArchiveOffNeedsIndex: refusing to start is the only safe response
// to "no archive and nowhere to write".
func TestWriterArchiveOffNeedsIndex(t *testing.T) {
	dir := t.TempDir()
	if _, err := OpenWithOptions(dir, Options{JSONLArchive: false}); err == nil {
		t.Fatal("expected an error when the archive is off and no index is open")
	}
}

// TestExportRoundTrip: what comes out must be loadable as the archive it
// replaced.
func TestExportRoundTrip(t *testing.T) {
	withShanghaiBuckets(t)
	dir := t.TempDir()
	base := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	recs := sampleRecords(base)
	writeLog(t, dir, recs)
	openReadyStore(t, dir)

	// Through the read-only handle a CLI would use, not the server's own —
	// that path must work against a database another process has open.
	ro, err := OpenStoreForRead(dir)
	if err != nil {
		t.Fatalf("OpenStoreForRead: %v", err)
	}
	defer ro.Close()

	var buf bytes.Buffer
	n, err := ro.Export("", "", &buf)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if n != len(recs) {
		t.Fatalf("exported %d records, want %d", n, len(recs))
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != len(recs) {
		t.Fatalf("exported %d lines, want %d", len(lines), len(recs))
	}
	var prev time.Time
	for i, ln := range lines {
		var r Record
		if err := json.Unmarshal([]byte(ln), &r); err != nil {
			t.Fatalf("line %d not valid JSON: %v", i, err)
		}
		if i > 0 && r.TS.Before(prev) {
			t.Fatalf("line %d out of order: %v before %v", i, r.TS, prev)
		}
		prev = r.TS
	}
}

// TestRewriteClientMaskIndex checks the cheap path: one UPDATE, and no
// re-parse of the archive that the rewrite just touched.
func TestRewriteClientMaskIndex(t *testing.T) {
	withShanghaiBuckets(t)
	dir := t.TempDir()
	base := time.Now().UTC().Add(-30 * time.Hour).Truncate(time.Second)
	recs := sampleRecords(base)
	writeLog(t, dir, recs)
	st := openReadyStore(t, dir)

	const oldMask, newMask = "sk-...aaaa", "sk-...zzzz"
	want := countRows(t, st, `SELECT COUNT(*) FROM req WHERE client_token = ?`, oldMask)
	if want == 0 {
		t.Fatal("fixture has no rows with the old mask")
	}
	totalBefore := countRows(t, st, `SELECT COUNT(*) FROM req`)

	w, err := Open(dir, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer w.Close()
	n, err := w.RewriteClientMask(oldMask, newMask)
	if err != nil {
		t.Fatalf("RewriteClientMask: %v", err)
	}
	if int64(n) != want {
		t.Errorf("rewrote %d records, want %d", n, want)
	}
	if got := countRows(t, st, `SELECT COUNT(*) FROM req WHERE client_token = ?`, oldMask); got != 0 {
		t.Errorf("%d rows still carry the old mask", got)
	}
	if got := countRows(t, st, `SELECT COUNT(*) FROM req WHERE client_token = ?`, newMask); got != want {
		t.Errorf("new mask on %d rows, want %d", got, want)
	}
	if got := countRows(t, st, `SELECT COUNT(*) FROM req`); got != totalBefore {
		t.Errorf("row count changed during rewrite: %d -> %d", totalBefore, got)
	}

	// A following catch-up must not decide the rewritten files were tampered
	// with and rebuild them (which would be correct but costs a full re-parse).
	if err := st.catchUp(false); err != nil {
		t.Fatalf("catchUp: %v", err)
	}
	if got := countRows(t, st, `SELECT COUNT(*) FROM req WHERE client_token = ?`, newMask); got != want {
		t.Errorf("after catch-up new mask on %d rows, want %d", got, want)
	}

	// The cube must agree with req, or the panel would show the old label.
	res, err := Query(Filter{Dir: dir, ClientToken: newMask})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if res.Summary.Count == 0 {
		t.Error("cube has no rows for the new mask")
	}
}

// TestPruneBefore covers retention with no file to delete.
func TestPruneBefore(t *testing.T) {
	withShanghaiBuckets(t)
	dir := t.TempDir()
	base := time.Now().UTC().Add(-72 * time.Hour).Truncate(time.Second)
	recs := sampleRecords(base)
	writeLog(t, dir, recs)
	st := openReadyStore(t, dir)

	days := map[string]bool{}
	for _, r := range recs {
		days[r.TS.UTC().Format("2006-01-02")] = true
	}
	if len(days) < 2 {
		t.Skipf("fixture spans %d day(s); need at least 2", len(days))
	}
	var sorted []string
	for d := range days {
		sorted = append(sorted, d)
	}
	// Cut off everything before the newest day.
	newest := ""
	for _, d := range sorted {
		if d > newest {
			newest = d
		}
	}
	if err := st.pruneBefore(newest); err != nil {
		t.Fatalf("pruneBefore: %v", err)
	}
	if got := countRows(t, st, `SELECT COUNT(*) FROM req WHERE day < ?`, newest); got != 0 {
		t.Errorf("%d rows survived the cutoff", got)
	}
	if got := countRows(t, st, `SELECT COUNT(*) FROM agg_cube WHERE day < ?`, newest); got != 0 {
		t.Errorf("%d cube rows survived the cutoff", got)
	}
	if got := countRows(t, st, `SELECT COUNT(*) FROM req WHERE day = ?`, newest); got == 0 {
		t.Error("prune removed the day it was told to keep")
	}
}

// TestCubeMatchesReqAggregates guards the split between the two aggregate
// sources: a query with a time bound reads req, the same query without one
// reads the cube, and they must agree on the rows they share.
func TestCubeMatchesReqAggregates(t *testing.T) {
	withShanghaiBuckets(t)
	dir := t.TempDir()
	base := time.Now().UTC().Add(-6 * time.Hour).Truncate(time.Second)
	recs := sampleRecords(base)
	writeLog(t, dir, recs)
	openReadyStore(t, dir)

	// A bound wide enough to include everything forces the req path while
	// selecting the same rows the cube path would.
	wide := Filter{Dir: dir, From: base.Add(-365 * 24 * time.Hour)}
	viaReq, err := Query(wide)
	if err != nil {
		t.Fatalf("query (req): %v", err)
	}
	if cubeEligible(wide) {
		t.Fatal("bounded filter should not be cube-eligible")
	}
	viaCube, err := Query(Filter{Dir: dir})
	if err != nil {
		t.Fatalf("query (cube): %v", err)
	}
	if !cubeEligible(Filter{Dir: dir}) {
		t.Fatal("unbounded filter should be cube-eligible")
	}
	if viaReq.Summary != viaCube.Summary {
		t.Errorf("summary differs by source:\n  req  %+v\n  cube %+v", viaReq.Summary, viaCube.Summary)
	}
	assertSameAggregates(t, "ByModel", viaReq.ByModel, viaCube.ByModel)
	assertSameAggregates(t, "ByClient", viaReq.ByClient, viaCube.ByClient)
	assertSameAggregates(t, "ByDay", viaReq.ByDay, viaCube.ByDay)
}
