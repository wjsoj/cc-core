package requestlog

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The 2026-08-09 production incident, as a test.
//
// catchUp treats "a file in the ingest ledger is no longer on disk" as a
// retention delete and calls dropDay, which is `DELETE FROM req WHERE day = ?`.
// That is right while the archive is authoritative. Once the archive is turned
// off, the ledger still names every file written before the switch, and the
// rows behind them exist ONLY in this database — so removing the now-inert
// files (housekeeping, not retention) deleted 999k rows of history, including
// rows the writer had inserted directly.
func TestArchiveOffKeepsRowsWhenFilesVanish(t *testing.T) {
	withShanghaiBuckets(t)
	dir := t.TempDir()
	base := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Second)
	recs := sampleRecords(base)

	// Phase 1: an ordinary archived run, so the ledger gets populated.
	st := openReadyStore(t, dir)
	writeLog(t, dir, recs)
	if err := st.catchUp(false); err != nil {
		t.Fatalf("catchUp: %v", err)
	}
	total := countRows(t, st, `SELECT COUNT(*) FROM req`)
	if total == 0 {
		t.Fatal("nothing ingested")
	}
	if countRows(t, st, `SELECT COUNT(*) FROM ingest`) == 0 {
		t.Fatal("ledger empty; the test would not exercise the purge")
	}

	// Phase 2: switch to index-only. The writer declares the mode as it opens.
	w, err := OpenWithOptions(dir, Options{JSONLArchive: false})
	if err != nil {
		t.Fatalf("OpenWithOptions: %v", err)
	}
	defer w.Close()

	// Phase 3: the operator deletes the now-inert archive.
	files, _ := filepath.Glob(filepath.Join(dir, "requests-*.jsonl"))
	if len(files) == 0 {
		t.Fatal("no archive files to remove")
	}
	for _, f := range files {
		if err := os.Remove(f); err != nil {
			t.Fatal(err)
		}
	}

	// Two passes: the purge, if it fired at all, would fire on the first.
	for range 2 {
		if err := st.catchUp(false); err != nil {
			t.Fatalf("catchUp after removal: %v", err)
		}
	}

	if got := countRows(t, st, `SELECT COUNT(*) FROM req`); got != total {
		t.Fatalf("history destroyed by removing inert archive files: %d rows left of %d", got, total)
	}
	if got := countRows(t, st, `SELECT COALESCE(SUM(count), 0) FROM agg_cube`); got == 0 {
		t.Error("cube was emptied even though the rows survived")
	}
}

// The archive-on behaviour is deliberate and must not regress: when the files
// ARE the record, retention deleting one has to take its rows with it.
func TestArchiveOnStillDropsDeletedDays(t *testing.T) {
	withShanghaiBuckets(t)
	dir := t.TempDir()
	base := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Second)
	recs := sampleRecords(base)

	st := openReadyStore(t, dir)
	writeLog(t, dir, recs)
	if err := st.catchUp(false); err != nil {
		t.Fatalf("catchUp: %v", err)
	}
	total := countRows(t, st, `SELECT COUNT(*) FROM req`)

	w, err := OpenWithOptions(dir, Options{JSONLArchive: true})
	if err != nil {
		t.Fatalf("OpenWithOptions: %v", err)
	}
	defer w.Close()

	files, _ := filepath.Glob(filepath.Join(dir, "requests-*.jsonl"))
	if len(files) < 1 {
		t.Fatal("no archive files")
	}
	if err := os.Remove(files[0]); err != nil {
		t.Fatal(err)
	}
	if err := st.catchUp(false); err != nil {
		t.Fatalf("catchUp: %v", err)
	}
	if got := countRows(t, st, `SELECT COUNT(*) FROM req`); got >= total {
		t.Errorf("retention delete did not drop the day's rows: %d of %d remain", got, total)
	}
}

// Before any Writer opens, the mode is unknown — and "unknown" must not
// authorise a destructive purge. This is the case a restored database lands
// in: its ledger names files that the restore did not bring back.
func TestUnknownArchiveModeDoesNotPurge(t *testing.T) {
	withShanghaiBuckets(t)
	dir := t.TempDir()
	base := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Second)
	recs := sampleRecords(base)

	st := openReadyStore(t, dir)
	writeLog(t, dir, recs)
	if err := st.catchUp(false); err != nil {
		t.Fatalf("catchUp: %v", err)
	}
	total := countRows(t, st, `SELECT COUNT(*) FROM req`)
	st.Close()

	// Remove the files, then reopen with no Writer at all — exactly what a
	// restore-then-start does before the server wires its writer up.
	files, _ := filepath.Glob(filepath.Join(dir, "requests-*.jsonl"))
	for _, f := range files {
		if err := os.Remove(f); err != nil {
			t.Fatal(err)
		}
	}
	st2 := openReadyStore(t, dir)
	if err := st2.catchUp(false); err != nil {
		t.Fatalf("catchUp: %v", err)
	}
	if got := countRows(t, st2, `SELECT COUNT(*) FROM req`); got != total {
		t.Fatalf("rows purged with no writer to declare the mode: %d of %d", got, total)
	}
}
