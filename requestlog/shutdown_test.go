package requestlog

import (
	"path/filepath"
	"testing"
	"time"
)

// bufferedWriter returns a writer with records still pending: the drain loop
// only flushes on its 5s ticker, at dbBatch, or on Close, so a couple of
// records logged and immediately handed back are still in memory.
func bufferedWriter(t *testing.T, dir string, archive bool) (*Writer, []Record) {
	t.Helper()
	w, err := OpenWithOptions(dir, Options{JSONLArchive: archive})
	if err != nil {
		t.Fatalf("OpenWithOptions: %v", err)
	}
	recs := sampleRecords(time.Now().UTC().Add(-time.Hour).Truncate(time.Second))
	for _, r := range recs {
		w.Log(r)
	}
	return w, recs
}

// Shutdown is the supported way to stop the pair, and the property that matters
// is that nothing is lost on the way down.
func TestShutdownKeepsTheFinalBatch(t *testing.T) {
	withShanghaiBuckets(t)
	dir := t.TempDir()
	st := openReadyStore(t, dir)
	w, recs := bufferedWriter(t, dir, false)

	Shutdown(w, st)

	if dropped := w.Dropped(); dropped != 0 {
		t.Errorf("Shutdown dropped %d records", dropped)
	}
	// Re-open read-only to confirm the rows really landed, rather than trusting
	// a counter on the object that just wrote them.
	reopened := openReadyStore(t, dir)
	defer reopened.Close()
	if got, want := countRows(t, reopened, `SELECT COUNT(*) FROM req`), int64(len(recs)); got != want {
		t.Errorf("rows after shutdown = %d, want %d", got, want)
	}
}

// The hazard Shutdown exists to prevent, pinned so the ordering requirement is
// an observable property rather than folklore.
//
// Closing the store first deregisters it, so the writer's final flush resolves
// no destination. With the archive off there is no file behind it and the batch
// is gone. If this ever stops failing, the hazard is gone and Shutdown's doc
// comment should be revisited.
func TestClosingTheStoreFirstLosesTheFinalBatch(t *testing.T) {
	withShanghaiBuckets(t)
	dir := t.TempDir()
	st := openReadyStore(t, dir)
	w, recs := bufferedWriter(t, dir, false)

	st.Close() // wrong order, on purpose
	w.Close()

	if dropped := w.Dropped(); dropped == 0 {
		t.Fatal("expected the final batch to be dropped when the store closes first")
	}
	reopened := openReadyStore(t, dir)
	defer reopened.Close()
	if got := countRows(t, reopened, `SELECT COUNT(*) FROM req`); got == int64(len(recs)) {
		t.Errorf("all %d rows survived; the ordering hazard may no longer exist", got)
	}
}

// With the archive on the same mistake costs nothing, because the file is the
// authoritative copy and the next start scans it back in. This is what the
// original "close the index first" reasoning was based on — true, but only in
// that mode.
func TestArchiveOnSurvivesEitherOrder(t *testing.T) {
	withShanghaiBuckets(t)
	dir := t.TempDir()
	st := openReadyStore(t, dir)
	w, recs := bufferedWriter(t, dir, true)

	st.Close()
	w.Close()

	files, err := filepath.Glob(filepath.Join(dir, "requests-*.jsonl"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("archive on but no jsonl file was written")
	}
	reopened := openReadyStore(t, dir)
	defer reopened.Close()
	if got, want := countRows(t, reopened, `SELECT COUNT(*) FROM req`), int64(len(recs)); got != want {
		t.Errorf("rows recovered from the archive = %d, want %d", got, want)
	}
}

func TestShutdownHandlesNil(t *testing.T) {
	Shutdown(nil, nil)
	dir := t.TempDir()
	st := openReadyStore(t, dir)
	Shutdown(nil, st)
}
