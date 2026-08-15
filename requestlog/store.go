package requestlog

// SQLite index over the JSONL archive.
//
// # Why
//
// Every aggregate the admin panel renders used to mean re-parsing the whole
// log directory: at ~1M records the full-archive pass costs ~20s of pure
// json.Unmarshal (disk is irrelevant — the files are in page cache). The
// panel polls on a timer, so operators saw 15-30s loads while the scans
// competed with real proxy traffic for the box's two cores.
//
// This file adds a SQLite index over the same records. Query,
// AggregateByAuth and AggregateHourly consult it when one is open for their
// directory and fall back to the original scan when it is absent or still
// backfilling — so a broken/missing index degrades to the old behaviour
// instead of to an error.
//
// # Ownership
//
// By default the index is derived state: the writer appends JSONL, and it can
// be deleted at any time and will rebuild itself from those files on the next
// open. That is what licenses synchronous=NORMAL below. The writer also
// inserts each batch directly (store_write.go) so the index is current within
// a batch rather than a scan interval, but while the archive exists that is an
// optimisation — anything an insert loses is re-read from the file.
//
// Options.JSONLArchive = false removes the archive and with it that safety
// net, making this database the only copy. Nothing here changes shape in that
// mode; what changes is the consequence of a failed write, which is why the
// switch is off by default and documented where it is set rather than here.
//
// # Lookup by directory
//
// Callers reach the query helpers with only a directory path (Filter.Dir, or
// the dir argument), and there are ~20 such call sites across the two forks.
// Rather than thread a handle through all of them, OpenStore registers itself
// in a package-level table keyed by cleaned directory path and the helpers
// look themselves up. The invariant that makes this safe: at most one Store
// per directory, opened once at startup and closed at shutdown.

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
	_ "modernc.org/sqlite"
)

// IndexFileName is the SQLite database created inside the log directory.
// listLogFiles only matches requests-*.jsonl, so the index (and its -wal /
// -shm siblings) is invisible to the scanning path.
const IndexFileName = "requests.db"

// catchUpInterval is how often the background loop folds newly appended
// records into the index. The admin panel polls every 10s, so anything
// meaningfully below that is wasted work.
const catchUpInterval = 5 * time.Second

// catchUpMinGap throttles the on-demand catch-up that queries trigger, so a
// burst of concurrent panel requests costs at most one tail scan.
const catchUpMinGap = time.Second

// backfillBatch is how many records are inserted per transaction during the
// initial backfill, and backfillPause is the gap between batches. Together
// they cap the backfill at roughly half a core: the first run over a ~1M
// record archive must not starve the proxy it shares the box with.
const backfillBatch = 5000
const backfillPause = 15 * time.Millisecond

// Store is a SQLite index over one log directory.
type Store struct {
	db   *sql.DB
	dir  string
	path string

	// ingestMu serializes the scanners. SQLite would serialize the writes
	// anyway; holding it across a whole catch-up also keeps two callers from
	// both deciding a file needs re-ingesting.
	ingestMu sync.Mutex

	// ready flips once the first full pass over the directory has completed.
	// Until then the query helpers use the JSONL path, so a cold index costs
	// nothing but also gains nothing.
	ready atomic.Bool

	// lastCatchUp is the unix-nano time of the last completed catch-up,
	// consulted by the throttle in maybeCatchUp.
	lastCatchUp atomic.Int64

	// archiveMode records whether a JSONL archive is authoritative for this
	// directory: archiveUnknown until a Writer opens and declares it.
	//
	// It gates exactly one thing — the missing-file purge in catchUp — and it
	// defaults to "unknown" because that purge is destructive and must require
	// positive evidence. See archiveAuthoritative.
	archiveMode atomic.Int32

	// dirtyDays are days the writer inserted into directly, awaiting a cube
	// rebuild. Separate from ingestMu because it is touched on the write path.
	dirtyMu   sync.Mutex
	dirtyDays map[string]struct{}

	stopCh chan struct{}
	doneCh chan struct{}
}

var (
	storesMu sync.RWMutex
	stores   = map[string]*Store{}
)

func storeKey(dir string) string {
	if abs, err := filepath.Abs(dir); err == nil {
		return filepath.Clean(abs)
	}
	return filepath.Clean(dir)
}

// lookupStore returns the Store registered for dir, or nil.
func lookupStore(dir string) *Store {
	if dir == "" {
		return nil
	}
	storesMu.RLock()
	st := stores[storeKey(dir)]
	storesMu.RUnlock()
	return st
}

// indexFor returns the Store to serve dir from, or nil when the caller should
// fall back to scanning JSONL.
func indexFor(dir string) *Store {
	st := lookupStore(dir)
	if st == nil || !st.ready.Load() {
		return nil
	}
	return st
}

// OpenStore opens (creating if needed) the index for a log directory and
// starts the background ingest loop. It returns an error only for conditions
// the caller could act on (bad path, unusable SQLite); callers are expected
// to log and continue, since every query path falls back to scanning.
//
// Opening a second Store for the same directory replaces the registration and
// closes the previous one, so repeated calls are safe.
func OpenStore(dir string) (*Store, error) {
	if dir == "" {
		return nil, fmt.Errorf("requestlog: empty dir")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, IndexFileName)

	// synchronous=NORMAL, unlike the wallet DB's FULL: this is derived
	// telemetry. A power cut that loses the last commit costs a re-scan of
	// one day's tail on the next open, not money.
	dsn := "file:" + path + "?_txlock=immediate" +
		"&_pragma=busy_timeout(10000)" +
		"&_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(NORMAL)" +
		"&_pragma=cache_size(-32768)" +
		"&_pragma=auto_vacuum(INCREMENTAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// One writer plus a few readers. WAL allows concurrent readers; the
	// ingest path is single-threaded by ingestMu regardless.
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(2)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, err
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		_ = os.Chmod(path+suffix, 0o600)
	}

	st := &Store{
		db:     db,
		dir:    dir,
		path:   path,
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}
	if err := st.migrate(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	// Day buckets are labelled in the configured display zone, and that
	// label is materialized into req.bday at ingest time. If the operator
	// changed display_timezone since the last run every stored label is
	// wrong, so drop the derived rows and rebuild.
	if err := st.reconcileBucketLocation(); err != nil {
		_ = db.Close()
		return nil, err
	}

	storesMu.Lock()
	prev := stores[storeKey(dir)]
	stores[storeKey(dir)] = st
	storesMu.Unlock()
	if prev != nil {
		prev.Close()
	}

	go st.loop()
	return st, nil
}

// Close stops the background loop and closes the database. Safe to call more
// than once.
func (s *Store) Close() {
	if s == nil {
		return
	}
	select {
	case <-s.stopCh:
	default:
		close(s.stopCh)
		<-s.doneCh
	}
	storesMu.Lock()
	if stores[storeKey(s.dir)] == s {
		delete(stores, storeKey(s.dir))
	}
	storesMu.Unlock()
	_ = s.db.Close()
}

// Ready reports whether the index has completed its first full pass and is
// therefore serving queries.
func (s *Store) Ready() bool { return s != nil && s.ready.Load() }

// Archive modes for Store.archiveMode.
const (
	archiveUnknown int32 = iota
	archiveOn
	archiveOff
)

// setArchiveMode is called by a Writer as it opens, to tell the index whether
// requests-*.jsonl files are the authoritative record for this directory.
func (s *Store) setArchiveMode(on bool) {
	if s == nil {
		return
	}
	if on {
		s.archiveMode.Store(archiveOn)
		return
	}
	s.archiveMode.Store(archiveOff)
}

// archiveAuthoritative reports whether a file's disappearance may be taken as
// an instruction to delete the rows it contributed.
//
// Only archiveOn qualifies. Under archiveOff the ledger still names files the
// writer has stopped maintaining — deleting them is housekeeping, not a
// retention event, and treating it as one wipes history that exists nowhere
// else. Under archiveUnknown (no writer has opened yet) we simply do not know,
// and the safe reading of "do not know" is to keep the rows: a skipped purge
// is corrected on the next pass, a wrongful one is not correctable at all.
func (s *Store) archiveAuthoritative() bool {
	return s != nil && s.archiveMode.Load() == archiveOn
}

func (s *Store) loop() {
	defer close(s.doneCh)

	// ensureCube runs first and gates everything: an index written by a binary
	// older than the cube has rows in req but no cube to serve them from, and
	// serving that would silently under-report rather than fail. It is here
	// rather than in OpenStore because it is ~7s on a 90-day production
	// archive; until ready flips, queries take the JSONL path they always did.
	// Only while the index has yet to serve anything: once ready, the cube is
	// complete and catch-up maintains it incrementally, so re-running the
	// which-days-are-missing probe on every tick would be pure overhead.
	pass := func(initial bool) error {
		if !s.ready.Load() {
			if err := s.ensureCube(); err != nil {
				return err
			}
		}
		return s.catchUp(initial)
	}

	// First pass: bring the index up to date with everything already on
	// disk, then start serving. Errors leave ready false so queries keep
	// using the JSONL path.
	if err := pass(true); err != nil {
		log.Warnf("requestlog: index backfill failed (%v); queries fall back to scanning", err)
	} else {
		s.ready.Store(true)
		log.Infof("requestlog: index ready at %s", s.path)
	}

	t := time.NewTicker(catchUpInterval)
	defer t.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-t.C:
			// Retry the whole first pass while it has never succeeded, so a
			// failed backfill recovers instead of pinning the index dark.
			if err := pass(!s.ready.Load()); err != nil {
				log.Warnf("requestlog: index catch-up: %v", err)
				continue
			}
			s.ready.Store(true)
		}
	}
}

// maybeCatchUp folds in newly appended records before serving a query, so the
// panel never renders data older than the throttle window. Concurrent callers
// collapse: whoever loses the race returns immediately and reads whatever the
// winner just committed.
func (s *Store) maybeCatchUp() {
	last := s.lastCatchUp.Load()
	now := time.Now().UnixNano()
	if now-last < int64(catchUpMinGap) {
		return
	}
	if !s.lastCatchUp.CompareAndSwap(last, now) {
		return
	}
	if err := s.catchUp(false); err != nil {
		log.Warnf("requestlog: on-demand catch-up: %v", err)
	}
}

// migrations is append-only. Each entry is a complete schema delta; never
// reorder or rewrite a previous entry — only append.
var storeMigrations = []string{
	// 1: initial schema.
	//
	// req mirrors one JSONL line. ts is unix nanoseconds — integer ordering
	// and range predicates, and enough resolution to round-trip a record's
	// timestamp exactly rather than approximately; day is the UTC day (matching
	// the source file name, which is what the day-granularity Filter bounds
	// and the ingest bookkeeping key on) while bday is the same instant
	// rendered in the display zone, which is what ByDay/hourly labels use.
	// Keeping both avoids doing timezone math in SQL, where Go's zone rules
	// (and DST) are not available.
	`
CREATE TABLE req (
    id              INTEGER PRIMARY KEY,
    ts              INTEGER NOT NULL,
    day             TEXT    NOT NULL,
    bday            TEXT    NOT NULL,
    client          TEXT    NOT NULL DEFAULT '',
    client_token    TEXT    NOT NULL DEFAULT '',
    provider        TEXT    NOT NULL DEFAULT '',
    auth_id         TEXT    NOT NULL DEFAULT '',
    auth_label      TEXT    NOT NULL DEFAULT '',
    auth_kind       TEXT    NOT NULL DEFAULT '',
    model           TEXT    NOT NULL DEFAULT '',
    input           INTEGER NOT NULL DEFAULT 0,
    output          INTEGER NOT NULL DEFAULT 0,
    cache_read      INTEGER NOT NULL DEFAULT 0,
    cache_create    INTEGER NOT NULL DEFAULT 0,
    cache_create_1h INTEGER NOT NULL DEFAULT 0,
    cost_usd        REAL    NOT NULL DEFAULT 0,
    billed_usd      REAL    NOT NULL DEFAULT 0,
    multiplier      REAL    NOT NULL DEFAULT 0,
    status          INTEGER NOT NULL DEFAULT 0,
    duration_ms     INTEGER NOT NULL DEFAULT 0,
    stream          INTEGER NOT NULL DEFAULT 0,
    path            TEXT    NOT NULL DEFAULT '',
    attempts        INTEGER NOT NULL DEFAULT 0,
    error           TEXT    NOT NULL DEFAULT '',
    attempt_only    INTEGER NOT NULL DEFAULT 0,
    user_id         INTEGER NOT NULL DEFAULT 0,
    audit           TEXT
);

CREATE INDEX idx_req_ts    ON req(ts DESC);
CREATE INDEX idx_req_day   ON req(day);
CREATE INDEX idx_req_auth  ON req(auth_id, ts DESC);
CREATE INDEX idx_req_ct    ON req(client_token, ts DESC);
CREATE INDEX idx_req_model ON req(model, ts DESC);
CREATE INDEX idx_req_user  ON req(user_id, ts DESC);

-- Daily rollups, one narrow table for every grouping the panel renders.
-- kind is 'total' | 'auth' | 'model' | 'client' | 'day'; dim is the key
-- within that grouping ('' for total, the bucket-local date for 'day').
-- Roughly 120 rows per day, so the unbounded lifetime aggregates that used
-- to scan a million records read a few thousand instead.
--
-- Rollups only ever serve *unfiltered* aggregates. Anything with a
-- predicate on it goes to req, where the indexes above make it cheap; a
-- rollup per filter combination would explode in cardinality for no gain.
CREATE TABLE agg_day (
    day             TEXT    NOT NULL,
    kind            TEXT    NOT NULL,
    dim             TEXT    NOT NULL,
    count           INTEGER NOT NULL DEFAULT 0,
    input           INTEGER NOT NULL DEFAULT 0,
    output          INTEGER NOT NULL DEFAULT 0,
    cache_read      INTEGER NOT NULL DEFAULT 0,
    cache_create    INTEGER NOT NULL DEFAULT 0,
    cache_create_1h INTEGER NOT NULL DEFAULT 0,
    cost_usd        REAL    NOT NULL DEFAULT 0,
    billed_usd      REAL    NOT NULL DEFAULT 0,
    errors          INTEGER NOT NULL DEFAULT 0,
    duration_ms     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (day, kind, dim)
) WITHOUT ROWID;

-- Per-source-file ingest bookkeeping. offset is the byte position after the
-- last complete line folded in; size/mtime_ns detect the three ways a file
-- can change under us (append, truncate, in-place rewrite).
CREATE TABLE ingest (
    file     TEXT    PRIMARY KEY,
    size     INTEGER NOT NULL DEFAULT 0,
    mtime_ns INTEGER NOT NULL DEFAULT 0,
    offset   INTEGER NOT NULL DEFAULT 0,
    rows     INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
`,
	// 2: indexes that actually cover the queries.
	//
	// The v1 indexes were keyed on the filter column plus ts alone, which
	// left two holes measured against a real 1M-row archive:
	//
	//   - the entry page orders by (ts DESC, id DESC) for stable paging, and
	//     an index on ts alone cannot satisfy a two-column sort. SQLite fell
	//     back to SCAN req + TEMP B-TREE, sorting every row to return 50 of
	//     them — 3.7s for what should be an index seek.
	//   - Model and Client are compared with COLLATE NOCASE (mirroring the
	//     scanning path's strings.EqualFold). A BINARY-collated index is
	//     unusable for a NOCASE comparison, so those filters scanned too.
	//
	// Every predicate also carries attempt_only = 0, so the indexes are
	// partial on it: smaller, and SQLite can still prove they apply.
	`
DROP INDEX IF EXISTS idx_req_ts;
DROP INDEX IF EXISTS idx_req_auth;
DROP INDEX IF EXISTS idx_req_ct;
DROP INDEX IF EXISTS idx_req_model;
DROP INDEX IF EXISTS idx_req_user;

CREATE INDEX idx_req_ts     ON req(ts DESC, id DESC)                        WHERE attempt_only = 0;
CREATE INDEX idx_req_auth   ON req(auth_id, ts DESC, id DESC)               WHERE attempt_only = 0;
CREATE INDEX idx_req_ct     ON req(client_token, ts DESC, id DESC)          WHERE attempt_only = 0;
CREATE INDEX idx_req_model  ON req(model COLLATE NOCASE, ts DESC, id DESC)  WHERE attempt_only = 0;
CREATE INDEX idx_req_client ON req(client COLLATE NOCASE, ts DESC, id DESC) WHERE attempt_only = 0;
CREATE INDEX idx_req_user   ON req(user_id, ts DESC, id DESC)               WHERE attempt_only = 0;
`,
	// 3: the aggregate cube, and the provenance columns that let the writer
	// insert rows directly without racing the file scanner.
	//
	// ## agg_cube replaces agg_day
	//
	// agg_day pre-summed one grouping at a time and therefore only ever
	// served *unfiltered* aggregates; anything with a predicate fell through
	// to req. Measured on a 984k-row production archive, one such query
	// (?model=claude-opus-4-7, 116k matching rows) cost ~2.9s, because the
	// filter indexes cover the predicate but not the eleven counter columns —
	// each matching row is a separate table lookup, done once per grouping.
	//
	// Carrying every low-cardinality dimension in one key instead collapses
	// that same archive to 10,382 rows (~199 on the busiest day): a 95x
	// reduction that still answers Summary/ByModel/ByClient/ByDay for any
	// combination of model, client, provider, auth and status by grouping the
	// cube. What stays on req is what the cube genuinely cannot express:
	// sub-day time bounds, and the entry page itself.
	//
	// errors is a stored counter rather than a predicate on status, because a
	// row can carry an error string with a 2xx status (a stream that died
	// after headers) and those must still count as errors.
	//
	// ## src_file / src_off
	//
	// The pair identifies the JSONL line a row came from, making insertion
	// idempotent: the writer inserts a record as it appends it, the scanner
	// later re-reads that same line, and the unique index turns the second
	// one into a no-op. Rows indexed before this migration have no known
	// offset, so they default to -1 and the index is partial on off >= 0 —
	// legacy rows are simply not deduplicated against, which is safe because
	// their files are fully consumed and only ever re-read after a dropDay.
	`
DROP TABLE IF EXISTS agg_day;

CREATE TABLE agg_cube (
    day             TEXT    NOT NULL,
    bday            TEXT    NOT NULL,
    model           TEXT    NOT NULL,
    client          TEXT    NOT NULL,
    client_token    TEXT    NOT NULL,
    provider        TEXT    NOT NULL,
    auth_id         TEXT    NOT NULL,
    status          INTEGER NOT NULL,
    user_id         INTEGER NOT NULL,
    count           INTEGER NOT NULL DEFAULT 0,
    input           INTEGER NOT NULL DEFAULT 0,
    output          INTEGER NOT NULL DEFAULT 0,
    cache_read      INTEGER NOT NULL DEFAULT 0,
    cache_create    INTEGER NOT NULL DEFAULT 0,
    cache_create_1h INTEGER NOT NULL DEFAULT 0,
    cost_usd        REAL    NOT NULL DEFAULT 0,
    billed_usd      REAL    NOT NULL DEFAULT 0,
    errors          INTEGER NOT NULL DEFAULT 0,
    duration_ms     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (day, bday, model, client, client_token, provider, auth_id, status, user_id)
) WITHOUT ROWID;

ALTER TABLE req ADD COLUMN src_file TEXT    NOT NULL DEFAULT '';
ALTER TABLE req ADD COLUMN src_off  INTEGER NOT NULL DEFAULT -1;

CREATE UNIQUE INDEX idx_req_src ON req(src_file, src_off) WHERE src_off >= 0;
`,

	// 4: the settle-time USD→CNY rate.
	//
	// Wallets are USD-denominated while users pay and read their spend in CNY,
	// so every yuan figure is a conversion. Doing it at display time leaves the
	// number floating — the same range exported a week apart totals differently
	// and neither figure can be recomputed once the live rate moves. Storing the
	// rate the row settled at makes its yuan amount a fact rather than a current
	// opinion, which is the difference between a spend statement and an estimate.
	//
	// Deliberately the rate and not the converted amount: rounding a per-row CNY
	// to cents makes the sum of the rows disagree with the sum of the range, and
	// the debit that actually happened was in USD anyway. Storing the input lets
	// a reader reproduce either total at full precision.
	//
	// Default 0 means "no rate known", not "free" — legacy rows and non-billing
	// deployments both land there, and Record.BilledCNY reports that as ok=false
	// rather than converting at zero. Not carried into agg_cube: a rate is a
	// per-instant snapshot, so summing or grouping it is meaningless, and the
	// spend views that need CNY read rows individually.
	`
ALTER TABLE req ADD COLUMN cny_rate REAL NOT NULL DEFAULT 0;
`,
}

func (s *Store) migrate() error {
	var version int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	for i := version; i < len(storeMigrations); i++ {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(storeMigrations[i]); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
		// PRAGMA user_version does not accept a bound parameter.
		if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, i+1)); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// reconcileBucketLocation re-labels every derived row when the display time
// zone changed since the last run. req.bday and the cube's day rollups are
// labelled in that zone, so a change silently invalidates them.
func (s *Store) reconcileBucketLocation() error {
	want := bucketLoc.String()
	var got string
	err := s.db.QueryRow(`SELECT value FROM meta WHERE key = 'bucket_loc'`).Scan(&got)
	switch {
	case err == sql.ErrNoRows:
		_, err = s.db.Exec(`INSERT INTO meta (key, value) VALUES ('bucket_loc', ?)`, want)
		return err
	case err != nil:
		return err
	case got == want:
		return nil
	}
	log.Infof("requestlog: display zone changed %s -> %s; relabelling index", got, want)
	return s.relabelBuckets(bucketLoc, want)
}

// relabelBuckets recomputes every row's display-zone day label in place and
// rebuilds the cube from the result.
//
// This replaces a DELETE of req/agg_cube/ingest that left the file scanner to
// re-read the whole archive. That was survivable only while an archive existed:
// under Options{JSONLArchive: false} there are no files to re-read, so a
// display-zone change — one line in a config — would have silently destroyed
// the entire retention window of request history, with the daily backup
// faithfully replicating the empty result.
//
// Nothing about a zone change actually invalidates a row. ts is absolute, and
// `day` is the SOURCE FILE's UTC day, which is why it is deliberately left
// alone here; only `bday` is zone-dependent. Relabelling it is therefore both
// sufficient and non-destructive, and it beats re-parsing ~1M JSONL lines even
// when the archive is present.
//
// meta is written last: a crash partway leaves the old zone recorded, so the
// next open redoes the whole pass rather than resuming into a half-labelled
// index.
func (s *Store) relabelBuckets(loc *time.Location, name string) error {
	days, err := s.distinctDays()
	if err != nil {
		return err
	}
	for _, d := range days {
		if err := s.relabelDay(d, loc); err != nil {
			return fmt.Errorf("relabel %s: %w", d, err)
		}
		// The cube is keyed on bday among other dimensions, so it has to be
		// recomputed from the rows we just relabelled, not merely re-summed.
		if err := s.rebuildCube(d); err != nil {
			return fmt.Errorf("rebuild cube %s: %w", d, err)
		}
	}
	_, err = s.db.Exec(`INSERT INTO meta (key, value) VALUES ('bucket_loc', ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, name)
	return err
}

func (s *Store) distinctDays() ([]string, error) {
	rows, err := s.db.Query(`SELECT DISTINCT day FROM req ORDER BY day`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var days []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		days = append(days, d)
	}
	return days, rows.Err()
}

// relabelDay rewrites bday for one source day's rows. It reads through
// idx_req_day, and touches only the rows whose label actually moved — a zone
// change of a few hours leaves most of a day where it was.
//
// Grouped by target label rather than updated row by row: a UTC day spans at
// most a couple of local days, so this is a handful of statements per day
// instead of tens of thousands.
func (s *Store) relabelDay(day string, loc *time.Location) error {
	rows, err := s.db.Query(`SELECT id, ts, bday FROM req WHERE day = ?`, day)
	if err != nil {
		return err
	}
	byLabel := map[string][]int64{}
	for rows.Next() {
		var id, ts int64
		var cur string
		if err := rows.Scan(&id, &ts, &cur); err != nil {
			rows.Close()
			return err
		}
		if want := time.Unix(0, ts).In(loc).Format("2006-01-02"); want != cur {
			byLabel[want] = append(byLabel[want], id)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if len(byLabel) == 0 {
		return nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for label, ids := range byLabel {
		for chunk := range chunkIDs(ids, 500) {
			q := `UPDATE req SET bday = ? WHERE id IN (` + placeholders(len(chunk)) + `)`
			args := make([]any, 0, len(chunk)+1)
			args = append(args, label)
			for _, id := range chunk {
				args = append(args, id)
			}
			if _, err := tx.Exec(q, args...); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

// chunkIDs yields ids in batches of at most n, keeping each UPDATE's variable
// count well inside SQLITE_MAX_VARIABLE_NUMBER.
func chunkIDs(ids []int64, n int) func(func([]int64) bool) {
	return func(yield func([]int64) bool) {
		for start := 0; start < len(ids); start += n {
			end := min(start+n, len(ids))
			if !yield(ids[start:end]) {
				return
			}
		}
	}
}

func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	b := make([]byte, 0, 2*n-1)
	for i := range n {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, '?')
	}
	return string(b)
}
