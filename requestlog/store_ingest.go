package requestlog

// Incremental ingest of the JSONL archive into the SQLite index.
//
// The archive is append-only in the common case, so the steady state is a
// tail read of one file. The three ways it can still change out from under
// us are all detected and repaired:
//
//   - append      — today's file grew; read from the recorded offset
//   - truncate    — file shorter than what we consumed; re-ingest the day
//   - rewrite     — RewriteClientMask replaces a rotated file in place via
//                   temp-file + rename. Token masks are equal length, so the
//                   size is typically unchanged and only mtime moves. Rotated
//                   files never legitimately change, so for them *any* drift
//                   in (size, mtime) triggers a re-ingest of that day.
//
// A day is the unit of repair because it is the unit of storage: one file,
// one req.day value, one set of agg_cube rows.

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	log "github.com/sirupsen/logrus"
)

// catchUp brings the index in line with the directory. When initial is true
// the work is paced (see backfillPause) because it may cover the entire
// archive while the proxy is serving traffic.
func (s *Store) catchUp(initial bool) error {
	s.ingestMu.Lock()
	defer s.ingestMu.Unlock()

	files, err := listLogFiles(s.dir)
	if err != nil {
		return err
	}
	// Oldest first: a backfill that dies halfway leaves a contiguous prefix
	// of history rather than holes, and the recent days people actually look
	// at are the last to land — which is also when ready flips.
	sort.Strings(files)

	state, err := s.ingestState()
	if err != nil {
		return err
	}

	// Anything still on disk is not a candidate for retention cleanup.
	live := make(map[string]struct{}, len(files))
	touched := make(map[string]struct{})
	todayUTC := time.Now().UTC().Format("2006-01-02")

	for _, path := range files {
		name := filepath.Base(path)
		day := extractDay(path)
		live[name] = struct{}{}

		fi, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		size, mtime := fi.Size(), fi.ModTime().UnixNano()

		prev, seen := state[name]
		from := int64(0)
		switch {
		case !seen:
			// New file.
		case size < prev.offset:
			// Truncated: everything we recorded for this day is suspect.
			if err := s.dropDay(day, name); err != nil {
				return err
			}
		case day < todayUTC && (size != prev.size || mtime != prev.mtimeNS):
			// A rotated file changed. It cannot have been appended to, so
			// this is a rewrite — rebuild the day rather than trusting the
			// offset.
			if err := s.dropDay(day, name); err != nil {
				return err
			}
		case size > prev.offset:
			from = prev.offset
		default:
			// Unchanged.
			continue
		}

		n, end, err := s.ingestFile(path, day, from, initial)
		if err != nil {
			return err
		}
		if err := s.recordIngest(name, size, mtime, end, n, from == 0); err != nil {
			return err
		}
		if n > 0 || from == 0 {
			touched[day] = struct{}{}
		}
	}

	// Files the retention GC deleted: drop their rows so lifetime totals track
	// what the operator can actually still inspect.
	//
	// Gated on the archive actually being authoritative. With Options{
	// JSONLArchive: false} the ledger still names every file the writer wrote
	// before the switch, and those rows now live ONLY in this database —
	// deleting the stale files is housekeeping, not a retention event, but
	// this loop read it as one and took 999k rows of production history with
	// it (2026-08-09). dropDay is `DELETE FROM req WHERE day = ?`, so it does
	// not even spare the rows the writer inserted directly.
	if s.archiveAuthoritative() {
		for name, rec := range state {
			if _, ok := live[name]; ok {
				continue
			}
			if err := s.dropDay(rec.day, name); err != nil {
				return err
			}
		}
	} else if len(state) > len(live) {
		// Say so once per pass rather than silently diverging: the ledger is
		// describing files that no longer drive anything.
		log.Debugf("requestlog: %d stale ingest entrie(s) with no file; archive is not authoritative, keeping their rows",
			len(state)-len(live))
	}

	// Days the writer inserted into directly since the last pass. With the
	// JSONL archive on these are already in `touched` (the file grew too),
	// but with it off the scanner sees nothing and this is the only signal
	// that the cube is stale.
	for day := range s.takeDirtyDays() {
		touched[day] = struct{}{}
	}
	for day := range touched {
		if err := s.rebuildCube(day); err != nil {
			return err
		}
	}
	s.lastCatchUp.Store(time.Now().UnixNano())
	return nil
}

type ingestRec struct {
	day      string
	size     int64
	mtimeNS  int64
	offset   int64
	rowCount int64
}

func (s *Store) ingestState() (map[string]ingestRec, error) {
	rows, err := s.db.Query(`SELECT file, size, mtime_ns, offset, rows FROM ingest`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]ingestRec)
	for rows.Next() {
		var name string
		var r ingestRec
		if err := rows.Scan(&name, &r.size, &r.mtimeNS, &r.offset, &r.rowCount); err != nil {
			return nil, err
		}
		r.day = extractDay(name)
		out[name] = r
	}
	return out, rows.Err()
}

func (s *Store) dropDay(day, file string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`DELETE FROM req WHERE day = ?`, day); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM agg_cube WHERE day = ?`, day); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM ingest WHERE file = ?`, file); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) recordIngest(file string, size, mtimeNS, offset, added int64, reset bool) error {
	if reset {
		_, err := s.db.Exec(`INSERT INTO ingest (file, size, mtime_ns, offset, rows)
			VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(file) DO UPDATE SET
				size = excluded.size, mtime_ns = excluded.mtime_ns,
				offset = excluded.offset, rows = excluded.rows`,
			file, size, mtimeNS, offset, added)
		return err
	}
	_, err := s.db.Exec(`UPDATE ingest
		SET size = ?, mtime_ns = ?, offset = ?, rows = rows + ?
		WHERE file = ?`, size, mtimeNS, offset, added, file)
	return err
}

// insertReq is OR IGNORE against idx_req_src: the same JSONL line can be
// offered twice, once by the writer as it appends and once by the scanner as
// it re-reads the file, and exactly one of them must land.
const insertReq = `INSERT OR IGNORE INTO req (
	ts, day, bday, client, client_token, provider, auth_id, auth_label, auth_kind,
	model, input, output, cache_read, cache_create, cache_create_1h,
	cost_usd, billed_usd, multiplier, status, duration_ms, stream,
	path, attempts, error, attempt_only, user_id, audit, src_file, src_off
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

// ingestFile folds the records in path[from:] into req and returns how many
// rows were added and the byte offset just past the last complete line.
//
// A partial trailing line (the writer is mid-append) is deliberately left
// unconsumed: the offset stays before it so the next pass re-reads it whole.
func (s *Store) ingestFile(path, day string, from int64, paced bool) (int64, int64, error) {
	fh, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, from, nil
		}
		return 0, from, err
	}
	defer fh.Close()
	if from > 0 {
		if _, err := fh.Seek(from, io.SeekStart); err != nil {
			return 0, from, err
		}
	}

	name := filepath.Base(path)
	br := bufio.NewReaderSize(fh, 256*1024)
	offset := from
	var added int64

	tx, stmt, err := s.beginInsert()
	if err != nil {
		return 0, from, err
	}
	// Ensure a failure path never leaks the transaction.
	defer func() {
		if tx != nil {
			_ = stmt.Close()
			_ = tx.Rollback()
		}
	}()

	batch := 0
	for {
		line, err := br.ReadBytes('\n')
		if err != nil {
			// EOF with no newline means a partial line; drop it and stop.
			if errors.Is(err, io.EOF) {
				break
			}
			return added, offset, err
		}
		lineStart := offset
		offset += int64(len(line))

		var r Record
		// Malformed lines are skipped by the scanning path too; the offset
		// still advances so we never re-read them.
		if err := json.Unmarshal(line, &r); err != nil {
			continue
		}
		if err := insertRecord(stmt, day, r, name, lineStart); err != nil {
			return added, offset, err
		}
		// Counts lines folded in, not rows inserted. Under dual write most of
		// these are already present (the writer got there first) and insert as
		// no-ops, but the line is accounted for either way — which is what
		// keeps sum(ingest.rows) comparable to the file's line count, the
		// cheapest health check there is on this index.
		added++
		batch++

		if batch >= backfillBatch {
			if err := commitInsert(tx, stmt); err != nil {
				tx = nil
				return added, offset, err
			}
			// Checkpoint the offset with the batch so a crash resumes here
			// instead of replaying the whole file.
			if err := s.recordIngest(filepath.Base(path), offset, 0, offset, 0, false); err != nil {
				tx = nil
				return added, offset, err
			}
			if paced {
				time.Sleep(backfillPause)
			}
			batch = 0
			if tx, stmt, err = s.beginInsert(); err != nil {
				tx = nil
				return added, offset, err
			}
		}
	}

	if err := commitInsert(tx, stmt); err != nil {
		tx = nil
		return added, offset, err
	}
	tx = nil
	return added, offset, nil
}

func (s *Store) beginInsert() (*sql.Tx, *sql.Stmt, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, nil, err
	}
	stmt, err := tx.Prepare(insertReq)
	if err != nil {
		_ = tx.Rollback()
		return nil, nil, err
	}
	return tx, stmt, nil
}

func commitInsert(tx *sql.Tx, stmt *sql.Stmt) error {
	if err := stmt.Close(); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// insertRecord adds one row, or does nothing if idx_req_src shows the same
// JSONL line was already offered by the other producer.
func insertRecord(stmt *sql.Stmt, day string, r Record, srcFile string, srcOff int64) error {
	var audit any
	if r.ClaudeAudit != nil {
		b, err := json.Marshal(r.ClaudeAudit)
		if err == nil {
			audit = string(b)
		}
	}
	_, err := stmt.Exec(
		r.TS.UnixNano(),
		day,
		r.TS.In(bucketLoc).Format("2006-01-02"),
		r.Client, r.ClientToken, r.Provider,
		r.AuthID, r.AuthLabel, r.AuthKind,
		r.Model,
		r.Input, r.Output, r.CacheRead, r.CacheCreate, r.CacheCreate1h,
		r.CostUSD, r.BilledUSD, r.Multiplier,
		r.Status, r.DurationMs, boolToInt(r.Stream),
		r.Path, r.Attempts, r.Error, boolToInt(r.AttemptOnly),
		r.UserID, audit, srcFile, srcOff,
	)
	return err
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// aggSelect is the counter list shared by every rollup, kept in one place so
// the rollups and the live GROUP BY path in store_query.go can never drift.
//
// billed_usd mirrors Record.BilledOrCost: rows predating the CostUSD /
// BilledUSD split carry the charged amount in cost_usd and nothing in
// billed_usd, so falling back per row is what makes a spend total correct
// across both log generations.
const aggSelect = `COUNT(*), COALESCE(SUM(input),0), COALESCE(SUM(output),0),
	COALESCE(SUM(cache_read),0), COALESCE(SUM(cache_create),0), COALESCE(SUM(cache_create_1h),0),
	COALESCE(SUM(cost_usd),0),
	COALESCE(SUM(CASE WHEN billed_usd != 0 THEN billed_usd ELSE cost_usd END),0),
	COALESCE(SUM(CASE WHEN status >= 400 OR error != '' THEN 1 ELSE 0 END),0),
	COALESCE(SUM(duration_ms),0)`

const aggCols = `count, input, output, cache_read, cache_create, cache_create_1h,
	cost_usd, billed_usd, errors, duration_ms`

// cubeDims is the cube's key, in PRIMARY KEY order. Listed once so the insert,
// its GROUP BY, and the query-side re-aggregation can never disagree.
const cubeDims = `day, bday, model, client, client_token, provider, auth_id, status, user_id`

// rebuildCube recomputes the cube rows for one day. Past days are only ever
// touched once (at ingest); the current day is recomputed whenever new records
// land, which is a grouped scan of that day's slice — 26k rows on the busiest
// production day, collapsing to ~199 cube rows.
//
// attempt_only rows are excluded here because every consumer excludes them
// (see matches, AggregateByAuth, AggregateHourly) — retry telemetry must not
// inflate user-visible counts.
func (s *Store) rebuildCube(day string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(`DELETE FROM agg_cube WHERE day = ?`, day); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO agg_cube (`+cubeDims+`, `+aggCols+`)
		SELECT `+cubeDims+`, `+aggSelect+`
		FROM req WHERE day = ? AND attempt_only = 0
		GROUP BY `+cubeDims, day); err != nil {
		return err
	}
	return tx.Commit()
}

// ensureCube populates the cube for days that have rows in req but none in the
// cube. It runs at open, which is what carries an index built by an older
// binary across the migration that introduced the cube: the JSONL is already
// folded into req, so this rebuilds from there in seconds rather than
// re-parsing the archive.
func (s *Store) ensureCube() error {
	rows, err := s.db.Query(`SELECT DISTINCT day FROM req
		WHERE day NOT IN (SELECT DISTINCT day FROM agg_cube)`)
	if err != nil {
		return err
	}
	var days []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			rows.Close()
			return err
		}
		days = append(days, d)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if len(days) == 0 {
		return nil
	}
	log.Infof("requestlog: building aggregate cube for %d day(s)", len(days))
	for _, d := range days {
		if err := s.rebuildCube(d); err != nil {
			return err
		}
	}
	return nil
}
