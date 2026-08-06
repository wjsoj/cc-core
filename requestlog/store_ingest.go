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
// one req.day value, one set of agg_day rows.

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

	// Files the retention GC deleted: drop their rows so lifetime totals
	// track what the operator can actually still inspect.
	for name, rec := range state {
		if _, ok := live[name]; ok {
			continue
		}
		if err := s.dropDay(rec.day, name); err != nil {
			return err
		}
	}

	for day := range touched {
		if err := s.rebuildRollup(day); err != nil {
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
	if _, err := tx.Exec(`DELETE FROM agg_day WHERE day = ?`, day); err != nil {
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

const insertReq = `INSERT INTO req (
	ts, day, bday, client, client_token, provider, auth_id, auth_label, auth_kind,
	model, input, output, cache_read, cache_create, cache_create_1h,
	cost_usd, billed_usd, multiplier, status, duration_ms, stream,
	path, attempts, error, attempt_only, user_id, audit
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

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
		offset += int64(len(line))

		var r Record
		// Malformed lines are skipped by the scanning path too; the offset
		// still advances so we never re-read them.
		if err := json.Unmarshal(line, &r); err != nil {
			continue
		}
		if err := insertRecord(stmt, day, r); err != nil {
			return added, offset, err
		}
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

func insertRecord(stmt *sql.Stmt, day string, r Record) error {
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
		r.UserID, audit,
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

// rebuildRollup recomputes every rollup row for one day. Past days are only
// ever touched once (at ingest); the current day is recomputed on each
// catch-up, which is a grouped scan of that day's index slice.
//
// attempt_only rows are excluded here because every consumer excludes them
// (see matches, AggregateByAuth, AggregateHourly) — retry telemetry must not
// inflate user-visible counts.
func (s *Store) rebuildRollup(day string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(`DELETE FROM agg_day WHERE day = ?`, day); err != nil {
		return err
	}

	// dim expression per kind. 'client' mirrors the scanning path's key
	// choice: the masked token when present, else the friendly name.
	kinds := []struct{ kind, dim, extra string }{
		{"total", `''`, ``},
		{"auth", `auth_id`, ` AND auth_id != ''`},
		{"model", `model`, ``},
		{"client", `CASE WHEN client_token != '' THEN client_token ELSE client END`, ``},
		{"day", `bday`, ``},
	}
	for _, k := range kinds {
		q := `INSERT INTO agg_day (day, kind, dim, ` + aggCols + `)
			SELECT ?, ?, ` + k.dim + `, ` + aggSelect + `
			FROM req WHERE day = ? AND attempt_only = 0` + k.extra + `
			GROUP BY ` + k.dim + ` HAVING COUNT(*) > 0`
		if _, err := tx.Exec(q, day, k.kind, day); err != nil {
			return err
		}
	}
	return tx.Commit()
}
