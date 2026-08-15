package requestlog

// Writes that originate in this process rather than from re-reading the
// archive.
//
// Until this file existed the index was purely derived: the writer appended
// JSONL and a scanner folded it in a few seconds later. That is still the
// fallback, and it is what makes every path here safe to fail — a batch that
// does not land is re-read from the file on the next catch-up.
//
// It stops being a fallback once the operator turns the JSONL archive off.
// From that point a dropped batch is a lost record, which is why appendRows
// reports its errors rather than swallowing them, and why the archive stays
// on by default.

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// pendingRow is a record together with the JSONL position it was written at.
// The position is what makes the insert idempotent against the scanner later
// re-reading the same line (see idx_req_src).
type pendingRow struct {
	rec  Record
	file string
	off  int64
}

// appendRows inserts a batch in one transaction and marks the days it touched
// so the next catch-up refreshes their cube rows.
func (s *Store) appendRows(rows []pendingRow) error {
	if s == nil || len(rows) == 0 {
		return nil
	}
	// Serialized against the scanner: both write req, and letting them
	// interleave would mean two transactions racing on the same offsets.
	s.ingestMu.Lock()
	defer s.ingestMu.Unlock()

	tx, stmt, err := s.beginInsert()
	if err != nil {
		return err
	}
	days := make(map[string]struct{}, 2)
	for _, p := range rows {
		day := p.rec.TS.UTC().Format("2006-01-02")
		if err := insertRecord(stmt, day, p.rec, p.file, p.off); err != nil {
			_ = stmt.Close()
			_ = tx.Rollback()
			return err
		}
		days[day] = struct{}{}
	}
	if err := commitInsert(tx, stmt); err != nil {
		return err
	}
	s.markDirty(days)
	return nil
}

func (s *Store) markDirty(days map[string]struct{}) {
	if len(days) == 0 {
		return
	}
	s.dirtyMu.Lock()
	if s.dirtyDays == nil {
		s.dirtyDays = make(map[string]struct{}, len(days))
	}
	for d := range days {
		s.dirtyDays[d] = struct{}{}
	}
	s.dirtyMu.Unlock()
}

// takeDirtyDays returns and clears the pending set.
func (s *Store) takeDirtyDays() map[string]struct{} {
	s.dirtyMu.Lock()
	out := s.dirtyDays
	s.dirtyDays = nil
	s.dirtyMu.Unlock()
	return out
}

// pruneBefore deletes everything older than the retention cutoff.
//
// While the archive is on, the scanner already drops a day when its file
// disappears, so this is redundant; with the archive off there is no file to
// disappear and this is the only thing enforcing retention. Running it in both
// modes keeps one code path rather than two.
//
// incremental_vacuum is what actually returns the pages: without it a pruned
// database keeps its size and merely accumulates free pages.
func (s *Store) pruneBefore(cutoffDay string) error {
	if s == nil || cutoffDay == "" {
		return nil
	}
	s.ingestMu.Lock()
	defer s.ingestMu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, q := range []string{
		`DELETE FROM req WHERE day < ?`,
		`DELETE FROM agg_cube WHERE day < ?`,
	} {
		if _, err := tx.Exec(q, cutoffDay); err != nil {
			return err
		}
	}
	// ingest keys on file name, which embeds the same day, so the cutoff
	// compares directly against it.
	if _, err := tx.Exec(`DELETE FROM ingest WHERE file < ?`,
		"requests-"+cutoffDay+".jsonl"); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	_, _ = s.db.Exec(`PRAGMA incremental_vacuum`)
	return nil
}

// rewriteClientMask repoints historical rows at a rotated token's new mask.
//
// This replaces what used to be the expensive half of an admin token reset:
// rewriting every rotated JSONL file to change one field. The files are still
// rewritten while the archive is on (they remain the source of truth for a
// rebuild), but the index no longer has to re-parse the archive to notice.
func (s *Store) rewriteClientMask(oldMask, newMask string) error {
	if s == nil {
		return nil
	}
	s.ingestMu.Lock()
	defer s.ingestMu.Unlock()

	days, err := s.daysWithToken(oldMask)
	if err != nil {
		return err
	}
	if _, err := s.db.Exec(`UPDATE req SET client_token = ? WHERE client_token = ?`,
		newMask, oldMask); err != nil {
		return err
	}
	for _, d := range days {
		if err := s.rebuildCube(d); err != nil {
			return err
		}
	}
	return s.reconcileIngestStats()
}

func (s *Store) daysWithToken(mask string) ([]string, error) {
	rows, err := s.db.Query(`SELECT DISTINCT day FROM req WHERE client_token = ?`, mask)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// reconcileIngestStats re-stats every tracked file after an in-place rewrite.
//
// The scanner treats any (size, mtime) drift on a rotated file as tampering
// and rebuilds that day from scratch — correct, but it would undo the cheap
// UPDATE above by re-parsing all 90 files. Accepting the new stats suppresses
// that, and is only sound when the rewrite preserved byte offsets. Masks are
// fixed width so it normally does; when a file's size did change, the offsets
// (and with them src_off) are meaningless, so that day is dropped and re-read
// rather than trusted.
func (s *Store) reconcileIngestStats() error {
	state, err := s.ingestState()
	if err != nil {
		return err
	}
	for name, prev := range state {
		fi, err := os.Stat(filepath.Join(s.dir, name))
		if err != nil {
			// Gone: the scanner's own missing-file branch will drop it.
			continue
		}
		if fi.Size() != prev.size {
			if err := s.dropDay(prev.day, name); err != nil {
				return err
			}
			continue
		}
		if _, err := s.db.Exec(`UPDATE ingest SET mtime_ns = ? WHERE file = ?`,
			fi.ModTime().UnixNano(), name); err != nil {
			return err
		}
	}
	return nil
}

// OpenStoreForRead opens an existing index without starting ingest, for tools
// that run alongside a live server.
//
// The read-write OpenStore would be actively wrong here: it starts a scanner
// that writes to the same database the server is already writing to, so a CLI
// export on a production box would put two ingesters on one archive. The
// inserts are idempotent so it would not corrupt anything, but the per-file row
// bookkeeping would double-count and both processes would burn CPU re-reading
// the same tail.
//
// It refuses a schema this binary does not know rather than migrating: a
// read-only handle cannot migrate, and reading a newer schema through older
// query code is how you get a silently partial answer.
func OpenStoreForRead(dir string) (*Store, error) {
	path := filepath.Join(dir, IndexFileName)
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("requestlog: no index at %s: %w", path, err)
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&_pragma=busy_timeout(10000)")
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, err
	}
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		_ = db.Close()
		return nil, err
	}
	if version != len(storeMigrations) {
		_ = db.Close()
		return nil, fmt.Errorf("requestlog: index schema is v%d, this build expects v%d",
			version, len(storeMigrations))
	}
	// Pre-closed channels: there is no loop to stop, and Close must not block
	// waiting for one to finish.
	stop, done := make(chan struct{}), make(chan struct{})
	close(stop)
	close(done)
	st := &Store{db: db, dir: dir, path: path, stopCh: stop, doneCh: done}
	st.ready.Store(true)
	return st, nil
}

// Export writes the indexed records back out as JSONL, oldest first, and
// returns how many it wrote. fromDay/toDay are inclusive 'YYYY-MM-DD' UTC
// labels; empty means unbounded.
//
// This is the escape hatch that makes turning the archive off reversible: the
// operator can always materialize the same file format again.
func (s *Store) Export(fromDay, toDay string, out io.Writer) (int, error) {
	if s == nil {
		return 0, fmt.Errorf("requestlog: nil store")
	}
	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)
	n := 0
	err := s.exportRange(fromDay, toDay, func(r Record) error {
		if err := enc.Encode(&r); err != nil {
			return err
		}
		n++
		return nil
	})
	return n, err
}

// exportRange streams stored records back out as JSONL, oldest first. It is
// what keeps the archive's guarantee available once the archive itself is off:
// the rows can always be written back to a file the operator can grep.
//
// fromDay/toDay are inclusive 'YYYY-MM-DD' UTC labels; empty means unbounded.
func (s *Store) exportRange(fromDay, toDay string, emit func(Record) error) error {
	var sb strings.Builder
	var args []any
	sb.WriteString(`SELECT ts, client, client_token, provider, auth_id, auth_label,
		auth_kind, model, input, output, cache_read, cache_create, cache_create_1h,
		cost_usd, billed_usd, multiplier, cny_rate, status, duration_ms, stream, path,
		attempts, error, user_id, audit
		FROM req WHERE 1 = 1`)
	if fromDay != "" {
		sb.WriteString(` AND day >= ?`)
		args = append(args, fromDay)
	}
	if toDay != "" {
		sb.WriteString(` AND day <= ?`)
		args = append(args, toDay)
	}
	sb.WriteString(` ORDER BY ts ASC, id ASC`)

	rows, err := s.db.Query(sb.String(), args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		r, err := scanRecord(rows)
		if err != nil {
			return err
		}
		if err := emit(r); err != nil {
			return err
		}
	}
	return rows.Err()
}
