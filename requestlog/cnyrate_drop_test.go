package requestlog

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

// Migration 5 drops a column off a table that, on a real deployment, already
// holds a million rows. DROP COLUMN rewrites the table rather than just
// editing metadata, so the thing worth testing is not that the DDL parses —
// it is that the rows come out the other side. A migration that loses the
// archive is worse than the column it removes.
func TestDroppingTheRateKeepsEveryRow(t *testing.T) {
	withShanghaiBuckets(t)
	dir := t.TempDir()
	writeLog(t, dir, sampleRecords(time.Now()))

	st := openReadyStore(t, dir)
	before, err := st.storeQuery(Filter{Dir: dir, Limit: 1})
	if err != nil {
		t.Fatalf("query before: %v", err)
	}
	want := before.Summary.Count
	if want == 0 {
		t.Fatal("seed produced no rows; the test would pass vacuously")
	}
	st.Close()

	// Rewind the database to the state migration 5 has to upgrade: the column
	// present, populated, and the version stamped at 4.
	dbPath := filepath.Join(dir, IndexFileName)
	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	for _, stmt := range []string{
		`ALTER TABLE req ADD COLUMN cny_rate REAL NOT NULL DEFAULT 0`,
		`UPDATE req SET cny_rate = 7.1842`,
		`PRAGMA user_version = 4`,
	} {
		if _, err := raw.Exec(stmt); err != nil {
			t.Fatalf("rewind %q: %v", stmt, err)
		}
	}
	raw.Close()

	st2 := openReadyStore(t, dir)
	after, err := st2.storeQuery(Filter{Dir: dir, Limit: 1})
	if err != nil {
		t.Fatalf("query after: %v", err)
	}
	if after.Summary.Count != want {
		t.Errorf("row count = %d after the drop, want %d — the migration lost rows",
			after.Summary.Count, want)
	}

	var version int
	if err := st2.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatalf("read version: %v", err)
	}
	if version != len(storeMigrations) {
		t.Errorf("user_version = %d, want %d", version, len(storeMigrations))
	}

	rows, err := st2.db.Query(`PRAGMA table_info(req)`)
	if err != nil {
		t.Fatalf("table_info: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, typ string
		var notnull int
		var dflt sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			t.Fatalf("scan table_info: %v", err)
		}
		if name == "cny_rate" {
			t.Error("cny_rate survived migration 5")
		}
	}
}
