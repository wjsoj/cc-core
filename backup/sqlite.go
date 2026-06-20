package backup

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"

	// Registers the "sqlite" driver (pure-Go, same as the apps use).
	_ "modernc.org/sqlite"
)

// SnapshotSQLite writes a consistent, self-contained copy of the SQLite
// database at src to dst using `VACUUM INTO`. Unlike a raw file copy this is
// transactional: the live server can keep reading/writing while we capture a
// single point-in-time snapshot with no -wal/-shm siblings to ship.
//
// dst is force-chmodded to 0600 (VACUUM INTO honors the umask, which we then
// tighten). Mirrors hypitoken's internal/saas/db.(*DB).SnapshotTo so both
// apps share one implementation.
func SnapshotSQLite(ctx context.Context, src, dst string) error {
	if src == "" || dst == "" {
		return fmt.Errorf("snapshot: empty src/dst")
	}
	// VACUUM INTO refuses to overwrite — drop any stale file from a crashed run.
	_ = os.Remove(dst)

	// Open read-only with a busy timeout so a momentary writer lock doesn't
	// fail the snapshot. VACUUM INTO only needs read access to the source.
	dsn := fmt.Sprintf("file:%s?mode=ro&_pragma=busy_timeout(10000)", src)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	q := fmt.Sprintf(`VACUUM INTO '%s'`, strings.ReplaceAll(dst, "'", "''"))
	if _, err := db.ExecContext(ctx, q); err != nil {
		return fmt.Errorf("vacuum into %s: %w", dst, err)
	}
	_ = os.Chmod(dst, 0o600)
	return nil
}
