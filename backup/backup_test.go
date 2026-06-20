package backup

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestArchiveCryptRoundTrip is the core DR guarantee: files → tar.gz → seal
// → open → untar must reproduce the exact bytes, and only the matching
// private key can open the sealed archive.
func TestArchiveCryptRoundTrip(t *testing.T) {
	src := t.TempDir()
	files := map[string][]byte{
		"tokens.json":     []byte(`{"tokens":[{"token":"sk-abc"}]}`),
		"auths/acc1.json": []byte(`{"refresh_token":"rt-1"}`),
		"saas.db":         bytes.Repeat([]byte{0x7f, 0x00, 0x42}, 1000),
	}
	var entries []FileEntry
	for name, data := range files {
		p := filepath.Join(src, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		entries = append(entries, FileEntry{Name: name, SourcePath: p, Mode: 0o600})
	}

	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	var tgz bytes.Buffer
	if err := writeTarGz(&tgz, entries); err != nil {
		t.Fatalf("writeTarGz: %v", err)
	}
	sealed, err := sealTo(tgz.Bytes(), pub)
	if err != nil {
		t.Fatalf("sealTo: %v", err)
	}
	if bytes.Contains(sealed, []byte("refresh_token")) {
		t.Fatal("sealed blob leaks plaintext")
	}

	// Wrong key must fail.
	_, wrongPriv, _ := GenerateKeypair()
	if _, err := openFrom(sealed, wrongPriv); err == nil {
		t.Fatal("openFrom succeeded with wrong key")
	}

	plain, err := openFrom(sealed, priv)
	if err != nil {
		t.Fatalf("openFrom: %v", err)
	}
	dst := t.TempDir()
	if err := extractTarGz(bytes.NewReader(plain), dst); err != nil {
		t.Fatalf("extractTarGz: %v", err)
	}
	for name, want := range files {
		got, err := os.ReadFile(filepath.Join(dst, filepath.FromSlash(name)))
		if err != nil {
			t.Fatalf("read restored %s: %v", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("restored %s mismatch", name)
		}
	}
}

func TestSafeJoinRejectsTraversal(t *testing.T) {
	base := t.TempDir()
	for _, bad := range []string{"../escape", "/etc/passwd", "a/../../b", ".."} {
		if _, err := safeJoin(base, bad); err == nil {
			t.Errorf("safeJoin allowed traversal: %q", bad)
		}
	}
	if _, err := safeJoin(base, "auths/acc1.json"); err != nil {
		t.Errorf("safeJoin rejected valid name: %v", err)
	}
}

func TestParseKeyDateAndPrefix(t *testing.T) {
	d, ok := parseKeyDate("hypitoken/2026-06-20.tar.gz.enc")
	if !ok || d.Format(dateLayout) != "2026-06-20" {
		t.Fatalf("parseKeyDate: got %v %v", d, ok)
	}
	if _, ok := parseKeyDate("hypitoken/notadate.tar.gz.enc"); ok {
		t.Fatal("parseKeyDate accepted bad stamp")
	}
	for in, want := range map[string]string{"": "", "x": "x/", "/x/": "x/", "a/b": "a/b/"} {
		if got := (S3Config{Prefix: in}).normPrefix(); got != want {
			t.Errorf("normPrefix(%q)=%q want %q", in, got, want)
		}
	}
}

func TestSnapshotSQLite(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "src.db")
	sdb, err := sql.Open("sqlite", "file:"+srcPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sdb.Exec(`CREATE TABLE wallets(token TEXT, balance_usd REAL); INSERT INTO wallets VALUES('sk-x', 12.5)`); err != nil {
		t.Fatal(err)
	}
	sdb.Close()

	dstPath := filepath.Join(dir, "snap.db")
	if err := SnapshotSQLite(context.Background(), srcPath, dstPath); err != nil {
		t.Fatalf("SnapshotSQLite: %v", err)
	}
	snap, err := sql.Open("sqlite", "file:"+dstPath+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer snap.Close()
	var bal float64
	if err := snap.QueryRow(`SELECT balance_usd FROM wallets WHERE token='sk-x'`).Scan(&bal); err != nil {
		t.Fatalf("query snapshot: %v", err)
	}
	if bal != 12.5 {
		t.Fatalf("snapshot balance = %v, want 12.5", bal)
	}
}

func TestParseKeyDateStableClock(t *testing.T) {
	// Options.now() must default to UTC and honor an injected time.
	fixed := time.Date(2026, 6, 20, 10, 0, 0, 0, time.UTC)
	if got := (Options{Now: fixed}).now(); !got.Equal(fixed) {
		t.Fatalf("now() = %v, want %v", got, fixed)
	}
}
