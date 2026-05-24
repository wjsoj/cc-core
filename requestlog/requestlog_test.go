package requestlog

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWriterRoundTripAndQuery(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t0 := time.Now().UTC()
	w.Log(Record{
		TS: t0, Client: "alice", ClientToken: "sk-mask1", Provider: "anthropic",
		AuthID: "auth-1", AuthKind: "oauth", Model: "claude-opus-4-7",
		Input: 100, Output: 50, CostUSD: 0.01, Status: 200,
	})
	w.Log(Record{
		TS: t0, Client: "alice", ClientToken: "sk-mask1", Provider: "openai",
		AuthID: "auth-2", AuthKind: "apikey", Model: "gpt-5",
		Input: 200, Output: 80, CostUSD: 0.02, Status: 500, Error: "boom",
	})
	w.Close()

	// Verify file on disk has 2 lines.
	files, _ := filepath.Glob(filepath.Join(dir, "requests-*.jsonl"))
	if len(files) != 1 {
		t.Fatalf("expected 1 log file, got %d", len(files))
	}
	f, _ := os.Open(files[0])
	defer f.Close()
	cnt := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		cnt++
		var r Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatalf("decode: %v", err)
		}
	}
	if cnt != 2 {
		t.Fatalf("expected 2 records, got %d", cnt)
	}

	// Query: filter to status=500 should return 1 record.
	res, err := Query(Filter{Dir: dir, Status: 500})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if got := len(res.Entries); got != 1 {
		t.Fatalf("Query Entries=%d want 1", got)
	}
	if res.Summary.Errors != 1 {
		t.Fatalf("Summary.Errors=%d want 1", res.Summary.Errors)
	}
}

func TestQueryFilterByUserIDAndAuthID(t *testing.T) {
	dir := t.TempDir()
	w, _ := Open(dir, 0)
	w.Log(Record{TS: time.Now().UTC(), Model: "x", UserID: 100, AuthID: "auth-A", Status: 200})
	w.Log(Record{TS: time.Now().UTC(), Model: "y", UserID: 200, AuthID: "auth-B", Status: 200})
	w.Close()

	res, _ := Query(Filter{Dir: dir, UserID: 100})
	if len(res.Entries) != 1 || res.Entries[0].UserID != 100 {
		t.Fatalf("UserID filter wrong: %+v", res.Entries)
	}
	res, _ = Query(Filter{Dir: dir, AuthID: "auth-B"})
	if len(res.Entries) != 1 || res.Entries[0].AuthID != "auth-B" {
		t.Fatalf("AuthID filter wrong: %+v", res.Entries)
	}
}

func TestRewriteClientMask(t *testing.T) {
	dir := t.TempDir()
	w, _ := Open(dir, 0)
	for i := 0; i < 5; i++ {
		w.Log(Record{TS: time.Now().UTC(), ClientToken: "old-mask", Model: "m", Status: 200})
	}
	w.Log(Record{TS: time.Now().UTC(), ClientToken: "other", Model: "m", Status: 200})
	w.Close()

	n, err := w.RewriteClientMask("old-mask", "new-mask")
	if err != nil {
		t.Fatalf("Rewrite: %v", err)
	}
	if n != 5 {
		t.Fatalf("rewritten=%d want 5", n)
	}

	// Verify on-disk has new-mask, no old-mask, other unchanged.
	files, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	data, _ := os.ReadFile(files[0])
	body := string(data)
	if strings.Contains(body, "old-mask") {
		t.Fatal("old-mask still present")
	}
	if !strings.Contains(body, "new-mask") {
		t.Fatal("new-mask not written")
	}
	if !strings.Contains(body, "other") {
		t.Fatal("other client lost")
	}
}

func TestAggregateHourlyEmptyDir(t *testing.T) {
	dir := t.TempDir()
	buckets, err := AggregateHourly(dir, 6)
	if err != nil {
		t.Fatal(err)
	}
	if len(buckets) != 6 {
		t.Fatalf("expected 6 buckets, got %d", len(buckets))
	}
	for _, b := range buckets {
		if b.Count != 0 {
			t.Fatal("empty dir should produce zero counts")
		}
	}
}

func TestProviderLegacyTreatedAsAnthropic(t *testing.T) {
	dir := t.TempDir()
	w, _ := Open(dir, 0)
	w.Log(Record{TS: time.Now().UTC(), Provider: "", Model: "x", Status: 200}) // legacy
	w.Log(Record{TS: time.Now().UTC(), Provider: "openai", Model: "x", Status: 200})
	w.Close()

	res, _ := Query(Filter{Dir: dir, Provider: "anthropic"})
	if len(res.Entries) != 1 {
		t.Fatalf("legacy provider record should match 'anthropic' filter; got %d entries", len(res.Entries))
	}
}
