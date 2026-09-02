package auth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The measurement must outlive the process: MarkUsageLimitReached writes it
// to the credential file, parseFile reads it back, and files written before
// the field existed load as "never hit".
func TestLastQuotaHitPersistsAcrossReload(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct{ name, seed string }{
		{"anthropic-oauth", `{"type":"claude","access_token":"sk-ant-oat01-x","refresh_token":"sk-ant-ort01-x"}`},
		{"codex-oauth", `{"type":"codex","access_token":"eyJ.x.y","refresh_token":"rt","chatgpt_account_id":"acct"}`},
		{"apikey", `{"type":"apikey","api_key":"sk-ant-api03-x"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name+".json")
			if err := os.WriteFile(path, []byte(tc.seed), 0600); err != nil {
				t.Fatal(err)
			}
			a, err := parseFile(path, []byte(tc.seed))
			if err != nil {
				t.Fatalf("parseFile: %v", err)
			}
			if !a.LastQuotaHit.At.IsZero() {
				t.Fatal("a file without the field must load as never hit")
			}

			resetAt := time.Now().Add(106 * time.Hour).Truncate(time.Second)
			a.MarkUsageLimitReached(resetAt)
			// The write is asynchronous; wait for it.
			deadline := time.Now().Add(3 * time.Second)
			var raw map[string]any
			for time.Now().Before(deadline) {
				data, _ := os.ReadFile(path)
				raw = nil
				if json.Unmarshal(data, &raw) == nil {
					if _, ok := raw["last_quota_hit"]; ok {
						break
					}
				}
				time.Sleep(20 * time.Millisecond)
			}
			if _, ok := raw["last_quota_hit"]; !ok {
				t.Fatalf("last_quota_hit not persisted: %v", raw)
			}
			if _, ok := raw["access_token"]; tc.name != "apikey" && !ok {
				t.Fatal("persisting the hit must not drop the token")
			}

			data, _ := os.ReadFile(path)
			b, err := parseFile(path, data)
			if err != nil {
				t.Fatalf("re-parse: %v", err)
			}
			if !b.LastQuotaHit.ResetAt.Equal(resetAt) || b.LastQuotaHit.At.IsZero() {
				t.Fatalf("reloaded hit = %+v, want reset %v", b.LastQuotaHit, resetAt)
			}
			if b.IsQuotaExceeded(time.Now()) {
				t.Fatal("the persisted hit is a measurement, not a cooldown: a reloaded credential must not be parked")
			}
		})
	}
}

func TestParseQuotaHitToleratesGarbage(t *testing.T) {
	for _, raw := range []map[string]any{
		{},
		{"last_quota_hit": "nope"},
		{"last_quota_hit": map[string]any{"at": "2026-09-02T00:00:00Z"}},
		{"last_quota_hit": map[string]any{"at": "garbage", "reset_at": "2026-09-02T00:00:00Z"}},
	} {
		if h := parseQuotaHit(raw); !h.At.IsZero() {
			t.Fatalf("%v → %+v", raw, h)
		}
	}
}

// A hit present in the file but not in memory (backfilled by hand, or the
// process restarted and never re-read it) must survive saveAuth: the file is
// the record, memory is only the latest observation.
func TestSaveAuthKeepsFileHitWhenMemoryHasNone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.json")
	seed := `{"type":"claude","access_token":"sk-ant-oat01-x","refresh_token":"sk-ant-ort01-x","last_quota_hit":{"at":"2026-09-02T07:37:00Z","reset_at":"2026-09-07T02:30:11Z"}}`
	if err := os.WriteFile(path, []byte(seed), 0600); err != nil {
		t.Fatal(err)
	}
	a, err := parseFile(path, []byte(seed))
	if err != nil {
		t.Fatal(err)
	}
	a.LastQuotaHit = QuotaHit{} // simulate a process that never saw it
	a.SetDisabled(true)
	if err := saveAuth(a); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	b, err := parseFile(path, data)
	if err != nil {
		t.Fatal(err)
	}
	if b.LastQuotaHit.At.IsZero() || !b.Disabled {
		t.Fatalf("saveAuth erased the file's record: %+v disabled=%v", b.LastQuotaHit, b.Disabled)
	}
}
