package usage

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func testCounts(in, out int64) Counts {
	return Counts{InputTokens: in, OutputTokens: out, Requests: 1}
}

// The core contract: first sighting bills, an identical replay does not.
func TestDeduperAdmitsOnce(t *testing.T) {
	d := NewDeduper(time.Minute, 100)
	fp := Fingerprint(testCounts(10, 20), 0.5, "auth-1")

	if ok, err := d.Admit("req-1", "auth", fp); !ok || err != nil {
		t.Fatalf("first Admit = (%v, %v), want (true, nil)", ok, err)
	}
	for i := range 3 {
		if ok, err := d.Admit("req-1", "auth", fp); ok || err != nil {
			t.Fatalf("replay %d = (%v, %v), want (false, nil)", i, ok, err)
		}
	}
	if d.Len() != 1 {
		t.Errorf("Len = %d, want 1", d.Len())
	}
}

// Reusing an id for different content is a caller bug, not a retry. Nothing
// may be billed and the caller must be able to detect it.
func TestDeduperConflictOnDifferentContent(t *testing.T) {
	d := NewDeduper(time.Minute, 100)

	if ok, _ := d.Admit("req-1", "auth", Fingerprint(testCounts(10, 20), 0.5, "auth-1")); !ok {
		t.Fatal("first Admit rejected")
	}
	ok, err := d.Admit("req-1", "auth", Fingerprint(testCounts(999, 999), 9.9, "auth-1"))
	if ok {
		t.Error("conflicting content must not be admitted")
	}
	if !errors.Is(err, ErrRequestConflict) {
		t.Errorf("err = %v, want ErrRequestConflict", err)
	}
}

// One request writes both the credential ledger and the client ledger. Scope
// keeps them from cancelling each other out.
func TestDeduperScopesAreIndependent(t *testing.T) {
	d := NewDeduper(time.Minute, 100)
	fp := Fingerprint(testCounts(10, 20), 0.5)

	if ok, _ := d.Admit("req-1", "auth", fp); !ok {
		t.Fatal("auth scope rejected")
	}
	if ok, _ := d.Admit("req-1", "client", fp); !ok {
		t.Error("client scope must be independent of auth scope")
	}
	if ok, _ := d.Admit("req-1", "auth", fp); ok {
		t.Error("auth scope replay must still be rejected")
	}
}

// No request id → nothing to deduplicate. Fail open: never lose billing.
func TestDeduperEmptyRequestIDAlwaysAdmits(t *testing.T) {
	d := NewDeduper(time.Minute, 100)
	fp := Fingerprint(testCounts(1, 1), 0)
	for i := range 3 {
		if ok, err := d.Admit("", "auth", fp); !ok || err != nil {
			t.Fatalf("call %d = (%v, %v), want (true, nil)", i, ok, err)
		}
	}
	if d.Len() != 0 {
		t.Errorf("empty ids must not be stored, Len = %d", d.Len())
	}
}

// Past the TTL the id is a new request again, and the entry is reclaimed.
func TestDeduperTTLExpiry(t *testing.T) {
	d := NewDeduper(time.Minute, 100)
	now := time.Unix(1700000000, 0)
	d.now = func() time.Time { return now }
	fp := Fingerprint(testCounts(1, 1), 0)

	if ok, _ := d.Admit("req-1", "auth", fp); !ok {
		t.Fatal("first Admit rejected")
	}
	now = now.Add(59 * time.Second)
	if ok, _ := d.Admit("req-1", "auth", fp); ok {
		t.Error("still inside TTL — must be rejected")
	}
	now = now.Add(2 * time.Second) // past TTL
	if ok, _ := d.Admit("req-1", "auth", fp); !ok {
		t.Error("past TTL — must be admitted as a new request")
	}
}

// Memory must stay bounded even if request ids never repeat.
func TestDeduperEvictsWhenOverCapacity(t *testing.T) {
	const max = 64
	d := NewDeduper(time.Hour, max)
	fp := Fingerprint(testCounts(1, 1), 0)

	for i := range max * 4 {
		if ok, err := d.Admit(fmt.Sprintf("req-%d", i), "auth", fp); !ok || err != nil {
			t.Fatalf("Admit %d = (%v, %v)", i, ok, err)
		}
	}
	if got := d.Len(); got > max {
		t.Errorf("Len = %d, want <= %d", got, max)
	}
	// The most recent id must still be claimed — eviction is oldest-first.
	if ok, _ := d.Admit(fmt.Sprintf("req-%d", max*4-1), "auth", fp); ok {
		t.Error("most recent entry was evicted; eviction must be oldest-first")
	}
}

// Concurrent retries of one request must produce exactly one admission.
func TestDeduperConcurrentAdmitExactlyOnce(t *testing.T) {
	d := NewDeduper(time.Minute, 1000)
	fp := Fingerprint(testCounts(10, 20), 0.5)

	const goroutines = 50
	var wg sync.WaitGroup
	var mu sync.Mutex
	admitted := 0

	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			if ok, err := d.Admit("req-hot", "auth", fp); ok && err == nil {
				mu.Lock()
				admitted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if admitted != 1 {
		t.Errorf("admitted %d times, want exactly 1", admitted)
	}
}

// ── Store integration ────────────────────────────────────────────────────

// The production scenario: retryRoundTripper replays on the same credential,
// or failover replays on another. The ledger must count the request once.
func TestStoreRecordOnceSurvivesRetry(t *testing.T) {
	s := OpenInMemory()
	defer s.Close()
	s.EnableDedup(NewDeduper(time.Minute, 100))

	c := testCounts(100, 200)
	if ok, err := s.RecordOnce("req-1", "auth-1", "cred", c); !ok || err != nil {
		t.Fatalf("first RecordOnce = (%v, %v)", ok, err)
	}
	if ok, err := s.RecordOnce("req-1", "auth-1", "cred", c); ok || err != nil {
		t.Fatalf("retry RecordOnce = (%v, %v), want (false, nil)", ok, err)
	}

	snap := s.Snapshot()
	got := snap["auth-1"].Daily
	var total Counts
	for _, v := range got {
		total.Add(v)
	}
	if total.InputTokens != 100 || total.Requests != 1 {
		t.Errorf("ledger double-counted: input=%d requests=%d, want 100/1",
			total.InputTokens, total.Requests)
	}
}

// A request bills the credential ledger and the client ledger under the same
// request id. Both must land.
func TestStoreRecordOnceBothLedgers(t *testing.T) {
	s := OpenInMemory()
	defer s.Close()
	s.EnableDedup(NewDeduper(time.Minute, 100))

	c := testCounts(10, 20)
	if ok, _ := s.RecordOnce("req-1", "auth-1", "cred", c); !ok {
		t.Fatal("auth ledger rejected")
	}
	if ok, _ := s.RecordClientOnce("req-1", "tok-1", "client", c, 1.25); !ok {
		t.Fatal("client ledger rejected — scopes must be independent")
	}
	if got := s.WeeklyCostUSD("tok-1"); got != 1.25 {
		t.Errorf("WeeklyCostUSD = %v, want 1.25", got)
	}
	// And each is still individually idempotent.
	if ok, _ := s.RecordClientOnce("req-1", "tok-1", "client", c, 1.25); ok {
		t.Error("client ledger replay must be rejected")
	}
	if got := s.WeeklyCostUSD("tok-1"); got != 1.25 {
		t.Errorf("WeeklyCostUSD after replay = %v, want 1.25", got)
	}
}

// Dedup is opt-in. Without it the methods must behave exactly like the
// originals — an existing fork that never calls EnableDedup sees no change.
func TestStoreRecordOnceWithoutDedupIsPassthrough(t *testing.T) {
	s := OpenInMemory()
	defer s.Close()

	c := testCounts(10, 20)
	for i := range 3 {
		if ok, err := s.RecordOnce("req-1", "auth-1", "cred", c); !ok || err != nil {
			t.Fatalf("call %d = (%v, %v), want (true, nil)", i, ok, err)
		}
	}
	var total Counts
	for _, v := range s.Snapshot()["auth-1"].Daily {
		total.Add(v)
	}
	if total.Requests != 3 {
		t.Errorf("requests = %d, want 3 (no dedup installed)", total.Requests)
	}
}

// A conflicting replay must not touch the ledger.
func TestStoreRecordOnceConflictRecordsNothing(t *testing.T) {
	s := OpenInMemory()
	defer s.Close()
	s.EnableDedup(NewDeduper(time.Minute, 100))

	if ok, _ := s.RecordOnce("req-1", "auth-1", "cred", testCounts(10, 20)); !ok {
		t.Fatal("first RecordOnce rejected")
	}
	ok, err := s.RecordOnce("req-1", "auth-1", "cred", testCounts(999, 999))
	if ok || !errors.Is(err, ErrRequestConflict) {
		t.Fatalf("conflict = (%v, %v), want (false, ErrRequestConflict)", ok, err)
	}
	var total Counts
	for _, v := range s.Snapshot()["auth-1"].Daily {
		total.Add(v)
	}
	if total.InputTokens != 10 {
		t.Errorf("conflicting counts leaked into ledger: input=%d, want 10", total.InputTokens)
	}
}

// Fingerprint must separate requests that differ in any billable dimension.
func TestFingerprintDiscriminates(t *testing.T) {
	base := Fingerprint(testCounts(10, 20), 0.5, "auth-1")

	if got := Fingerprint(testCounts(10, 20), 0.5, "auth-1"); got != base {
		t.Error("identical inputs must hash identically")
	}
	for name, got := range map[string]uint64{
		"input":  Fingerprint(testCounts(11, 20), 0.5, "auth-1"),
		"output": Fingerprint(testCounts(10, 21), 0.5, "auth-1"),
		"cost":   Fingerprint(testCounts(10, 20), 0.6, "auth-1"),
		"extra":  Fingerprint(testCounts(10, 20), 0.5, "auth-2"),
	} {
		if got == base {
			t.Errorf("%s change must alter the fingerprint", name)
		}
	}
}
