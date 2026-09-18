package checkout

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestBeginAttemptSharesDurableGuard(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ledger")
	one, err := NewLedger(dir)
	if err != nil {
		t.Fatal(err)
	}
	two, err := NewLedger(dir)
	if err != nil {
		t.Fatal(err)
	}
	a := Auth{Token: "fixture_token_not_real_12345", UserID: "user_fixture", AccountID: "acct_fixture"}
	q := Quote{Session: Session{ID: "oaics_fixture", Entity: "openai_llc"}, Selection: Selection{Plan: "chatgptplusplan", Country: "US", Currency: "USD"}, Billing: Billing{Name: "Fixture", Email: "fixture@example.invalid", Line1: "Fixture", City: "Fixture", Country: "US", PostalCode: "10001"}, Amount: 2000, Expires: time.Now().Add(time.Minute), Key: "pk_live_fixture", UserID: a.UserID, AccountID: a.AccountID}
	var wg sync.WaitGroup
	var successes atomic.Int32
	for _, l := range []*Ledger{one, two} {
		wg.Add(1)
		go func(l *Ledger) {
			defer wg.Done()
			if l.BeginAttempt(a, q) == nil {
				successes.Add(1)
			}
		}(l)
	}
	wg.Wait()
	if successes.Load() != 1 || !two.Owns(a, q.Session) {
		t.Fatal("duplicate claim or missing recovery")
	}
	// The old protocol and browser executor share the same exclusive record.
	if err = two.claim(a, q); err == nil {
		t.Fatal("protocol bypassed browser claim")
	}
	files, _ := os.ReadDir(dir)
	if len(files) != 1 {
		t.Fatal("wrong record count")
	}
	data, _ := os.ReadFile(filepath.Join(dir, files[0].Name()))
	for _, secret := range []string{a.Token, q.Billing.Email, q.Billing.Line1} {
		if strings.Contains(string(data), secret) {
			t.Fatal("sensitive input stored")
		}
	}
	if (*Ledger)(nil).BeginAttempt(a, q) == nil {
		t.Fatal("nil ledger accepted")
	}
	bad := q
	bad.Session.ID = "oaics_second"
	bad.UserID = "other"
	if one.BeginAttempt(a, bad) == nil {
		t.Fatal("wrong identity accepted")
	}
}
