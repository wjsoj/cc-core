package checkout

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func reconciliationFixture(t *testing.T) (Auth, Quote, *Ledger, Snapshot) {
	t.Helper()
	a, sel, b, _ := fixture()
	q := Quote{Session: Session{ID: "oaics_fixture", Entity: "openai_llc"}, Selection: sel, Billing: b, Amount: 2000, Key: "pk_live_fixture", Expires: time.Now().Add(time.Minute), UserID: a.UserID, AccountID: a.AccountID}
	l := ledgerFor(t)
	if err := l.BeginAttempt(a, q); err != nil {
		t.Fatal(err)
	}
	snap := Snapshot{Status: "complete", PaymentStatus: "paid", Plan: sel.Plan, Amount: 2000, Currency: "usd", Metadata: map[string]string{"user_ref": a.UserID, "account_id": a.AccountID}}
	return a, q, l, snap
}

func reconciliationClient(t *testing.T, snap Snapshot, session Session) (*Client, *int) {
	t.Helper()
	calls := 0
	c, err := NewClientWithTransport(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || r.Body != nil || r.URL.String() != "https://chatgpt.com/backend-api/payments/checkout/"+session.Entity+"/"+session.ID {
			t.Error("reconciliation made a non-read-only or unbound request")
		}
		data, _ := json.Marshal(snap)
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(data)))}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	return c, &calls
}

func TestReconcileRequiresFullPaidEvidence(t *testing.T) {
	for _, name := range []string{"paid", "metadata_plan", "bare_paid", "wrong_amount", "missing_amount", "wrong_currency", "missing_currency", "wrong_plan", "conflicting_plan", "wrong_user", "missing_user", "wrong_account", "missing_account", "open", "expired", "contradictory_status", "unknown_status"} {
		t.Run(name, func(t *testing.T) {
			a, q, l, snap := reconciliationFixture(t)
			wantState, wantErr := "unknown", true
			switch name {
			case "paid":
				wantState, wantErr = "paid", false
			case "metadata_plan":
				snap.Plan = ""
				snap.Metadata["user_origin_tag"] = q.Selection.Plan
				wantState, wantErr = "paid", false
			case "bare_paid":
				snap = Snapshot{Status: "complete", PaymentStatus: "paid"}
			case "wrong_amount":
				snap.Amount++
			case "missing_amount":
				snap.Amount = 0
			case "wrong_currency":
				snap.Currency = "php"
			case "missing_currency":
				snap.Currency = ""
			case "wrong_plan":
				snap.Plan = "chatgptpro"
			case "conflicting_plan":
				snap.Metadata["user_origin_tag"] = "chatgptpro"
			case "wrong_user":
				snap.Metadata["user_ref"] = "other"
			case "missing_user":
				delete(snap.Metadata, "user_ref")
			case "wrong_account":
				snap.Metadata["account_id"] = "other"
			case "missing_account":
				delete(snap.Metadata, "account_id")
			case "open":
				snap = Snapshot{Status: "open", PaymentStatus: "unpaid"}
				wantState, wantErr = "pending", false
			case "expired":
				snap = Snapshot{Status: "expired", PaymentStatus: "unpaid"}
				wantState, wantErr = "expired", false
			case "contradictory_status":
				snap.Status = "open"
				wantErr = false
			case "unknown_status":
				snap.Status = "new_upstream_status"
				wantErr = false
			}
			c, calls := reconciliationClient(t, snap, q.Session)
			defer c.Close()
			out, err := c.Reconcile(context.Background(), a, q.Session, l)
			if (err != nil) != wantErr || out.State != wantState || out.Paid != (wantState == "paid") || *calls != 1 {
				t.Fatalf("result=%+v error=%v calls=%d", out, err, *calls)
			}
			if l.BeginAttempt(a, q) == nil {
				t.Fatal("reconciliation released confirmation guard")
			}
		})
	}
}

func TestReconcileRejectsUnownedAndDamagedRecordsBeforeNetwork(t *testing.T) {
	for _, name := range []string{"nil", "wrong_owner", "wrong_order", "truncated", "oversized", "wrong_record_session", "wrong_phase", "public_file", "symlink"} {
		t.Run(name, func(t *testing.T) {
			a, q, l, snap := reconciliationFixture(t)
			sum := sha256.Sum256([]byte(q.Session.Entity + ":" + q.Session.ID))
			path := filepath.Join(l.dir, hex.EncodeToString(sum[:])+".json")
			switch name {
			case "nil":
				l = nil
			case "wrong_owner":
				a.Token = "other_fixture_token_not_real_12345"
			case "wrong_order":
				q.Session.ID = "oaics_other"
			case "truncated":
				if err := os.WriteFile(path, []byte(`{"owner":`), 0600); err != nil {
					t.Fatal(err)
				}
			case "oversized":
				if err := os.WriteFile(path, []byte(strings.Repeat(" ", 8193)), 0600); err != nil {
					t.Fatal(err)
				}
			case "wrong_record_session", "wrong_phase":
				r, err := l.readAttempt(a, q.Session)
				if err != nil {
					t.Fatal(err)
				}
				if name == "wrong_phase" {
					r.Phase = "unknown"
				} else {
					r.Session.ID = "oaics_other"
				}
				data, _ := json.Marshal(r)
				if err = os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			case "public_file":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				other := filepath.Join(t.TempDir(), "record.json")
				if err := os.Rename(path, other); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(other, path); err != nil {
					t.Fatal(err)
				}
			}
			c, calls := reconciliationClient(t, snap, q.Session)
			defer c.Close()
			out, err := c.Reconcile(context.Background(), a, q.Session, l)
			if err == nil || out.Paid || *calls != 0 || l.Owns(a, q.Session) {
				t.Fatalf("unauthorized read: %+v %v calls=%d", out, err, *calls)
			}
		})
	}
}

func TestReconcileLegacyRecordAndExpiredQuote(t *testing.T) {
	a, q, l, snap := reconciliationFixture(t)
	c, calls := reconciliationClient(t, snap, q.Session)
	defer c.Close()
	q.Expires = time.Now().Add(-time.Hour)
	if out, err := c.ReconcileQuote(context.Background(), a, q); err != nil || !out.Paid {
		t.Fatalf("late paid failed: %+v %v", out, err)
	}
	sum := sha256.Sum256([]byte(q.Session.Entity + ":" + q.Session.ID))
	path := filepath.Join(l.dir, hex.EncodeToString(sum[:])+".json")
	r, err := l.readAttempt(a, q.Session)
	if err != nil {
		t.Fatal(err)
	}
	r.UserID = ""
	r.AccountID = ""
	data, _ := json.Marshal(r)
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if !l.Owns(a, q.Session) {
		t.Fatal("legacy owner cannot query")
	}
	if out, err := c.Reconcile(context.Background(), a, q.Session, l); err == nil || out.Paid || *calls != 2 {
		t.Fatalf("legacy record falsely proved paid: %+v %v", out, err)
	}
}

func TestReconcileNetworkFailureIsUnknown(t *testing.T) {
	a, q, l, _ := reconciliationFixture(t)
	c, _ := NewClientWithTransport(roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("secret proxy credentials") }))
	defer c.Close()
	out, err := c.Reconcile(context.Background(), a, q.Session, l)
	if err == nil || out.Paid || out.State != "unknown" || strings.Contains(err.Error(), "secret") {
		t.Fatalf("unsafe failure: %+v %v", out, err)
	}
}
