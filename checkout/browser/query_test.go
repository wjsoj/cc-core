package browser

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/wjsoj/cc-core/checkout"
)

func TestQueryOperationsAreOrderBound(t *testing.T) {
	session := checkout.Session{ID: "oaics_fixture", Entity: "openai_llc"}
	const base = "/backend-api/payments/checkout"
	for _, test := range []struct {
		method, path, body string
		valid              bool
	}{
		{"GET", base + "/openai_llc/oaics_fixture", "", true},
		{"GET", base + "/openai_llc/oaics_other", "", false},
		{"GET", base + "/other_entity/oaics_fixture", "", false},
		{"GET", base + "/openai_llc/oaics_fixture", "{}", false},
		{"POST", base + "/taxes", `{"checkout_session_id":"oaics_fixture","processor_entity":"openai_llc"}`, true},
		{"POST", base + "/taxes", `{"checkout_session_id":"oaics_other","processor_entity":"openai_llc"}`, false},
		{"POST", base + "/taxes", `{"checkout_session_id":"oaics_fixture","processor_entity":"openai_llc","unknown":true}`, false},
		{"POST", base + "/confirm", "{}", false},
		{"POST", base + "/approve", "{}", false},
		{"POST", base, "{}", false},
	} {
		if err := validateQuery(test.method, test.path, []byte(test.body), session); (err == nil) != test.valid {
			t.Fatalf("query validation mismatch: %s %s", test.method, test.path)
		}
	}
}

func TestBrowserQueryRejectsForeignDestinationsWithoutBrowser(t *testing.T) {
	transport := &queryTransport{}
	for _, target := range []string{"https://api.stripe.com/v1/confirmation_tokens", "https://chatgpt.com.evil.test/", "https://chatgpt.com:443/", "https://chatgpt.com/a?x=1", "https://chatgpt.com/a#fragment", "https://chatgpt.com/%61", "http://chatgpt.com/"} {
		req, _ := http.NewRequest("GET", target, nil)
		if _, err := transport.RoundTrip(req); err == nil {
			t.Fatal("foreign destination accepted")
		}
	}
}

func TestChromiumQuoteAndStatusUseSameContext(t *testing.T) {
	var queries atomic.Int32
	var paid atomic.Bool
	b, _ := fixtureBrowserWithResponse(t, func(url string) (int, string, string) {
		switch url {
		case "https://chatgpt.com/backend-api/payments/checkout/openai_llc/oaics_fixture":
			queries.Add(1)
			if paid.Load() {
				return 200, `{"status":"complete","payment_status":"paid"}`, "application/json"
			}
			return 200, `{"status":"open","payment_status":"unpaid","plan_name":"chatgptplusplan","publishable_key":"pk_live_fixture"}`, "application/json"
		case "https://chatgpt.com/backend-api/payments/checkout/taxes":
			queries.Add(1)
			return 200, `{"checkout_session":{"status":"open","payment_status":"unpaid","amount_total":2000,"currency":"usd","metadata":{"user_ref":"user_fixture","account_id":"acct_fixture"}}}`, "application/json"
		}
		return 0, "", ""
	})
	a, s := createFixture(t, b)
	c := b.QueryClient()
	defer c.Close()
	selection := checkout.Selection{Plan: "chatgptplusplan", Country: "US", Currency: "USD"}
	billing := checkout.Billing{Name: "Fixture", Email: "fixture@example.invalid", Line1: "Fixture", City: "Fixture", Country: "US", PostalCode: "10001"}
	q, err := c.Quote(context.Background(), a, s, selection, billing)
	if err != nil || q.Amount != 2000 || q.AccountID != "acct_fixture" || queries.Load() != 2 {
		t.Fatalf("browser quote failed: %v", err)
	}
	bad := a
	bad.AccountID = "other_account"
	if _, err = c.Quote(context.Background(), bad, s, selection, billing); err == nil {
		t.Fatal("quote account mismatch accepted")
	}
	before := queries.Load()
	if _, err = c.Status(context.Background(), checkout.Auth{Token: "different_synthetic_token"}, s); err == nil || queries.Load() != before {
		t.Fatal("cross-owner query reached browser network")
	}
	if _, err = c.Status(context.Background(), a, checkout.Session{ID: "oaics_other", Entity: s.Entity}); err == nil || queries.Load() != before {
		t.Fatal("cross-order query reached browser network")
	}
	snap, err := c.Status(context.Background(), a, s)
	if err != nil || snap.Paid() {
		t.Fatal("open checkout or HTTP 200 marked paid")
	}
	paid.Store(true)
	snap, err = c.Status(context.Background(), a, s)
	if err != nil || !snap.Paid() {
		t.Fatal("authoritative paid state not recognized")
	}
}

func TestChromiumQueryErrorsAreRedacted(t *testing.T) {
	b, _ := fixtureBrowserWithResponse(t, func(url string) (int, string, string) {
		if strings.HasSuffix(url, "/openai_llc/oaics_fixture") && strings.Contains(url, "/backend-api/") {
			return 403, "secret upstream diagnostic never echo", "text/html"
		}
		return 0, "", ""
	})
	a, s := createFixture(t, b)
	_, err := b.QueryClient().Status(context.Background(), a, s)
	var upstream *checkout.UpstreamError
	if !errors.As(err, &upstream) || upstream.Status != 403 || strings.Contains(err.Error(), "secret") {
		t.Fatalf("wrong redacted query error: %v", err)
	}
}

func TestChromiumReconcileUsesOrderContextWithoutPaymentRequests(t *testing.T) {
	var paid atomic.Bool
	var queries atomic.Int32
	b, _ := fixtureBrowserWithResponse(t, func(url string) (int, string, string) {
		switch url {
		case "https://chatgpt.com/backend-api/payments/checkout/openai_llc/oaics_fixture":
			queries.Add(1)
			if paid.Load() {
				return 200, `{"status":"complete","payment_status":"paid","plan_name":"chatgptplusplan","amount_total":2000,"currency":"usd","metadata":{"user_ref":"user_fixture","account_id":"acct_fixture"}}`, "application/json"
			}
			return 200, `{"status":"open","payment_status":"unpaid","plan_name":"chatgptplusplan","publishable_key":"pk_live_fixture"}`, "application/json"
		case "https://chatgpt.com/backend-api/payments/checkout/taxes":
			queries.Add(1)
			return 200, `{"checkout_session":{"status":"open","payment_status":"unpaid","amount_total":2000,"currency":"usd","metadata":{"user_ref":"user_fixture","account_id":"acct_fixture"}}}`, "application/json"
		}
		if strings.Contains(url, "/confirm") || strings.Contains(url, "/approve") {
			t.Error("reconciliation submitted payment")
		}
		return 0, "", ""
	})
	a, s := createFixture(t, b)
	c := b.QueryClient()
	defer c.Close()
	q, err := c.Quote(context.Background(), a, s, checkout.Selection{Plan: "chatgptplusplan", Country: "US", Currency: "USD"}, checkout.Billing{Name: "Fixture", Email: "fixture@example.invalid", Line1: "Fixture", City: "Fixture", Country: "US", PostalCode: "10001"})
	if err != nil {
		t.Fatal(err)
	}
	l, err := checkout.NewLedger(filepath.Join(t.TempDir(), "ledger"))
	if err != nil {
		t.Fatal(err)
	}
	if err = l.BeginAttempt(a, q); err != nil {
		t.Fatal(err)
	}
	before := queries.Load()
	if out, err := c.Reconcile(context.Background(), a, s, l); err != nil || out.Paid || out.State != "pending" {
		t.Fatalf("pending: %+v %v", out, err)
	}
	paid.Store(true)
	if out, err := c.Reconcile(context.Background(), a, s, l); err != nil || !out.Paid || out.State != "paid" {
		t.Fatalf("paid: %+v %v", out, err)
	}
	if queries.Load() != before+2 {
		t.Fatal("reconciliation did more than one GET per call")
	}
}
