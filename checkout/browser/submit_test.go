package browser

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/chromedp/chromedp"
	"github.com/wjsoj/cc-core/checkout"
)

func submitFixture(t *testing.T) (*Browser, checkout.Auth, checkout.Quote, *checkout.Ledger, *atomic.Int64) {
	t.Helper()
	var amount atomic.Int64
	amount.Store(2000)
	b, _ := fixtureBrowserWithResponse(t, func(url string) (int, string, string) {
		switch url {
		case "https://chatgpt.com/backend-api/payments/checkout/openai_llc/oaics_fixture":
			return 200, `{"status":"open","payment_status":"unpaid","plan_name":"chatgptplusplan","publishable_key":"pk_live_fixture"}`, "application/json"
		case "https://chatgpt.com/backend-api/payments/checkout/taxes":
			return 200, fmt.Sprintf(`{"checkout_session":{"status":"open","payment_status":"unpaid","amount_total":%d,"currency":"usd","metadata":{"user_ref":"user_fixture","account_id":"acct_fixture"}}}`, amount.Load()), "application/json"
		case "https://chatgpt.com/checkout/openai_llc/oaics_fixture":
			return 200, strings.Replace(billingFixture, "</body>", `<input autocomplete="cc-number"><input autocomplete="cc-exp"><input autocomplete="cc-csc"><script>window.trusted=false;document.querySelector('#subscribe').onclick=e=>{window.submits++;window.trusted=e.isTrusted};</script></body>`, 1), "text/html"
		}
		return 0, "", ""
	})
	a, s := createFixture(t, b)
	billing := checkout.Billing{Name: "Fixture User", Email: "fixture@example.invalid", Line1: "Fixture road", City: "Fixture", Country: "US", State: "NY", PostalCode: "10001"}
	if result, err := b.FillBilling(context.Background(), a, s, billing); err != nil || len(result.Missing) != 0 {
		t.Fatalf("billing: %+v %v", result, err)
	}
	c := b.QueryClient()
	defer c.Close()
	q, err := c.Quote(context.Background(), a, s, checkout.Selection{Plan: "chatgptplusplan", Country: "US", Currency: "USD"}, billing)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := b.FillCard(context.Background(), a, s, checkout.Card{Number: "4242424242424242", Month: "12", Year: "2035", CVC: "123"}); err != nil || !result.CompleteCard() {
		t.Fatalf("card: %+v %v", result, err)
	}
	ledger, err := checkout.NewLedger(filepath.Join(t.TempDir(), "ledger"))
	if err != nil {
		t.Fatal(err)
	}
	return b, a, q, ledger, &amount
}

func TestChromiumSubmitIsTrustedAndOnce(t *testing.T) {
	b, a, q, ledger, _ := submitFixture(t)
	var wg sync.WaitGroup
	var success atomic.Int32
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, err := b.Submit(context.Background(), a, q, ledger)
			if err == nil {
				success.Add(1)
			}
			if out.Paid || !out.Attempted {
				t.Error("submission misclassified")
			}
		}()
	}
	wg.Wait()
	if success.Load() != 1 || !ledger.Owns(a, q.Session) {
		t.Fatal("not exactly one durable submission")
	}
	var observed struct {
		Submits int  `json:"submits"`
		Trusted bool `json:"trusted"`
	}
	if err := b.run(context.Background(), chromedp.Evaluate(`({submits:window.submits,trusted:window.trusted})`, &observed)); err != nil || observed.Submits != 1 || !observed.Trusted {
		t.Fatalf("not one trusted click: %+v %v", observed, err)
	}
	// Losing the in-memory flag must not permit another attempt.
	b.submitAttempted = false
	if out, err := b.Submit(context.Background(), a, q, ledger); err == nil || !out.Attempted {
		t.Fatal("persistent guard ignored")
	}
}

func TestChromiumSubmitRejectsPreflightWithoutClaim(t *testing.T) {
	for _, name := range []string{"quote_changed", "wrong_owner", "wrong_billing", "disabled", "ambiguous", "overlay", "missing_ledger"} {
		t.Run(name, func(t *testing.T) {
			b, a, q, ledger, amount := submitFixture(t)
			usedLedger := ledger
			var script string
			switch name {
			case "quote_changed":
				amount.Store(2100)
			case "wrong_owner":
				a.Token = "other_synthetic_access_token_12345"
			case "wrong_billing":
				q.Billing.City = "Other"
			case "disabled":
				script = `document.querySelector('#subscribe').disabled=true`
			case "ambiguous":
				script = `document.body.insertAdjacentHTML('beforeend','<button>Subscribe</button>')`
			case "overlay":
				script = `document.body.insertAdjacentHTML('beforeend','<div style="position:fixed;inset:0;z-index:9999;background:white">User verification</div>')`
			case "missing_ledger":
				usedLedger = nil
			}
			if script != "" {
				if err := b.run(context.Background(), chromedp.Evaluate(script, nil)); err != nil {
					t.Fatal(err)
				}
			}
			out, err := b.Submit(context.Background(), a, q, usedLedger)
			if err == nil || out.Attempted || out.Paid || ledger.Owns(a, q.Session) {
				t.Fatalf("unsafe preflight result: %+v %v", out, err)
			}
			var submits int
			if err = b.run(context.Background(), chromedp.Evaluate(`window.submits`, &submits)); err != nil || submits != 0 {
				t.Fatal("preflight failure clicked")
			}
		})
	}
}
