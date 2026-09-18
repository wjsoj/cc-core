package browser

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/chromedp/cdproto/network"
	"github.com/wjsoj/cc-core/checkout"
)

func observerFixture() *paymentObserver {
	o := &paymentObserver{}
	o.arm(checkout.Quote{Session: checkout.Session{ID: "oaics_fixture", Entity: "openai_llc"}, Amount: 2000, Selection: checkout.Selection{Currency: "USD"}})
	return o
}
func observationRequest(rawURL, body string) *network.EventRequestWillBeSent {
	return &network.EventRequestWillBeSent{Request: &network.Request{URL: rawURL, Method: "POST", PostDataEntries: []*network.PostDataEntry{{Bytes: base64.StdEncoding.EncodeToString([]byte(body))}}}}
}
func bindObservedIntent(t *testing.T, o *paymentObserver) {
	t.Helper()
	r, ok := o.track(observationRequest("https://chatgpt.com/backend-api/payments/checkout/confirm", `{"checkout_session_id":"oaics_fixture"}`))
	if !ok {
		t.Fatal("bound confirm ignored")
	}
	r.status = 200
	o.accept(r, []byte(`{"type":"payment_intent","status":"success","client_secret":"pi_fixture_secret_SYNTHETICSECRET"}`))
	if o.intent != "pi_fixture" || o.result.Observed {
		t.Fatal("confirm should bind intent but not invent payment result")
	}
}

func TestObservationTracksOnlyArmedOrderRoutes(t *testing.T) {
	unarmed := &paymentObserver{}
	valid := observationRequest("https://chatgpt.com/backend-api/payments/checkout/confirm", `{"checkout_session_id":"oaics_fixture"}`)
	if _, ok := unarmed.track(valid); ok {
		t.Fatal("observing before user submission")
	}
	o := observerFixture()
	for _, tc := range []struct{ url, body string }{
		{"https://chatgpt.com/backend-api/payments/checkout/confirm", `{"checkout_session_id":"oaics_other"}`},
		{"https://chatgpt.com/backend-api/payments/checkout/confirm", `{"checkout_session_id":"oaics_fixture","processor_entity":"other"}`},
		{"https://chatgpt.com/backend-api/payments/checkout/confirm", `{`},
		{"https://api.stripe.com/v1/payment_pages/oaics_other/confirm", `{}`},
		{"https://evil.example/v1/payment_intents/pi_fixture/confirm", `{}`},
		{"https://api.stripe.com.evil.example/v1/payment_intents/pi_fixture/confirm", `{}`},
		{"http://api.stripe.com/v1/payment_intents/pi_fixture/confirm", `{}`},
		{"https://api.stripe.com/v1/payment_intents/pi_fixture/confirm?client_secret=synthetic", `{}`},
		{"https://api.stripe.com/v1/payment_intents/pi_fixture/cancel", `{}`},
		{"https://api.stripe.com/v1/payment_intents/pi_fixture/confirm/extra", `{}`},
	} {
		if _, ok := o.track(observationRequest(tc.url, tc.body)); ok {
			t.Fatal("unrelated route accepted")
		}
	}
	valid.Request.Method = "GET"
	if _, ok := o.track(valid); ok {
		t.Fatal("non-POST accepted")
	}
	valid.Request.Method = "POST"
	valid.RedirectResponse = &network.Response{}
	if _, ok := o.track(valid); ok {
		t.Fatal("redirect accepted")
	}
}

func TestObservationRequiresBindingIDAmountAndCurrency(t *testing.T) {
	good := `{"id":"pi_fixture","amount":2000,"currency":"usd","status":"requires_payment_method","last_payment_error":{"code":"payment_intent_authentication_failure","message":"SYNTHETIC_PRIVATE_MESSAGE"},"client_secret":"SYNTHETIC_PRIVATE_SECRET","payment_method":{"id":"SYNTHETIC_PRIVATE_METHOD"}}`
	for _, name := range []string{"valid", "unbound", "foreign_url", "foreign_body", "wrong_amount", "missing_amount", "wrong_currency", "invalid_json", "oversized"} {
		t.Run(name, func(t *testing.T) {
			o := observerFixture()
			if name != "unbound" {
				bindObservedIntent(t, o)
			}
			body := good
			url := "https://api.stripe.com/v1/payment_intents/pi_fixture/verify_challenge"
			switch name {
			case "foreign_url":
				url = "https://api.stripe.com/v1/payment_intents/pi_other/verify_challenge"
			case "foreign_body":
				body = strings.Replace(body, `"pi_fixture"`, `"pi_other"`, 1)
			case "wrong_amount":
				body = strings.Replace(body, `2000`, `2100`, 1)
			case "missing_amount":
				body = strings.Replace(body, `"amount":2000,`, ``, 1)
			case "wrong_currency":
				body = strings.Replace(body, `"usd"`, `"eur"`, 1)
			case "invalid_json":
				body = `{`
			case "oversized":
				body = strings.Repeat(" ", observationBodyLimit) + good
			}
			r, ok := o.track(observationRequest(url, ``))
			if !ok {
				t.Fatal("intent route unexpectedly rejected")
			}
			r.status = 200
			o.accept(r, []byte(body))
			if name != "valid" {
				if o.result.Observed {
					t.Fatal("unbound or contradictory evidence accepted")
				}
				return
			}
			if !o.result.Observed || o.result.Paid || o.result.State != "requires_payment_method" || o.result.ErrorCode != "payment_intent_authentication_failure" {
				t.Fatal("authentication failure lost")
			}
			encoded, _ := json.Marshal(o.result)
			if strings.Contains(string(encoded), "SYNTHETIC_PRIVATE") || strings.Contains(string(encoded), "pi_fixture") {
				t.Fatal("raw payment data exposed")
			}
		})
	}
}

func TestObservationNeverTreatsStripeSucceededAsPaidOrOverwritesWithOldResult(t *testing.T) {
	o := observerFixture()
	bindObservedIntent(t, o)
	r := observedRequest{kind: "intent", intent: "pi_fixture", status: 200, sequence: 20}
	o.accept(r, []byte(`{"id":"pi_fixture","amount":2000,"currency":"usd","status":"requires_action"}`))
	if o.result.State != "requires_action" {
		t.Fatal("verification not recognized")
	}
	r.sequence = 10
	o.accept(r, []byte(`{"id":"pi_fixture","amount":2000,"currency":"usd","status":"requires_payment_method"}`))
	if o.result.State != "requires_action" {
		t.Fatal("older response overwrote newer one")
	}
	r.sequence = 21
	o.accept(r, []byte(`{"id":"pi_fixture","amount":2000,"currency":"usd","status":"succeeded"}`))
	if o.result.Paid || o.result.State != "processing" {
		t.Fatal("Stripe success bypassed order reconciliation")
	}
}

func TestObservationPaymentPageRequiresExplicitExpandedBoundIntent(t *testing.T) {
	for _, body := range []string{
		`{"id":"oaics_other","payment_intent":{"id":"pi_fixture","amount":2000,"currency":"usd","status":"requires_action"}}`,
		`{"id":"oaics_fixture","payment_intent":"pi_fixture"}`,
		`{"id":"oaics_fixture","payment_intent":{"id":"pi_fixture","amount":2100,"currency":"usd","status":"requires_action"}}`,
	} {
		o := observerFixture()
		o.accept(observedRequest{kind: "page_confirm", status: 200, sequence: 1}, []byte(body))
		if o.result.Observed || o.intent != "" {
			t.Fatal("incomplete Payment Page evidence accepted")
		}
	}
	o := observerFixture()
	o.accept(observedRequest{kind: "page_confirm", status: 200, sequence: 1}, []byte(`{"id":"oaics_fixture","payment_intent":{"id":"pi_fixture","amount":2000,"currency":"usd","status":"requires_action"}}`))
	if !o.result.Observed || o.result.State != "requires_action" || o.result.Paid {
		t.Fatal("bound Payment Page hint not recognized")
	}
}
