package checkout

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCapturedVerificationFailureIsNotPaid(t *testing.T) {
	// Minimal re-identified shape of requests 1989/2432. No captured credentials,
	// card data, payment identifiers or billing details are used as fixtures.
	var intent PaymentIntent
	err := json.Unmarshal([]byte(`{"status":"requires_payment_method","last_payment_error":{"code":"payment_intent_authentication_failure","type":"invalid_request_error","message":"Captcha challenge failed. Try again with a different payment method.","payment_method":{"id":"pm_fixture"}},"client_secret":"fixture-secret","next_action":null}`), &intent)
	if err != nil {
		t.Fatal(err)
	}
	r := intent.Result()
	if r.Paid || r.State != "requires_payment_method" || r.ErrorCode != "payment_intent_authentication_failure" || r.Message == "" {
		t.Fatalf("unexpected outcome: %+v", r)
	}
	data, _ := json.Marshal(r)
	for _, s := range []string{"pm_fixture", "fixture-secret", "Captcha challenge failed"} {
		if strings.Contains(string(data), s) {
			t.Fatal("raw upstream detail exposed")
		}
	}
}

func TestPaymentIntentResultStates(t *testing.T) {
	for _, tc := range []struct{ status, code, decline, state, expectedCode string }{
		{"requires_action", "", "", "requires_action", ""},
		{"succeeded", "card_declined", "", "processing", ""},
		{"processing", "", "", "processing", ""},
		{"canceled", "", "", "canceled", ""},
		{"requires_payment_method", "card_declined", "insufficient_funds", "requires_payment_method", "insufficient_funds"},
		{"requires_payment_method", "card_declined", "generic_decline", "requires_payment_method", "card_declined"},
		{"requires_payment_method", "expired_card", "", "requires_payment_method", "expired_card"},
		{"requires_payment_method", "incorrect_cvc", "", "requires_payment_method", "incorrect_cvc"},
		{"requires_payment_method", "private-upstream-value", "private-decline-value", "requires_payment_method", ""},
		{"unknown-private-status", "", "", "unknown", ""},
	} {
		r := (PaymentIntent{Status: tc.status, LastPaymentError: &PaymentIntentFailure{Code: tc.code, DeclineCode: tc.decline}}).Result()
		if r.Paid || r.State != tc.state || r.ErrorCode != tc.expectedCode {
			t.Fatalf("%+v: %+v", tc, r)
		}
		b, _ := json.Marshal(r)
		if strings.Contains(string(b), "private") {
			t.Fatal("unrecognized upstream value exposed")
		}
	}
}
