package checkout

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestPaymentFailureClassificationAndRedaction(t *testing.T) {
	for _, tc := range []struct {
		name, marker, body, kind string
		status                   int
	}{
		{"unauthorized", "", `{"token":"private-session"}`, "authentication", 401},
		{"forbidden JSON", "", `{"detail":"private-session"}`, "forbidden", 403},
		{"forbidden HTML not necessarily challenge", "", `<html>private-session</html>`, "forbidden", 403},
		{"explicit challenge", "challenge", `<html>private-session</html>`, "challenge", 403},
		{"challenge with 200", "challenge", `<html>private-session</html>`, "challenge", 200},
		{"limit", "", `{"error":"private-session"}`, "rate_limited", 429},
		{"server", "", `private-session`, "rejected", 503},
		{"invalid JSON", "", `<html>private-session</html>`, "invalid_response", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			c := &Client{http: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.GetBody != nil {
					t.Fatal("financial POST is replayable")
				}
				if r.Header.Get("Accept-Encoding") != "identity" || r.Header.Get("Accept") != "application/json" {
					t.Fatal("unsupported representation requested")
				}
				return &http.Response{StatusCode: tc.status, Header: http.Header{"Cf-Mitigated": {tc.marker}}, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			})}}
			var out any
			err := c.request(context.Background(), "private-session", "https://chatgpt.com/backend-api/payments/checkout/taxes", strings.NewReader(`{}`), false, &out)
			var upstream *UpstreamError
			if !errors.As(err, &upstream) || upstream.Kind != tc.kind || upstream.Status != tc.status || upstream.Operation != "获取含税报价" {
				t.Fatalf("unexpected error: %v", err)
			}
			if calls != 1 || strings.Contains(err.Error(), "private-session") || strings.Contains(err.Error(), "<html>") {
				t.Fatal("request replayed or secret exposed")
			}
		})
	}
}

func TestPayStopsOn403AtEveryStage(t *testing.T) {
	for _, path := range []string{
		"/backend-api/payments/checkout/openai_llc/oaics_fixture",
		"/backend-api/payments/checkout/taxes",
		"/v1/confirmation_tokens",
		"/backend-api/payments/checkout/confirm",
		"/v1/payment_intents/pi_fixture/confirm",
	} {
		t.Run(path, func(t *testing.T) {
			s := &scenario{}
			c := s.client()
			a, sel, billing, card := fixture()
			q, err := c.Quote(context.Background(), a, Session{"oaics_fixture", "openai_llc"}, sel, billing)
			if err != nil {
				t.Fatal(err)
			}
			transport := c.http.Transport
			blocked := false
			c.http.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if blocked {
					t.Fatal("request continued after 403")
				}
				if r.URL.Path == path {
					blocked = true
					return &http.Response{StatusCode: 403, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`<html>secret</html>`))}, nil
				}
				return transport.RoundTrip(r)
			})
			out, err := c.Pay(context.Background(), a, q, card, ledgerFor(t))
			var upstream *UpstreamError
			if !blocked || out.Paid || !errors.As(err, &upstream) || upstream.Status != 403 {
				t.Fatalf("payment did not stop: %+v %v", out, err)
			}
		})
	}
}

func TestPaymentOperationNeverContainsIdentifiers(t *testing.T) {
	for _, tc := range []struct{ host, path, want string }{
		{"chatgpt.com", "/backend-api/payments/checkout", "创建结账"},
		{"chatgpt.com", "/backend-api/payments/checkout/confirm", "确认结账"},
		{"chatgpt.com", "/backend-api/payments/checkout/openai_llc/oaics_private", "查询结账状态"},
		{"api.stripe.com", "/v1/confirmation_tokens", "创建卡片令牌"},
		{"api.stripe.com", "/v1/payment_intents/pi_private/confirm", "确认 Stripe 付款"},
	} {
		if got := paymentOperation(tc.host, tc.path); got != tc.want {
			t.Errorf("operation=%q", got)
		}
	}
}
