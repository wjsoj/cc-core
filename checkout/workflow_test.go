package checkout

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type scenario struct {
	mu          sync.Mutex
	paths       []string
	confirms    int
	taxes       int
	amount      int
	changeAt    int
	state       string
	failConfirm bool
	mismatch    bool
	paid        bool
}

func (s *scenario) client() *Client {
	return &Client{http: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.paths = append(s.paths, r.URL.Host+r.URL.Path)
		if r.URL.Host == "api.stripe.com" && r.Header.Get("Authorization") != "" {
			return nil, errors.New("auth leaked to Stripe")
		}
		var out any
		switch {
		case r.URL.Path == "/backend-api/payments/checkout":
			out = map[string]string{"checkout_session_id": "oaics_fixture", "processor_entity": "openai_llc"}
		case strings.HasSuffix(r.URL.Path, "/oaics_fixture"):
			out = map[string]any{"status": "open", "payment_status": "unpaid", "plan_name": "chatgptplusplan", "publishable_key": "pk_live_fixture"}
			if s.paid {
				out = map[string]any{"status": "complete", "payment_status": "paid", "plan_name": "chatgptplusplan", "amount_total": 2000, "currency": "usd", "metadata": map[string]string{"user_ref": "user_fixture", "account_id": "acct_fixture"}}
			}
		case strings.HasSuffix(r.URL.Path, "/taxes"):
			s.taxes++
			amount := s.amount
			if amount == 0 {
				amount = 2000
			}
			if s.changeAt > 0 && s.taxes >= s.changeAt {
				amount++
			}
			user := "user_fixture"
			if s.mismatch {
				user = "other"
			}
			out = map[string]any{"checkout_session": map[string]any{"status": "open", "payment_status": "unpaid", "currency": "usd", "amount_total": amount, "metadata": map[string]string{"user_ref": user, "account_id": "acct_fixture"}}}
		case r.URL.Path == "/v1/confirmation_tokens":
			out = map[string]string{"id": "ctoken_fixture"}
		case r.URL.Path == "/backend-api/payments/checkout/confirm":
			s.confirms++
			if s.failConfirm {
				return nil, errors.New("sensitive upstream error")
			}
			out = map[string]string{"type": "payment_intent", "status": "success", "client_secret": "pi_fixture_secret_fixture", "confirm_return_url": "https://chatgpt.com/checkout/verify"}
		case r.URL.Path == "/v1/payment_intents/pi_fixture/confirm":
			state := s.state
			if state == "" {
				state = "succeeded"
				s.paid = true
			}
			out = map[string]string{"status": state}
		default:
			return nil, errors.New("unexpected upstream")
		}
		b, _ := json.Marshal(out)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(b))), Header: make(http.Header)}, nil
	})}}
}
func fixture() (Auth, Selection, Billing, Card) {
	return Auth{Token: "fixture_not_real_token_12345", UserID: "user_fixture", AccountID: "acct_fixture"}, Selection{Plan: "chatgptplusplan", Country: "US", Currency: "USD"}, Billing{Name: "Test User", Email: "test@example.invalid", Line1: "Test Street", City: "Test", PostalCode: "00000", Country: "US"}, Card{Number: "4242424242424242", CVC: "123", Month: "12", Year: "2035"}
}
func ledgerFor(t *testing.T) *Ledger {
	t.Helper()
	l, err := NewLedger(filepath.Join(t.TempDir(), "ledger"))
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestFullWorkflow(t *testing.T) {
	s := &scenario{}
	c := s.client()
	a, sel, b, card := fixture()
	ctx := context.Background()
	session, err := c.Create(ctx, a, sel)
	if err != nil {
		t.Fatal(err)
	}
	q, err := c.Quote(ctx, a, session, sel, b)
	if err != nil {
		t.Fatal(err)
	}
	l := ledgerFor(t)
	r, err := c.Pay(ctx, a, q, card, l)
	if err != nil || !r.Paid {
		t.Fatalf("payment: %+v %v", r, err)
	}
	if s.confirms != 1 {
		t.Fatal("wrong confirm count")
	}
	if !l.Owns(a, session) || l.Owns(Auth{Token: "another"}, session) {
		t.Fatal("recovery ownership broken")
	}
	files, _ := os.ReadDir(l.dir)
	for _, f := range files {
		raw, _ := os.ReadFile(filepath.Join(l.dir, f.Name()))
		for _, secret := range []string{a.Token, card.Number, `"cvc"`, b.Email, "pi_fixture_secret_fixture", "ctoken_fixture"} {
			if strings.Contains(string(raw), secret) {
				t.Fatal("secret persisted")
			}
		}
	}
}
func TestSafetyStates(t *testing.T) {
	for _, tc := range []struct {
		name     string
		s        *scenario
		wantErr  bool
		state    string
		confirms int
	}{
		{name: "3ds", s: &scenario{state: "requires_action"}, state: "requires_action", confirms: 1},
		{name: "processing", s: &scenario{state: "processing"}, state: "processing", confirms: 1},
		{name: "declined", s: &scenario{state: "requires_payment_method"}, state: "requires_payment_method", confirms: 1},
		{name: "amount changed", s: &scenario{changeAt: 2}, wantErr: true},
		{name: "amount changed after token", s: &scenario{changeAt: 3}, wantErr: true},
		{name: "confirm connection lost", s: &scenario{failConfirm: true}, wantErr: true, confirms: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := tc.s
			c := s.client()
			a, sel, b, card := fixture()
			ctx := context.Background()
			q, err := c.Quote(ctx, a, Session{"oaics_fixture", "openai_llc"}, sel, b)
			if err != nil {
				t.Fatal(err)
			}
			l := ledgerFor(t)
			out, err := c.Pay(ctx, a, q, card, l)
			if (err != nil) != tc.wantErr || out.Paid || tc.state != "" && out.State != tc.state {
				t.Fatalf("%+v %v", out, err)
			}
			if s.confirms != tc.confirms {
				t.Fatal("unexpected charge")
			}
			if tc.s.failConfirm {
				c2 := s.client()
				l2, _ := NewLedger(l.dir)
				_, err = c2.Pay(ctx, a, q, card, l2)
				if err == nil || s.confirms != 1 {
					t.Fatal("ambiguous confirmation replayed after restart")
				}
			}
		})
	}
}
func TestParallelConfirmGuard(t *testing.T) {
	s := &scenario{state: "processing"}
	c := s.client()
	a, sel, b, card := fixture()
	q, err := c.Quote(context.Background(), a, Session{"oaics_fixture", "openai_llc"}, sel, b)
	if err != nil {
		t.Fatal(err)
	}
	l := ledgerFor(t)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = c.Pay(context.Background(), a, q, card, l) }()
	}
	wg.Wait()
	if s.confirms != 1 {
		t.Fatalf("confirms=%d", s.confirms)
	}
}
func TestValidationAndOwnership(t *testing.T) {
	a, sel, b, card := fixture()
	s := &scenario{mismatch: true}
	c := s.client()
	if _, err := c.Quote(context.Background(), a, Session{"oaics_fixture", "openai_llc"}, sel, b); err == nil {
		t.Fatal("wrong owner accepted")
	}
	for _, raw := range []string{"", "{bad}", "abc\r\nsecret"} {
		if _, err := ParseAuth(raw); err == nil {
			t.Fatal("invalid auth accepted")
		}
	}
	for _, id := range []string{"../secret", "oaics_a?next=evil", "oaics_a/other"} {
		if (Session{id, "openai_llc"}).Validate() == nil {
			t.Fatal("invalid session accepted")
		}
	}
	card.Number = "4242424242424241"
	if card.Validate() == nil {
		t.Fatal("invalid card accepted")
	}
	s.mismatch = false
	q, err := c.Quote(context.Background(), a, Session{"oaics_fixture", "openai_llc"}, sel, b)
	if err != nil {
		t.Fatal(err)
	}
	q.Expires = time.Now().Add(-time.Second)
	_, _, _, card = fixture()
	if _, err = c.Pay(context.Background(), a, q, card, ledgerFor(t)); err == nil {
		t.Fatal("expired quote accepted")
	}
}
