package checkout

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

// TestClientSubscriptionUsesOwnTransport pins the property Subscription
// exists to guarantee: the billing probe travels over the SAME transport
// (and therefore the same pinned proxy, when the caller configured one) as
// every other call this Client makes — not a transport of auth.ClientFor's
// own choosing. A roundTripFunc swapped into c.http is enough to prove that:
// if Subscription built its own client instead of reusing c.http, this fake
// transport would never see the request and the test would hang or fail.
func TestClientSubscriptionUsesOwnTransport(t *testing.T) {
	var sawHosts []string
	c := &Client{http: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		sawHosts = append(sawHosts, r.URL.Host)
		body := `{"accounts":{}}`
		if r.URL.Path == "/backend-api/subscriptions" {
			body = `{"id":"sub-1","plan_type":"plus"}`
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}}

	info, err := c.Subscription(context.Background(), Auth{Token: "fixture_access_token_not_real_012345", AccountID: "acct-1"})
	if err != nil {
		t.Fatalf("Subscription: %v", err)
	}
	if info.Portal == nil || info.Portal.PlanType != "plus" {
		t.Fatalf("portal not decoded: %+v", info.Portal)
	}
	for _, h := range sawHosts {
		if h != "chatgpt.com" {
			t.Errorf("request went to %q, want chatgpt.com", h)
		}
	}
	// Only subscription + accounts/check. This UI never displays saved cards.
	if len(sawHosts) != 2 {
		t.Errorf("expected two subscription endpoints hit, got %d requests", len(sawHosts))
	}
}

// TestClientSubscriptionRejectsEmptyToken mirrors Create/Quote/Pay's own
// guard: an invalid token must fail before any network call, not surface as
// an upstream error.
func TestClientSubscriptionRejectsEmptyToken(t *testing.T) {
	called := false
	c := &Client{http: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		called = true
		return nil, errors.New("must not be dialed")
	})}}
	if _, err := c.Subscription(context.Background(), Auth{}); err == nil {
		t.Fatal("empty Auth must be rejected")
	}
	if called {
		t.Error("must not attempt a network call for an invalid token")
	}
}

func TestSubscriptionBrowserQueryAndRedactedFailure(t *testing.T) {
	var paths []string
	c := &Client{http: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		paths = append(paths, r.URL.Path)
		if r.URL.Path == "/backend-api/accounts/check/v4-2023-04-27" {
			if r.URL.Query().Get("timezone_offset_min") != "-480" || r.Header.Get("Oai-Language") != "en-US" {
				t.Error("browser context not forwarded")
			}
		}
		return &http.Response{StatusCode: 403, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("<html>upstream-sensitive-fixture</html>"))}, nil
	})}}
	_, err := c.Subscription(context.Background(), Auth{Token: "fixture_access_token_not_real_012345", AccountID: "fixture", TimezoneOffsetMinutes: -480})
	if err == nil || !strings.Contains(err.Error(), "HTTP 403") || strings.Contains(err.Error(), "sensitive") || strings.Contains(err.Error(), "<html>") {
		t.Fatalf("unsafe error: %v", err)
	}
	if len(paths) != 2 {
		t.Fatalf("unnecessary card lookup: %v", paths)
	}
}
