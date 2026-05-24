package kiroapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/wjsoj/cc-core/kirotransport"
)

func TestGetCreditsWireShape(t *testing.T) {
	var sawPath, sawAuth, sawOrigin, sawResource, sawProfile string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawPath = r.URL.Path
		sawAuth = r.Header.Get("Authorization")
		sawOrigin = r.URL.Query().Get("origin")
		sawResource = r.URL.Query().Get("resourceType")
		sawProfile = r.URL.Query().Get("profileArn")
		_, _ = io.WriteString(w, `{
			"nextDateReset": 1748000000,
			"subscriptionInfo": {"subscriptionTitle":"KIRO PRO+"},
			"usageBreakdownList": [{
				"currentUsage": 12,
				"currentUsageWithPrecision": 12.4,
				"usageLimit": 1000,
				"usageLimitWithPrecision": 1000.0,
				"nextDateReset": 1748000000,
				"bonuses": [
					{"currentUsage": 5.0, "usageLimit": 50.0, "status": "ACTIVE"},
					{"currentUsage": 100.0, "usageLimit": 200.0, "status": "EXPIRED"}
				],
				"freeTrialInfo": {
					"currentUsageWithPrecision": 3.0,
					"usageLimitWithPrecision": 25.0,
					"freeTrialStatus": "ACTIVE"
				}
			}]
		}`)
	}))
	defer srv.Close()

	c := &Client{
		HTTP:   &hostRewriter{base: srv.URL, next: srv.Client()},
		Token:  "aoaABC",
		Flavor: kirotransport.FlavorCLI,
	}
	out, err := c.GetCredits(context.Background(), "arn:test")
	if err != nil {
		t.Fatal(err)
	}
	if sawPath != "/getUsageLimits" {
		t.Errorf("path: %s", sawPath)
	}
	if sawAuth != "Bearer aoaABC" {
		t.Errorf("auth: %s", sawAuth)
	}
	if sawOrigin != "KIRO_CLI" {
		t.Errorf("origin should be KIRO_CLI for FlavorCLI, got %s", sawOrigin)
	}
	if sawResource != "AGENTIC_REQUEST" {
		t.Errorf("resourceType: %s", sawResource)
	}
	if sawProfile != "arn:test" {
		t.Errorf("profileArn: %s", sawProfile)
	}

	// Parsing
	if out.Plan() != "KIRO PRO+" {
		t.Errorf("plan: %q", out.Plan())
	}
	// UsageTotal = 12.4 (base) + 3.0 (active trial) + 5.0 (active bonus) = 20.4
	if got := out.UsageTotal(); got < 20.39 || got > 20.41 {
		t.Errorf("UsageTotal: %f, want ~20.4", got)
	}
	// LimitTotal = 1000 + 25 (trial) + 50 (active bonus) = 1075 — expired bonus excluded
	if got := out.LimitTotal(); got < 1074.99 || got > 1075.01 {
		t.Errorf("LimitTotal: %f, want 1075", got)
	}
	// Remaining = 1075 - 20.4 = 1054.6
	if got := out.Remaining(); got < 1054.5 || got > 1054.7 {
		t.Errorf("Remaining: %f", got)
	}
	// Reset time
	if got := out.NextResetAt(); !got.Equal(time.Unix(1748000000, 0)) {
		t.Errorf("NextResetAt: %v", got)
	}
}

func TestGetCreditsIDEFlavorDefaultOrigin(t *testing.T) {
	var sawOrigin string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawOrigin = r.URL.Query().Get("origin")
		_, _ = io.WriteString(w, `{"usageBreakdownList":[]}`)
	}))
	defer srv.Close()
	c := &Client{
		HTTP:   &hostRewriter{base: srv.URL, next: srv.Client()},
		Token:  "t",
		Flavor: kirotransport.FlavorIDE,
	}
	_, _ = c.GetCredits(context.Background(), "")
	if sawOrigin != "AI_EDITOR" {
		t.Errorf("IDE flavor should use AI_EDITOR origin, got %s", sawOrigin)
	}
}

func TestCreditsRemainingFlooredAtZero(t *testing.T) {
	r := &CreditsResponse{
		UsageBreakdownList: []UsageBreakdown{{
			CurrentUsageWithPrecision: 999.0,
			UsageLimitWithPrecision:   100.0,
		}},
	}
	if got := r.Remaining(); got != 0 {
		t.Errorf("over-quota should floor at 0, got %f", got)
	}
}

func TestCreditsEmptyResponse(t *testing.T) {
	r := &CreditsResponse{}
	if r.Plan() != "" || r.Primary() != nil || r.UsageTotal() != 0 || r.LimitTotal() != 0 {
		t.Errorf("empty response should yield zero values: %+v", r)
	}
}

func TestCreditsAPIKeyTokenType(t *testing.T) {
	var sawType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawType = r.Header.Get("tokentype")
		_, _ = io.WriteString(w, `{"usageBreakdownList":[]}`)
	}))
	defer srv.Close()
	c := &Client{
		HTTP:     &hostRewriter{base: srv.URL, next: srv.Client()},
		Token:    "ksk_abc",
		IsAPIKey: true,
	}
	_, _ = c.GetCredits(context.Background(), "")
	if sawType != "API_KEY" {
		t.Errorf("API_KEY tokentype: %q", sawType)
	}
}

// Reuse hostRewriter from kiroapi_test.go.
var _ = strings.NewReader // keep imports
var _ = json.Marshal
var _ url.URL
