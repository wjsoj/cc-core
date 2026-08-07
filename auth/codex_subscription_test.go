package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// portalCapture is a verbatim GET /backend-api/subscriptions?account_id=
// response from a live ChatGPT Plus account (identifiers replaced). It is the
// ground truth for the field names below — see docs/codex-subscription.md.
const portalCapture = `{
  "id": "sub-0000",
  "plan_type": "plus",
  "seats_in_use": 1,
  "seats_entitled": 1,
  "seat_capacity": [],
  "active_start": "2026-08-04T10:22:17Z",
  "active_until": "2026-09-04T10:22:17Z",
  "last_credit_grant_update": null,
  "next_credit_grant_update": null,
  "billing_period": "monthly",
  "scheduled_billing_period": null,
  "price_country": null,
  "pricing_scope": "default",
  "will_renew": true,
  "cancellation_outcome": null,
  "non_profit_org_discount_applied": null,
  "billing_currency": "USD",
  "is_delinquent": false,
  "is_processor_stripe": true,
  "became_delinquent_timestamp": null,
  "grace_period_end_timestamp": null,
  "from_webview": null
}`

// accountsCheckCapture is the verbatim accounts/check envelope for the same
// account, trimmed to the keys this package decodes. Note the "default" alias
// pointing at the same account object — the selection logic depends on it.
const accountsCheckCapture = `{
  "accounts": {
    "acct-0000": {
      "account": {
        "account_id": "acct-0000",
        "organization_id": "org-0000",
        "plan_type": "plus",
        "structure": "personal",
        "workspace_type": null,
        "created_time": "2026-03-26T14:22:59.594579Z",
        "has_previously_paid_subscription": true,
        "is_most_recent_expired_subscription_gratis": false,
        "started_as_free_workspace": false,
        "is_deactivated": false,
        "eligible_for_reactivation": false,
        "is_usage_based_seat_enabled": false
      },
      "entitlement": {
        "subscription_id": "sub-0000",
        "has_active_subscription": true,
        "is_active_subscription_gratis": false,
        "subscription_plan": "chatgptplusplan",
        "expires_at": "2026-09-04T16:22:17+00:00",
        "renews_at": "2026-09-04T10:22:17+00:00",
        "cancels_at": null,
        "billing_period": "monthly",
        "scheduled_plan_change": null,
        "billing_currency": "USD",
        "discount": {
          "discount_type": "percentage",
          "amount": 100,
          "duration_num_periods": 1,
          "discount_expires_at": "2026-09-04T10:22:17+00:00",
          "discount_start_in_num_periods": null,
          "cancellation_policy": "term_end",
          "promo_campaign_id": "plus-1-month-free",
          "quantity_off": null
        },
        "applied_discounts": [
          {
            "discount_type": "percentage",
            "amount": 100,
            "duration_num_periods": 1,
            "discount_expires_at": "2026-09-04T10:22:17+00:00",
            "cancellation_policy": "term_end",
            "promo_campaign_id": "plus-1-month-free"
          }
        ],
        "trial": null,
        "is_delinquent": false,
        "became_delinquent_timestamp": null,
        "grace_period_end_timestamp": null
      },
      "last_active_subscription": {
        "subscription_id": "sub-0000",
        "purchase_origin_platform": "chatgpt_web",
        "will_renew": true,
        "cancellation_outcome": null
      }
    },
    "default": {
      "account": {
        "account_id": "acct-0000",
        "plan_type": "plus",
        "is_deactivated": false
      },
      "entitlement": {
        "subscription_id": "sub-0000",
        "has_active_subscription": true,
        "subscription_plan": "chatgptplusplan"
      }
    }
  }
}`

// TestCodexPortalDecodeCapture pins the /subscriptions field names against a
// real payload. active_start is the field the whole feature exists for — it
// is the only upstream source for "when was this credential last paid".
func TestCodexPortalDecodeCapture(t *testing.T) {
	var p CodexSubscriptionPortal
	if err := json.Unmarshal([]byte(portalCapture), &p); err != nil {
		t.Fatalf("decode portal capture: %v", err)
	}
	if p.PlanType != "plus" {
		t.Errorf("plan_type = %q, want plus", p.PlanType)
	}
	wantStart := time.Date(2026, 8, 4, 10, 22, 17, 0, time.UTC)
	if !p.ActiveStart.Equal(wantStart) {
		t.Errorf("active_start = %v, want %v", p.ActiveStart, wantStart)
	}
	if !p.ActiveUntil.Equal(time.Date(2026, 9, 4, 10, 22, 17, 0, time.UTC)) {
		t.Errorf("active_until = %v", p.ActiveUntil)
	}
	if p.BillingPeriod != "monthly" || p.BillingCurrency != "USD" {
		t.Errorf("billing = %q/%q", p.BillingPeriod, p.BillingCurrency)
	}
	if !p.WillRenew {
		t.Error("will_renew should be true")
	}
	if p.SeatsInUse != 1 || p.SeatsEntitled != 1 {
		t.Errorf("seats = %d/%d", p.SeatsInUse, p.SeatsEntitled)
	}
	if p.IsDelinquent || p.GracePeriodEndTimestamp != nil {
		t.Error("account should not be delinquent")
	}
}

// TestCodexEntitlementDecodeCapture pins the accounts/check entitlement,
// including the offset-form timestamp ("+00:00" rather than "Z") that this
// endpoint uses while /subscriptions uses Z. Both must parse.
func TestCodexEntitlementDecodeCapture(t *testing.T) {
	ent, acct, last, id, err := decodeAccountsCheckForTest(t, accountsCheckCapture, "acct-0000")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if id != "acct-0000" {
		t.Errorf("resolved account id = %q", id)
	}
	if ent.SubscriptionPlan != "chatgptplusplan" {
		t.Errorf("subscription_plan = %q", ent.SubscriptionPlan)
	}
	if ent.ExpiresAt == nil || !ent.ExpiresAt.Equal(time.Date(2026, 9, 4, 16, 22, 17, 0, time.UTC)) {
		t.Errorf("expires_at = %v (offset-form timestamp must parse)", ent.ExpiresAt)
	}
	if ent.Discount == nil || ent.Discount.Amount != 100 {
		t.Fatalf("discount not decoded: %+v", ent.Discount)
	}
	if ent.Discount.PromoCampaignID != "plus-1-month-free" {
		t.Errorf("promo_campaign_id = %q", ent.Discount.PromoCampaignID)
	}
	if len(ent.AppliedDiscounts) != 1 {
		t.Errorf("applied_discounts len = %d", len(ent.AppliedDiscounts))
	}
	if acct.CreatedTime == nil {
		t.Error("account created_time missing")
	}
	if !acct.HasPreviouslyPaidSubscription {
		t.Error("has_previously_paid_subscription should be true")
	}
	if last == nil || last.PurchaseOriginPlatform != "chatgpt_web" {
		t.Errorf("last_active_subscription = %+v", last)
	}
}

// TestCodexSubscriptionIsFree covers the case that motivated the helper: a
// term that is NOT gratis but is 100%-discounted still costs nothing. Reading
// only is_active_subscription_gratis reports such an account as paid.
func TestCodexSubscriptionIsFree(t *testing.T) {
	ent, _, _, _, err := decodeAccountsCheckForTest(t, accountsCheckCapture, "acct-0000")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	info := &CodexSubscriptionInfo{Entitlement: ent}

	if ent.IsActiveSubscriptionGratis {
		t.Fatal("capture precondition: gratis should be false here")
	}
	free, reason := info.IsFree()
	if !free {
		t.Fatal("fully discounted term must report free")
	}
	if reason != "promo:plus-1-month-free" {
		t.Errorf("reason = %q", reason)
	}

	// Gratis alone is also free.
	gratis := &CodexSubscriptionInfo{Entitlement: &CodexEntitlement{IsActiveSubscriptionGratis: true}}
	if free, reason := gratis.IsFree(); !free || reason != "gratis" {
		t.Errorf("gratis: free=%v reason=%q", free, reason)
	}

	// A partial discount is not free.
	partial := &CodexSubscriptionInfo{Entitlement: &CodexEntitlement{
		Discount: &CodexDiscount{DiscountType: "percentage", Amount: 50},
	}}
	if free, _ := partial.IsFree(); free {
		t.Error("50% off must not report free")
	}

	// Nil-safe.
	var nilInfo *CodexSubscriptionInfo
	if free, _ := nilInfo.IsFree(); free {
		t.Error("nil info must not report free")
	}
}

// TestCodexSubscriptionAtRisk pins the billing-side early warning: neither
// delinquency nor a cancelled renewal is visible to quota-based health.
func TestCodexSubscriptionAtRisk(t *testing.T) {
	end := time.Date(2026, 9, 4, 10, 22, 17, 0, time.UTC)

	healthy := &CodexSubscriptionInfo{
		Portal:     &CodexSubscriptionPortal{ActiveUntil: end, WillRenew: true},
		LastActive: &CodexLastActiveSubscription{WillRenew: true},
	}
	if risk, _, _ := healthy.AtRisk(); risk {
		t.Error("renewing account must not be at risk")
	}

	grace := int64(1788517337)
	delinquent := &CodexSubscriptionInfo{
		Portal: &CodexSubscriptionPortal{
			ActiveUntil: end, WillRenew: true,
			IsDelinquent: true, GracePeriodEndTimestamp: &grace,
		},
	}
	risk, reason, deadline := delinquent.AtRisk()
	if !risk || reason != "delinquent" {
		t.Errorf("delinquent: risk=%v reason=%q", risk, reason)
	}
	if !deadline.Equal(time.Unix(grace, 0)) {
		t.Errorf("deadline should be grace-period end, got %v", deadline)
	}

	cancelled := &CodexSubscriptionInfo{
		Portal:      &CodexSubscriptionPortal{ActiveUntil: end, WillRenew: false},
		Entitlement: &CodexEntitlement{HasActiveSubscription: true},
	}
	risk, reason, deadline = cancelled.AtRisk()
	if !risk || reason != "will_not_renew" {
		t.Errorf("cancelled: risk=%v reason=%q", risk, reason)
	}
	if !deadline.Equal(end) {
		t.Errorf("deadline should be term end, got %v", deadline)
	}

	var nilInfo *CodexSubscriptionInfo
	if risk, _, _ := nilInfo.AtRisk(); risk {
		t.Error("nil info must not report risk")
	}

	// last_active_subscription is the ONLY will_renew reporter when the
	// credential carries no account id, because /subscriptions needs one and
	// so Portal stays nil. Requiring a Portal here made that branch dead.
	entExpires := end
	lastActiveOnly := &CodexSubscriptionInfo{
		Entitlement: &CodexEntitlement{HasActiveSubscription: true, ExpiresAt: &entExpires},
		LastActive:  &CodexLastActiveSubscription{WillRenew: false},
	}
	risk, reason, deadline = lastActiveOnly.AtRisk()
	if !risk || reason != "will_not_renew" {
		t.Errorf("last-active-only cancellation: risk=%v reason=%q, want will_not_renew", risk, reason)
	}
	if !deadline.Equal(end) {
		t.Errorf("last-active-only deadline = %v, want %v", deadline, end)
	}

	// A never-paid free account trivially satisfies will_renew == false and has
	// no term to lose. Reporting it as about to lapse — with a zero-value date,
	// no less — is a false alarm on every free credential in the pool.
	free := &CodexSubscriptionInfo{
		Portal: &CodexSubscriptionPortal{PlanType: "free", WillRenew: false},
	}
	if risk, _, dl := free.AtRisk(); risk {
		t.Errorf("free account reported at risk (deadline %v)", dl)
	}

	// Same for a term already known to be inactive: nothing left to warn about.
	lapsed := &CodexSubscriptionInfo{
		Portal:      &CodexSubscriptionPortal{ActiveUntil: end, WillRenew: false},
		Entitlement: &CodexEntitlement{HasActiveSubscription: false},
	}
	if risk, _, _ := lapsed.AtRisk(); risk {
		t.Error("lapsed subscription must not be reported as at risk")
	}

	// Whenever a risk IS reported for a non-delinquent account, it must carry a
	// usable deadline — the panel renders it as a date.
	if risk, _, dl := cancelled.AtRisk(); risk && dl.IsZero() {
		t.Error("will_not_renew reported without a deadline")
	}
}

// TestCodexBillingRequestIdentity pins the request identity of the billing
// probes. Leaving User-Agent unset does not omit it — Go substitutes
// "Go-http-client/…", which on an OAuth subscription account is the single
// loudest third-party-client signal this project exists to avoid.
func TestCodexBillingRequestIdentity(t *testing.T) {
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		_, _ = w.Write([]byte(`{"accounts":{}}`))
	}))
	defer srv.Close()

	if _, err := codexBillingGET(context.Background(), srv.Client(), "tok", "acct-1", srv.URL); err != nil {
		t.Fatalf("codexBillingGET: %v", err)
	}

	if ua := got.Get("User-Agent"); ua != browserUA {
		t.Errorf("User-Agent = %q, want the Chrome UA that matches the uTLS fingerprint", ua)
	}
	if strings.Contains(got.Get("User-Agent"), "Go-http-client") {
		t.Error("request advertises itself as a Go HTTP client")
	}
	// Browsers omit Origin on a same-origin GET; sending it alongside a browser
	// UA would be a combination no real client produces.
	if o := got.Get("Origin"); o != "" {
		t.Errorf("Origin = %q, want it absent on a same-origin GET", o)
	}
	for h, want := range map[string]string{
		"Authorization":      "Bearer tok",
		"Chatgpt-Account-Id": "acct-1",
		"Sec-Fetch-Site":     "same-origin",
		"Sec-Fetch-Mode":     "cors",
		"Sec-Ch-Ua-Platform": `"Linux"`,
	} {
		if got.Get(h) != want {
			t.Errorf("%s = %q, want %q", h, got.Get(h), want)
		}
	}
}

// TestCodexSubscriptionPurchasedAt covers the accessor the admin view calls.
func TestCodexSubscriptionPurchasedAt(t *testing.T) {
	start := time.Date(2026, 8, 4, 10, 22, 17, 0, time.UTC)
	info := &CodexSubscriptionInfo{Portal: &CodexSubscriptionPortal{ActiveStart: start}}
	if !info.PurchasedAt().Equal(start) {
		t.Errorf("PurchasedAt = %v, want %v", info.PurchasedAt(), start)
	}

	// accounts/check alone cannot answer this — it must report unknown
	// rather than deriving a wrong date from renews_at.
	renews := start.AddDate(0, 1, 0)
	entOnly := &CodexSubscriptionInfo{Entitlement: &CodexEntitlement{RenewsAt: &renews}}
	if !entOnly.PurchasedAt().IsZero() {
		t.Errorf("PurchasedAt without portal must be zero, got %v", entOnly.PurchasedAt())
	}
	// ...but it can still answer expiry.
	exp := renews
	entOnly.Entitlement.ExpiresAt = &exp
	if !entOnly.ExpiresAt().Equal(exp) {
		t.Errorf("ExpiresAt fallback = %v", entOnly.ExpiresAt())
	}
}

// TestCodexAccountsCheckSelectsPaidAccount covers a token that can see both a
// deactivated account and a live one: billing the deactivated entry would
// report the wrong plan.
func TestCodexAccountsCheckSelectsPaidAccount(t *testing.T) {
	payload := `{"accounts":{
	  "dead":{"account":{"account_id":"dead","plan_type":"free","is_deactivated":true},
	          "entitlement":{"has_active_subscription":false}},
	  "live":{"account":{"account_id":"live","plan_type":"pro","is_deactivated":false},
	          "entitlement":{"has_active_subscription":true,"subscription_plan":"chatgptproplan"}}
	}}`
	// No matching id and no "default" alias → falls through to the paid pick.
	ent, acct, _, id, err := decodeAccountsCheckForTest(t, payload, "")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if id != "live" || acct.PlanType != "pro" {
		t.Errorf("selected account %q (plan %q), want live/pro", id, acct.PlanType)
	}
	if !ent.HasActiveSubscription {
		t.Error("selected entitlement should be the active one")
	}
}

// decodeAccountsCheckForTest exercises the real selection logic against a
// static body by stubbing the HTTP layer out — it calls the same parser the
// fetch path uses.
func decodeAccountsCheckForTest(t *testing.T, body, accountID string) (
	*CodexEntitlement, *CodexBillingAccount, *CodexLastActiveSubscription, string, error) {
	t.Helper()
	return parseCodexAccountsCheck([]byte(body), accountID)
}
