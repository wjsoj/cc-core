package auth

import (
	"testing"
)

// Minimal, re-identified schema from crack/chatgpt-checkout/rows/199.
// No request headers, original identifiers, cookies or Referer are included.
func TestAccountsCheck199FreeBillingShape(t *testing.T) {
	const fixture = `{"accounts":{"fixture":{"account":{"account_id":"fixture","plan_type":"free","created_time":"2026-09-01T00:00:00Z","has_previously_paid_subscription":false},"entitlement":{"subscription_id":null,"has_active_subscription":false,"subscription_plan":"chatgptfreeplan","expires_at":null,"renews_at":null,"cancels_at":null,"billing_period":null,"billing_currency":null,"is_delinquent":false},"last_active_subscription":{"subscription_id":null,"purchase_origin_platform":"chatgpt_not_purchased","will_renew":false,"cancellation_outcome":null}}}}`
	ent, account, last, id, err := parseCodexAccountsCheck([]byte(fixture), "fixture")
	if err != nil {
		t.Fatal(err)
	}
	if ent == nil || account == nil || last == nil {
		t.Fatal("captured billing groups lost")
	}
	if id != "fixture" || account.PlanType != "free" || ent.HasActiveSubscription || last.PurchaseOriginPlatform != "chatgpt_not_purchased" {
		t.Fatal("capture was incorrectly interpreted")
	}
}
