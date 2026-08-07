package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// CodexSubscriptionInfo is the *billing* view of a ChatGPT-subscription
// account: which plan it is on, when the current paid term started and ends,
// whether it auto-renews, what discount (if any) is making it free, and
// whether the account is delinquent.
//
// It complements CodexUsageInfo (auth/codex_usage.go): wham/usage answers
// "how much quota is left in this window", this answers "what was bought,
// when, and until when". Neither requires sending a real /responses request.
//
// Two upstream endpoints back it, both plain GETs authorised by the same
// OAuth access token the proxy already holds:
//
//	GET https://chatgpt.com/backend-api/subscriptions?account_id=<id>
//	GET https://chatgpt.com/backend-api/accounts/check/v4-2023-04-27
//
// They overlap but neither is a superset:
//   - /subscriptions is the only source of active_start (the term start —
//     i.e. *when the account was last paid/renewed*) and seat counts.
//   - accounts/check is the only source of the discount block, the trial
//     block, account created_time, and has_previously_paid_subscription.
//
// Sub-structs mirror the JSON verbatim (same convention as CodexUsageInfo)
// so a field the backend adds later can be surfaced by adding one struct
// field, and fields it removes decode as zero rather than failing.
type CodexSubscriptionInfo struct {
	// Portal is the /backend-api/subscriptions payload.
	Portal *CodexSubscriptionPortal `json:"portal,omitempty"`
	// Entitlement is accounts/check → accounts[<id>].entitlement.
	Entitlement *CodexEntitlement `json:"entitlement,omitempty"`
	// Account is accounts/check → accounts[<id>].account (billing-relevant
	// fields only; the full object carries ~35 keys of workspace/HIPAA/
	// residency config that no billing view needs).
	Account *CodexBillingAccount `json:"account,omitempty"`
	// LastActive is accounts/check → accounts[<id>].last_active_subscription.
	LastActive *CodexLastActiveSubscription `json:"last_active_subscription,omitempty"`

	// Updated is when we last successfully fetched this view.
	Updated time.Time `json:"updated"`
}

// CodexSubscriptionPortal mirrors GET /backend-api/subscriptions?account_id=.
//
// Timestamps here are RFC3339 strings, unlike the unix seconds wham/usage
// uses. They are kept as time.Time because every observed value has parsed;
// a future unparseable value fails the whole decode loudly rather than
// silently reading as zero, which is the right trade for billing data.
type CodexSubscriptionPortal struct {
	ID            string `json:"id"`
	PlanType      string `json:"plan_type"`
	SeatsInUse    int    `json:"seats_in_use"`
	SeatsEntitled int    `json:"seats_entitled"`

	// ActiveStart is the start of the current paid term — the closest thing
	// the API gives to "when was this credential last topped up". ActiveUntil
	// is when it lapses if WillRenew is false.
	ActiveStart time.Time `json:"active_start"`
	ActiveUntil time.Time `json:"active_until"`

	BillingPeriod   string `json:"billing_period"`   // "monthly" | "yearly"
	BillingCurrency string `json:"billing_currency"` // "USD"
	WillRenew       bool   `json:"will_renew"`

	// IsDelinquent means a renewal charge failed; the account keeps working
	// until GracePeriodEndTimestamp, then loses entitlement. This is the
	// earliest warning a proxy gets that a credential is about to die for
	// billing reasons rather than quota reasons.
	IsDelinquent              bool   `json:"is_delinquent"`
	BecameDelinquentTimestamp *int64 `json:"became_delinquent_timestamp,omitempty"`
	GracePeriodEndTimestamp   *int64 `json:"grace_period_end_timestamp,omitempty"`

	IsProcessorStripe bool `json:"is_processor_stripe"`

	// ScheduledBillingPeriod is non-null when the account has a pending
	// monthly→yearly (or reverse) switch at term end. CancellationOutcome
	// is non-null once a cancellation is scheduled. Both shapes are
	// uncaptured, so they pass through as raw JSON.
	ScheduledBillingPeriod json.RawMessage `json:"scheduled_billing_period,omitempty"`
	CancellationOutcome    json.RawMessage `json:"cancellation_outcome,omitempty"`
}

// CodexEntitlement mirrors accounts[<id>].entitlement.
type CodexEntitlement struct {
	SubscriptionID        string `json:"subscription_id"`
	HasActiveSubscription bool   `json:"has_active_subscription"`
	// IsActiveSubscriptionGratis is true when the term is comped outright
	// (as opposed to bought at a 100% discount — see Discount).
	IsActiveSubscriptionGratis bool `json:"is_active_subscription_gratis"`
	// SubscriptionPlan is the internal plan id ("chatgptplusplan"), which is
	// finer-grained than the "plus"/"pro" PlanType elsewhere.
	SubscriptionPlan string `json:"subscription_plan"`

	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	RenewsAt  *time.Time `json:"renews_at,omitempty"`
	CancelsAt *time.Time `json:"cancels_at,omitempty"`

	BillingPeriod   string `json:"billing_period"`
	BillingCurrency string `json:"billing_currency"`

	// Discount is the currently-applied promo; AppliedDiscounts is the full
	// list. A 100%-off entry here is how a "free" Plus term shows up, and it
	// is also the only field that says *when the free ride ends*
	// (DiscountExpiresAt) independently of the term end.
	Discount         *CodexDiscount  `json:"discount,omitempty"`
	AppliedDiscounts []CodexDiscount `json:"applied_discounts,omitempty"`

	// Trial shape is uncaptured (null on every account seen so far).
	Trial json.RawMessage `json:"trial,omitempty"`

	IsDelinquent              bool   `json:"is_delinquent"`
	BecameDelinquentTimestamp *int64 `json:"became_delinquent_timestamp,omitempty"`
	GracePeriodEndTimestamp   *int64 `json:"grace_period_end_timestamp,omitempty"`
}

// CodexDiscount is one entry of entitlement.applied_discounts[].
type CodexDiscount struct {
	DiscountType string `json:"discount_type"` // "percentage"
	// Amount is percent when DiscountType == "percentage" (100 = fully free).
	Amount                    float64    `json:"amount"`
	DurationNumPeriods        *int       `json:"duration_num_periods,omitempty"`
	DiscountExpiresAt         *time.Time `json:"discount_expires_at,omitempty"`
	DiscountStartInNumPeriods *int       `json:"discount_start_in_num_periods,omitempty"`
	CancellationPolicy        string     `json:"cancellation_policy,omitempty"`
	// PromoCampaignID names the campaign, e.g. "plus-1-month-free".
	PromoCampaignID string   `json:"promo_campaign_id,omitempty"`
	QuantityOff     *float64 `json:"quantity_off,omitempty"`
}

// CodexBillingAccount is the billing-relevant subset of accounts[<id>].account.
type CodexBillingAccount struct {
	AccountID      string     `json:"account_id"`
	OrganizationID string     `json:"organization_id,omitempty"`
	PlanType       string     `json:"plan_type"`
	Structure      string     `json:"structure,omitempty"` // "personal" | "workspace"
	WorkspaceType  string     `json:"workspace_type,omitempty"`
	CreatedTime    *time.Time `json:"created_time,omitempty"` // account signup

	// HasPreviouslyPaidSubscription distinguishes a never-paid free account
	// from one whose paid term lapsed — the two look identical on plan_type.
	HasPreviouslyPaidSubscription         bool `json:"has_previously_paid_subscription"`
	IsMostRecentExpiredSubscriptionGratis bool `json:"is_most_recent_expired_subscription_gratis"`
	StartedAsFreeWorkspace                bool `json:"started_as_free_workspace"`

	IsDeactivated           bool `json:"is_deactivated"`
	EligibleForReactivation bool `json:"eligible_for_reactivation"`
	IsUsageBasedSeatEnabled bool `json:"is_usage_based_seat_enabled"`
}

// CodexLastActiveSubscription mirrors accounts[<id>].last_active_subscription.
type CodexLastActiveSubscription struct {
	SubscriptionID string `json:"subscription_id"`
	// PurchaseOriginPlatform records where the subscription was bought
	// ("chatgpt_web", "ios", "android", …). iOS/Android purchases renew
	// through the app store, so a delinquency there cannot be fixed from
	// the web portal — worth surfacing before someone tries.
	PurchaseOriginPlatform string          `json:"purchase_origin_platform,omitempty"`
	WillRenew              bool            `json:"will_renew"`
	CancellationOutcome    json.RawMessage `json:"cancellation_outcome,omitempty"`
}

// ChatGPT web-portal billing endpoints. Pinned alongside codexWhamUsageURL
// for the same reason: every upstream shape this package speaks is pinned.
const (
	codexSubscriptionsURL = "https://chatgpt.com/backend-api/subscriptions"
	codexAccountsCheckURL = "https://chatgpt.com/backend-api/accounts/check/v4-2023-04-27"
)

// FetchCodexSubscription queries both billing endpoints and stores the merged
// result on the Auth. Safe to call from any goroutine; refreshes the access
// token first if necessary.
//
// Partial success is a success: the two endpoints fail independently, and
// either one alone is worth showing. The returned error is non-nil only when
// *both* failed (or the credential is unusable), and it wraps both causes.
// This matters because /subscriptions requires an account_id that some
// credentials don't carry, while accounts/check never does.
//
// Side effects on success:
//   - stores a.CodexSubscription and bumps a.CodexSubscriptionAt
//   - backfills a.PlanType when the credential's JWT didn't carry one, since
//     these endpoints are authoritative and the JWT claim can be stale after
//     an upgrade
//
// Deliberately NOT a side effect: credential health. A billing probe failing
// says nothing about whether /responses works, so — exactly as with
// FetchCodexUsage — no MarkFailure, no cooldown. Delinquency is surfaced for
// a human to act on, not used to auto-disable, because the grace period means
// a delinquent account keeps serving traffic normally until it doesn't.
func (a *Auth) FetchCodexSubscription(ctx context.Context, useUTLS bool) (*CodexSubscriptionInfo, error) {
	if a == nil {
		return nil, fmt.Errorf("nil auth")
	}
	if a.Kind != KindOAuth {
		return nil, fmt.Errorf("codex subscription probe requires OAuth credential (got %v)", a.Kind)
	}
	if NormalizeProvider(a.Provider) != ProviderOpenAI {
		return nil, fmt.Errorf("codex subscription probe is OpenAI-only (auth is %s)", a.Provider)
	}

	if err := a.EnsureFresh(ctx, 5*time.Minute, useUTLS); err != nil {
		return nil, fmt.Errorf("token refresh: %w", err)
	}
	token, _ := a.Credentials()
	if token == "" {
		return nil, fmt.Errorf("no access token after refresh")
	}
	accountID, _ := a.CodexIdentity()

	// Same pooled keep-alive client as FetchCodexUsage — see the note there
	// about SOCKS5 proxies resetting rapid back-to-back TLS handshakes. That
	// applies doubly here since this makes two requests in a row.
	client := ClientFor(a.ProxyURL, useUTLS)

	info := &CodexSubscriptionInfo{}
	var portalErr, checkErr error

	// /subscriptions is account-scoped and returns an error envelope rather
	// than a payload when account_id is missing, so skip it when we have no
	// id instead of burning a request on a guaranteed failure.
	if accountID != "" {
		info.Portal, portalErr = fetchCodexPortal(ctx, client, token, accountID)
	} else {
		portalErr = fmt.Errorf("subscriptions: credential carries no chatgpt account id")
	}

	var checkAccountID string
	info.Entitlement, info.Account, info.LastActive, checkAccountID, checkErr =
		fetchCodexAccountsCheck(ctx, client, token, accountID)

	if portalErr != nil && checkErr != nil {
		return nil, fmt.Errorf("codex subscription probe failed: subscriptions: %v; accounts/check: %w", portalErr, checkErr)
	}

	// A credential whose JWT predates an account switch can hold a stale or
	// empty account id; accounts/check reports the real one. Retry the portal
	// call once with it rather than returning a half-empty view.
	if info.Portal == nil && checkAccountID != "" && checkAccountID != accountID {
		if p, err := fetchCodexPortal(ctx, client, token, checkAccountID); err == nil {
			info.Portal = p
		}
	}

	info.Updated = time.Now()

	a.mu.Lock()
	a.CodexSubscription = info
	a.CodexSubscriptionAt = info.Updated
	if a.PlanType == "" {
		if info.Portal != nil && info.Portal.PlanType != "" {
			a.PlanType = info.Portal.PlanType
		} else if info.Account != nil && info.Account.PlanType != "" {
			a.PlanType = info.Account.PlanType
		}
	}
	a.mu.Unlock()

	return info, nil
}

// fetchCodexPortal performs the /backend-api/subscriptions GET.
func fetchCodexPortal(ctx context.Context, client *http.Client, token, accountID string) (*CodexSubscriptionPortal, error) {
	u := codexSubscriptionsURL + "?account_id=" + url.QueryEscape(accountID)
	body, err := codexBillingGET(ctx, client, token, accountID, u)
	if err != nil {
		return nil, err
	}
	portal := &CodexSubscriptionPortal{}
	if err := json.Unmarshal(body, portal); err != nil {
		return nil, fmt.Errorf("subscriptions decode: %w", err)
	}
	// The endpoint answers 200 with an error envelope ({"detail": ...}) when
	// account_id is absent or not visible to the token, so a missing id is
	// the real success signal, not the status code.
	if portal.ID == "" && portal.PlanType == "" {
		return nil, fmt.Errorf("subscriptions: empty payload for account %s", accountID)
	}
	return portal, nil
}

// fetchCodexAccountsCheck performs the accounts/check GET and picks the
// account entry the credential actually bills against. Also returns the
// resolved account id so the caller can recover from a stale JWT claim.
func fetchCodexAccountsCheck(ctx context.Context, client *http.Client, token, accountID string) (
	*CodexEntitlement, *CodexBillingAccount, *CodexLastActiveSubscription, string, error) {

	body, err := codexBillingGET(ctx, client, token, accountID, codexAccountsCheckURL)
	if err != nil {
		return nil, nil, nil, "", err
	}
	return parseCodexAccountsCheck(body, accountID)
}

// parseCodexAccountsCheck holds the decode + account-selection logic, split
// from the HTTP call so the selection rules can be tested against captured
// payloads without a network stub.
func parseCodexAccountsCheck(body []byte, accountID string) (
	*CodexEntitlement, *CodexBillingAccount, *CodexLastActiveSubscription, string, error) {

	var envelope struct {
		Accounts map[string]struct {
			Account     *CodexBillingAccount         `json:"account"`
			Entitlement *CodexEntitlement            `json:"entitlement"`
			LastActive  *CodexLastActiveSubscription `json:"last_active_subscription"`
		} `json:"accounts"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, nil, nil, "", fmt.Errorf("accounts/check decode: %w", err)
	}
	if len(envelope.Accounts) == 0 {
		return nil, nil, nil, "", fmt.Errorf("accounts/check: no accounts in payload")
	}

	// Selection order. The map is keyed by account id AND carries a "default"
	// alias pointing at the same object, so on a personal account every path
	// lands on the same entry; the ordering only matters for tokens that can
	// see several accounts (personal + team), where billing the wrong one
	// would report someone else's plan.
	//   1. exact account id from the credential
	//   2. the "default" alias
	//   3. a paid, non-deactivated account
	//   4. anything not deactivated
	keys := []string{}
	if accountID != "" {
		keys = append(keys, accountID)
	}
	keys = append(keys, "default")
	for _, k := range keys {
		if e, ok := envelope.Accounts[k]; ok && e.Account != nil && !e.Account.IsDeactivated {
			return e.Entitlement, e.Account, e.LastActive, e.Account.AccountID, nil
		}
	}

	var fallback *CodexBillingAccount
	var fbEnt *CodexEntitlement
	var fbLast *CodexLastActiveSubscription
	for _, e := range envelope.Accounts {
		if e.Account == nil || e.Account.IsDeactivated {
			continue
		}
		paid := e.Entitlement != nil && e.Entitlement.HasActiveSubscription
		if paid {
			return e.Entitlement, e.Account, e.LastActive, e.Account.AccountID, nil
		}
		if fallback == nil {
			fallback, fbEnt, fbLast = e.Account, e.Entitlement, e.LastActive
		}
	}
	if fallback != nil {
		return fbEnt, fallback, fbLast, fallback.AccountID, nil
	}
	return nil, nil, nil, "", fmt.Errorf("accounts/check: every account is deactivated")
}

// codexBillingGET issues one authorised GET against a chatgpt.com backend-api
// billing endpoint and returns the raw body.
//
// Header note: unlike wham/usage — which the Codex CLI itself calls, so
// FetchCodexUsage sends the CLI's captured minimal header set — these two
// endpoints are only ever reached from the *web portal*, so the request is
// presented as a browser XHR from chatgpt.com.
//
// The User-Agent is not optional here. Leaving it unset does not omit it: Go
// fills in "Go-http-client/1.1", which on an OAuth subscription account is the
// loudest possible third-party signal — and pairing it with browser Referer /
// Sec-Fetch markers is *more* anomalous than either alone, since no real client
// sends that combination. browserUA is the same Chrome UA applyCodexWhamHeaders
// uses, chosen so the UA agrees with this package's HelloChrome_Auto uTLS
// fingerprint rather than contradicting it at the TLS layer.
//
// Origin is deliberately absent: browsers do not send it on a same-origin GET,
// and these calls are same-origin from chatgpt.com. There is no request capture
// for these endpoints (docs/codex-subscription.md captures responses only), so
// this follows browser behaviour rather than a recording — replace it with a
// capture if one is ever taken.
func codexBillingGET(ctx context.Context, client *http.Client, token, accountID, endpoint string) ([]byte, error) {
	buildReq := func() (*http.Request, error) {
		r, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, err
		}
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Accept", "application/json")
		r.Header.Set("Accept-Encoding", "identity")
		r.Header.Set("Accept-Language", browserAcceptLanguage)
		r.Header.Set("User-Agent", browserUA)
		r.Header.Set("Sec-Ch-Ua", browserSecChUA)
		r.Header.Set("Sec-Ch-Ua-Mobile", "?0")
		r.Header.Set("Sec-Ch-Ua-Platform", `"Linux"`)
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		r.Header.Set("Sec-Fetch-Mode", "cors")
		r.Header.Set("Sec-Fetch-Dest", "empty")
		r.Header.Set("Referer", "https://chatgpt.com/")
		if accountID != "" {
			r.Header.Set("Chatgpt-Account-Id", accountID)
		}
		return r, nil
	}

	// Retry policy mirrors FetchCodexUsage exactly: transport flaps only,
	// never a non-2xx (401/403/429 are upstream signals the caller must see).
	var resp *http.Response
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt) * 250 * time.Millisecond):
			}
		}
		req, err := buildReq()
		if err != nil {
			return nil, err
		}
		resp, err = client.Do(req)
		if err == nil {
			lastErr = nil
			break
		}
		lastErr = err
		if !isRetryableCodexUsageErr(err) {
			break
		}
	}
	if lastErr != nil {
		return nil, fmt.Errorf("%s GET: %w", shortEndpoint(endpoint), lastErr)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet := string(body)
		if len(snippet) > 300 {
			snippet = snippet[:300] + "...(truncated)"
		}
		return nil, fmt.Errorf("%s HTTP %d: %s", shortEndpoint(endpoint), resp.StatusCode, snippet)
	}
	return body, nil
}

func shortEndpoint(endpoint string) string {
	if i := strings.Index(endpoint, "/backend-api/"); i >= 0 {
		s := endpoint[i+len("/backend-api/"):]
		if j := strings.IndexByte(s, '?'); j >= 0 {
			s = s[:j]
		}
		return s
	}
	return endpoint
}

// --- Derived helpers -------------------------------------------------------
//
// These exist so every consuming fork renders the same answer to the same
// question. "Is this free?" in particular has two independent sources
// (gratis flag vs 100%-off discount) and getting it wrong misreports cost.

// PurchasedAt reports when the current paid term began — the answer to
// "when was this credential last topped up". Zero time = unknown.
func (s *CodexSubscriptionInfo) PurchasedAt() time.Time {
	if s == nil {
		return time.Time{}
	}
	if s.Portal != nil && !s.Portal.ActiveStart.IsZero() {
		return s.Portal.ActiveStart
	}
	// accounts/check has no term start; renews_at minus one period is not
	// reliable across plan changes, so report unknown rather than guess.
	return time.Time{}
}

// ExpiresAt reports when the current term lapses. Zero time = unknown.
func (s *CodexSubscriptionInfo) ExpiresAt() time.Time {
	if s == nil {
		return time.Time{}
	}
	if s.Portal != nil && !s.Portal.ActiveUntil.IsZero() {
		return s.Portal.ActiveUntil
	}
	if s.Entitlement != nil && s.Entitlement.ExpiresAt != nil {
		return *s.Entitlement.ExpiresAt
	}
	return time.Time{}
}

// Plan reports the plan tier ("plus", "pro", "free", …), preferring the
// billing endpoints over the possibly-stale JWT claim.
func (s *CodexSubscriptionInfo) Plan() string {
	if s == nil {
		return ""
	}
	if s.Portal != nil && s.Portal.PlanType != "" {
		return s.Portal.PlanType
	}
	if s.Account != nil && s.Account.PlanType != "" {
		return s.Account.PlanType
	}
	return ""
}

// IsFree reports whether the current term costs nothing, and why. A term is
// free either because it is comped outright (gratis) or because a 100%
// discount is applied — the two are separate fields upstream and an account
// can be free via the second while gratis is false, which is exactly what a
// promo like "plus-1-month-free" looks like.
func (s *CodexSubscriptionInfo) IsFree() (free bool, reason string) {
	if s == nil || s.Entitlement == nil {
		return false, ""
	}
	if s.Entitlement.IsActiveSubscriptionGratis {
		return true, "gratis"
	}
	if d := s.Entitlement.Discount; d != nil && d.DiscountType == "percentage" && d.Amount >= 100 {
		if d.PromoCampaignID != "" {
			return true, "promo:" + d.PromoCampaignID
		}
		return true, "discount:100%"
	}
	return false, ""
}

// AtRisk reports whether the subscription will stop working soon for a
// *billing* reason — it is delinquent, or it is set not to renew. The
// deadline is the grace-period end for a delinquent account, otherwise the
// term end. Callers use this to warn before a credential silently drops out
// of the pool, which quota-based health checks cannot predict.
func (s *CodexSubscriptionInfo) AtRisk() (atRisk bool, reason string, deadline time.Time) {
	if s == nil {
		return false, "", time.Time{}
	}
	delinquent := (s.Portal != nil && s.Portal.IsDelinquent) ||
		(s.Entitlement != nil && s.Entitlement.IsDelinquent)
	if delinquent {
		var grace *int64
		if s.Portal != nil && s.Portal.GracePeriodEndTimestamp != nil {
			grace = s.Portal.GracePeriodEndTimestamp
		} else if s.Entitlement != nil && s.Entitlement.GracePeriodEndTimestamp != nil {
			grace = s.Entitlement.GracePeriodEndTimestamp
		}
		if grace != nil && *grace > 0 {
			return true, "delinquent", time.Unix(*grace, 0)
		}
		return true, "delinquent", s.ExpiresAt()
	}
	// will_renew has two reporters; trust either saying "no". Note this must
	// not additionally require a Portal: /subscriptions needs an account_id
	// that some credentials do not carry, and that is exactly the case where
	// last_active_subscription is the only reporter there is.
	noRenew := (s.Portal != nil && !s.Portal.WillRenew) ||
		(s.LastActive != nil && !s.LastActive.WillRenew)
	if !noRenew {
		return false, "", time.Time{}
	}
	// A term that will not renew only matters if there is a term to lose, and
	// a warning is only actionable if it says when. A never-paid free account
	// satisfies "will_renew == false" trivially and has no term end, so the
	// known-deadline requirement is what keeps it from being reported as
	// about to lapse — which it was, complete with a zero-value date.
	deadline = s.ExpiresAt()
	if deadline.IsZero() {
		return false, "", time.Time{}
	}
	if s.Entitlement != nil && !s.Entitlement.HasActiveSubscription {
		return false, "", time.Time{}
	}
	return true, "will_not_renew", deadline
}
