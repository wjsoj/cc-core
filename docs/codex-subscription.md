# ChatGPT subscription / billing probe

`auth/codex_subscription.go` — `(*Auth).FetchCodexSubscription`

## What it answers

`FetchCodexUsage` (wham/usage) answers **"how much quota is left in the current
window"**. It says nothing about the commercial state of the account. This probe
answers the other half:

- **When was this credential last paid for?** (`active_start` — the current term's start)
- **Which tier?** (`plus` / `pro` / …, plus the finer-grained `chatgptplusplan`)
- **Monthly or yearly?** (`billing_period`)
- **Will it renew, or is it cancelled at term end?** (`will_renew`)
- **Is it actually free, and why?** (gratis flag vs a 100%-off promo)
- **Is it about to die for billing reasons?** (`is_delinquent` + grace period)

That last one matters operationally: a delinquent account keeps serving traffic
normally until its grace period ends, then loses entitlement. No quota-based or
health-based signal in the pool can predict that — only this probe can.

## Upstream endpoints

Both are plain `GET`s authorised by the OAuth access token the pool already
holds. No extra cookie, no separate login, no scraping.

| Endpoint | Gives | Notes |
|---|---|---|
| `GET /backend-api/subscriptions?account_id=<id>` | `active_start`, `active_until`, `billing_period`, `will_renew`, seats, delinquency | **`account_id` is mandatory.** Without it the endpoint answers `200` with an error envelope, not a payload. |
| `GET /backend-api/accounts/check/v4-2023-04-27` | `entitlement` (discounts, trial, expiry), `account` (created_time, previously-paid), `last_active_subscription` (purchase platform) | Account-scoped via a map keyed by account id, with a `"default"` alias. |

Neither is a superset of the other:

- `active_start` and seat counts exist **only** on `/subscriptions`.
- the discount block, `created_time`, and `has_previously_paid_subscription`
  exist **only** on `accounts/check`.

Hence one call fetches both and merges. **Partial success is a success** — the
two fail independently and either alone is worth rendering. `FetchCodexSubscription`
returns an error only when *both* fail, wrapping both causes.

## Captured payloads (ground truth)

From a live Plus account on 2026-08-07, identifiers replaced. These are pinned
verbatim in `auth/codex_subscription_test.go`; treat them the way `crack/` specs
are treated — the struct field names are downstream of these captures.

`GET /backend-api/subscriptions?account_id=…`:

```json
{
  "id": "sub-0000", "plan_type": "plus",
  "seats_in_use": 1, "seats_entitled": 1,
  "active_start": "2026-08-04T10:22:17Z",
  "active_until": "2026-09-04T10:22:17Z",
  "billing_period": "monthly", "billing_currency": "USD",
  "will_renew": true, "cancellation_outcome": null,
  "is_delinquent": false, "is_processor_stripe": true,
  "became_delinquent_timestamp": null, "grace_period_end_timestamp": null
}
```

`accounts/check` → `accounts["<id>"].entitlement` for the same account:

```json
{
  "subscription_id": "sub-0000",
  "has_active_subscription": true,
  "is_active_subscription_gratis": false,
  "subscription_plan": "chatgptplusplan",
  "expires_at": "2026-09-04T16:22:17+00:00",
  "renews_at": "2026-09-04T10:22:17+00:00",
  "billing_period": "monthly", "billing_currency": "USD",
  "discount": {
    "discount_type": "percentage", "amount": 100,
    "duration_num_periods": 1,
    "discount_expires_at": "2026-09-04T10:22:17+00:00",
    "cancellation_policy": "term_end",
    "promo_campaign_id": "plus-1-month-free"
  },
  "trial": null, "is_delinquent": false
}
```

and `accounts["<id>"].last_active_subscription`:

```json
{ "subscription_id": "sub-0000", "purchase_origin_platform": "chatgpt_web",
  "will_renew": true, "cancellation_outcome": null }
```

## Usage

```go
info, err := a.FetchCodexSubscription(ctx, pool.UseUTLS())
if err != nil {
    // both endpoints failed — surface it, don't fail the credential
}
purchased := info.PurchasedAt()   // 2026-08-04T10:22:17Z
expires   := info.ExpiresAt()
tier      := info.Plan()          // "plus"
free, why := info.IsFree()        // true, "promo:plus-1-month-free"
risk, reason, deadline := info.AtRisk()
```

The result is also stored on the credential (`a.CodexSubscription`,
`a.CodexSubscriptionAt`) and exposed through `a.Snapshot()` as
`AuthInfo.CodexSubscription` — same pointer-swap discipline as `CodexUsage`, so
a snapshot holder always sees a consistent object.

### Why the helpers exist

They encode answers that are easy to get wrong from raw fields, so both forks
render the same thing:

- **`IsFree()`** — a term is free either because it is comped
  (`is_active_subscription_gratis`) **or** because a 100% discount is applied.
  These are independent fields. The captured account above has
  `gratis: false` while paying **$0**; reading only the gratis flag reports it
  as a paying account. The returned reason distinguishes the two
  (`"gratis"` vs `"promo:<campaign>"`).
- **`AtRisk()`** — folds delinquency and cancelled-renewal into one warning
  with the right deadline (grace-period end when delinquent, term end when
  merely not renewing). Two rules keep the non-delinquent half honest, both
  regression-tested:
  - `will_renew` is read from *either* reporter — `/subscriptions` or
    `last_active_subscription`. It must not additionally require the portal:
    a credential with no account id never gets a portal payload, and that is
    exactly when `last_active_subscription` is the only reporter there is.
  - A cancelled renewal is reported only when the term end is **known** and the
    entitlement is not already inactive. A never-paid free account satisfies
    `will_renew == false` trivially and has no term to lose; without the
    known-deadline rule every free credential in a pool warns that it is about
    to lapse, dated `0001-01-01`.
- **`PurchasedAt()`** — returns zero rather than deriving a term start from
  `renews_at` when `/subscriptions` was unavailable. A derived date would be
  wrong across a plan change, and a wrong purchase date is worse than none.

## Exposing it as an admin endpoint in a fork

cc-core is a library with no HTTP surface. Mirror the existing
`POST /auths/:id/codex-usage` handler (`internal/admin/admin.go` in both forks):

```go
api.POST("/auths/:id/codex-subscription", h.handleCodexSubscription)

func (h *Handler) handleCodexSubscription(c *gin.Context) {
	a := h.pool.FindByID(c.Param("id"))
	if a == nil || a.Kind != auth.KindOAuth {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "oauth credential not found"})
		return
	}
	if auth.NormalizeProvider(a.Provider) != auth.ProviderOpenAI {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "codex-subscription endpoint is OpenAI-only"})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()
	info, err := a.FetchCodexSubscription(ctx, h.pool.UseUTLS())
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"subscription": info})
}
```

Billing state changes at most once a month, so **do not poll it on the
`codexquota` cadence.** A manual refresh button plus a daily background pass is
the right shape; anything faster is wasted requests against an endpoint the
CLI never touches.

## Traps

- **`account_id` is mandatory on `/subscriptions`.** Omitting it returns `200`
  with `{"detail": …}`. The code therefore treats an empty `id`+`plan_type` as
  failure rather than trusting the status code.
- **Two timestamp formats.** `/subscriptions` emits `…Z`; `accounts/check`
  emits `…+00:00`. Both are RFC3339 and both parse into `time.Time`, but a
  hand-rolled `strings.HasSuffix(s, "Z")` check would break on one of them.
- **Unix seconds vs RFC3339 in the same feature.** `grace_period_end_timestamp`
  and `became_delinquent_timestamp` are unix seconds (`*int64`), while every
  other time here is an RFC3339 string. That asymmetry is upstream's, kept
  verbatim rather than normalised so the structs stay a mirror of the JSON.
- **`accounts/check` returns the same account twice** — once under its id and
  once under `"default"`. Harmless for personal accounts; for a token that can
  see several accounts (personal + team) the selection order matters, or the
  panel reports someone else's plan. Order: exact id → `"default"` → any paid
  non-deactivated → any non-deactivated.
- **Headers follow the *browser*, not the CLI — including the User-Agent.**
  wham/usage is called by the real Codex CLI, so `FetchCodexUsage` mirrors the
  CLI's captured header set. These two endpoints are only ever reached from the
  web portal, so the request is presented as a browser XHR: `browserUA` (the
  same Chrome UA `applyCodexWhamHeaders` uses, chosen to agree with this
  package's HelloChrome_Auto uTLS fingerprint), `Sec-Ch-Ua*`, `Sec-Fetch-*`,
  and `Referer`. **Leaving User-Agent unset does not omit it** — Go substitutes
  `Go-http-client/1.1`, which on an OAuth subscription account is the loudest
  third-party signal there is, and pairing it with browser `Referer` markers is
  more anomalous than either alone. `TestCodexBillingRequestIdentity` pins this.
  `Origin` is deliberately absent: browsers do not send it on a same-origin GET.
  There is no request-header capture for these endpoints (the captures below are
  responses only), so this follows browser behaviour rather than a recording —
  replace it if a capture is ever taken, and do not "unify" it with the CLI set
  without one showing the CLI calling these endpoints.
- **A failed probe must never touch credential health.** Same rule as
  `FetchCodexUsage`: no `MarkFailure`, no cooldown. Delinquency is surfaced for
  a human, not used to auto-disable — the grace period means a delinquent
  account still serves traffic correctly.

## Not covered: payment history

The per-invoice ledger (amount charged, paid-at, PDF) lives at
`GET /backend-api/invoices?account_id=<id>` and returns Stripe invoice objects
— enough to reconstruct exactly what was paid and when, including the
discount lines that make a term free. It is **deliberately not implemented
here**: it answers a finance question rather than a scheduling one, and its
payload is an order of magnitude larger than the subscription view. Add it as a
separate probe if a fork ever needs cost accounting rather than plan state.

Also observed and deliberately **not** wired: `GET /backend-api/payments/customer_portal`
returns a live Stripe billing-portal session URL that can cancel the
subscription or change the payment method. Never expose that through an admin
panel.
