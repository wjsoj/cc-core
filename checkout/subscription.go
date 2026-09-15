package checkout

import (
	"context"
	"errors"

	"github.com/wjsoj/cc-core/auth"
)

// Subscription answers a different question from Create/Quote/Pay: not "can
// this session buy a subscription" but "what does this account already have
// — has it ever paid, is a term active right now, what plan". It never
// creates a checkout session and never touches money.
//
// Reuses auth.FetchCodexSubscriptionWithClient — the same two-endpoint probe
// (chatgpt.com/backend-api/subscriptions + accounts/check) the admin panel's
// "which card pays for this Codex subscription" feature already runs against
// pooled OAuth credentials, through the entry point built for a bare token
// with no pool behind it. Same request shape, same partial-success handling,
// same decode quirks already hardened against a live delinquent account —
// this does not re-implement any of that.
//
// Uses c.http so the probe travels over whatever network path the caller
// already pinned for this visitor (SOCKS5 or direct) — never a path of its
// own choosing.
func (c *Client) Subscription(ctx context.Context, a Auth) (*auth.CodexSubscriptionInfo, error) {
	if !validToken(a.Token) {
		return nil, errors.New("登录态无效")
	}
	return auth.FetchCodexSubscriptionWithClient(ctx, c.http, a.Token, a.AccountID)
}
