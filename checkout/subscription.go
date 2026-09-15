package checkout

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

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
	info, err := auth.FetchCodexSubscriptionWithClient(ctx, c.http, a.Token, a.AccountID,
		auth.SubscriptionBrowserContext{TimezoneOffsetMinutes: a.TimezoneOffsetMinutes})
	if err != nil {
		// The shared admin probe includes upstream snippets and transport errors.
		// They can contain HTML, endpoint URLs and proxy credentials; never send
		// those verbatim through GPTPay's public API.
		codes := subscriptionHTTPStatus.FindAllString(err.Error(), -1)
		if len(codes) > 0 {
			return nil, fmt.Errorf("订阅查询被上游拒绝（%s）；未获取到账单数据", strings.Join(codes, ", "))
		}
		if ctx.Err() != nil {
			return nil, errors.New("订阅查询超时或已取消；未获取到账单数据")
		}
		return nil, errors.New("订阅查询网络或响应解析失败；未获取到账单数据")
	}
	return info, nil
}

var subscriptionHTTPStatus = regexp.MustCompile(`HTTP [1-5][0-9]{2}`)
