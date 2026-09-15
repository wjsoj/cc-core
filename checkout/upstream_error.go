package checkout

import (
	"fmt"
	"net/http"
	"strings"
)

// UpstreamError contains only bounded classifications, never upstream bodies,
// URLs, credentials, card data or request IDs. Callers may use errors.As.
// No classification authorizes retrying a financial request.
type UpstreamError struct {
	Operation string
	Kind      string
	Status    int
}

func (e *UpstreamError) Error() string {
	message := "上游拒绝请求"
	switch e.Kind {
	case "authentication":
		message = "登录授权未通过，请在官方页面重新登录"
	case "forbidden":
		message = "上游拒绝访问；仅凭 403 无法确定原因，请在官方页面核验"
	case "challenge":
		message = "上游要求浏览器验证，请在官方页面手动完成验证"
	case "rate_limited":
		message = "上游限流，请稍后查询状态"
	case "network":
		message = "所选网络请求失败"
	case "invalid_response":
		message = "上游未返回有效 JSON 数据"
	}
	status := ""
	if e.Status != 0 {
		status = fmt.Sprintf(" (HTTP %d)", e.Status)
	}
	return e.Operation + "：" + message + status + "；未确认支付成功，如已提交付款只能查询状态，勿重复支付"
}

func paymentOperation(host, path string) string {
	if host == "api.stripe.com" {
		if path == "/v1/confirmation_tokens" {
			return "创建卡片令牌"
		}
		if strings.HasPrefix(path, "/v1/payment_intents/") && strings.HasSuffix(path, "/confirm") {
			return "确认 Stripe 付款"
		}
		return "Stripe 请求"
	}
	switch path {
	case "/backend-api/payments/checkout":
		return "创建结账"
	case "/backend-api/payments/checkout/taxes":
		return "获取含税报价"
	case "/backend-api/payments/checkout/confirm":
		return "确认结账"
	default:
		return "查询结账状态"
	}
}

func paymentFailure(operation string, status int, headers http.Header) *UpstreamError {
	kind := "rejected"
	switch status {
	case http.StatusUnauthorized:
		kind = "authentication"
	case http.StatusForbidden:
		kind = "forbidden"
	case http.StatusTooManyRequests:
		kind = "rate_limited"
	}
	// An HTML response alone is not proof of a challenge or its provider.
	// Use only the explicit response marker, without handling the challenge.
	if headers.Get("Cf-Mitigated") == "challenge" {
		kind = "challenge"
	}
	return &UpstreamError{Operation: operation, Kind: kind, Status: status}
}
