package auth

import (
	"encoding/json"
	"net/http"
	"strings"
)

// SetExplicitFailuresOnly changes an API-key channel's pause policy. It does
// not clear an existing pause; recovery remains an explicit operator action.
func (a *Auth) SetExplicitFailuresOnly(v bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.ExplicitFailuresOnly = v
}

// ShouldPauseForAPIKeyError separates retrying a failed request from pausing
// the entire relay. Opted-in relays retain authentication, balance and explicit
// throttling protection, but model availability, transport faults, unclassified
// 5xx and missing usage are not evidence that every model on the key is broken.
// Legacy credentials and OAuth retain their existing health policy.
func (a *Auth) ShouldPauseForAPIKeyError(status int, payload []byte) bool {
	a.mu.RLock()
	explicit := a.Kind == KindAPIKey && a.ExplicitFailuresOnly
	a.mu.RUnlock()
	if !explicit {
		return true
	}
	switch status {
	case http.StatusUnauthorized, http.StatusPaymentRequired, http.StatusTooManyRequests:
		return true
	}
	var body struct {
		Code    string          `json:"code"`
		Message string          `json:"message"`
		Error   json.RawMessage `json:"error"`
	}
	if json.Unmarshal(payload, &body) != nil {
		return false
	}
	var nested struct {
		Code    string `json:"code"`
		Type    string `json:"type"`
		Message string `json:"message"`
	}
	_ = json.Unmarshal(body.Error, &nested)
	for _, code := range []string{body.Code, nested.Code, nested.Type} {
		switch strings.ToLower(strings.TrimSpace(code)) {
		case "invalid_api_key", "invalid_api_token", "api_key_invalid", "token_revoked", "authentication_error", "insufficient_balance", "insufficient_quota", "account_deactivated", "organization_deactivated", "billing_hard_limit_reached", "credit_balance_exhausted", "rate_limit_exceeded":
			return true
		}
	}
	// Some relays use new_api_error for every failure; their balance rejection
	// is explicit only in the message. Do not inspect unrelated request fields.
	message := strings.ToLower(body.Message + " " + nested.Message)
	for _, marker := range []string{"insufficient account balance", "insufficient credit balance", "insufficient balance", "余额不足", "预扣费额度失败"} {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}
