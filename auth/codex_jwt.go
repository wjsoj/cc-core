package auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// CodexIDTokenClaims captures the claims we actually consume from an OpenAI
// ID token. The full payload has many more fields — we only parse what we
// route on so we don't couple to the provider's JWT schema beyond need.
type CodexIDTokenClaims struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Sub           string `json:"sub"`
	// Custom claim namespace OpenAI uses for Codex-specific fields.
	//
	// The subscription and organization claims are present on the ID TOKEN only
	// (crack/codexapp0.147.0/rows/02-jwt-claims-oauth-token-response.json). They
	// are free: the token is already in hand, whereas FetchCodexSubscription has
	// to call a web-portal endpoint that is the most risk-exposed probe we run.
	// This is a fallback source, not a replacement — the claims are frozen at
	// issue time and an ID token lives one hour, so a token minted before a
	// billing change will not reflect it.
	CodexAuthInfo struct {
		ChatgptAccountID string `json:"chatgpt_account_id"`
		ChatgptPlanType  string `json:"chatgpt_plan_type"`
		ChatgptUserID    string `json:"chatgpt_user_id"`

		// RFC3339 timestamps describing the current subscription term.
		SubscriptionActiveStart string `json:"chatgpt_subscription_active_start"`
		SubscriptionActiveUntil string `json:"chatgpt_subscription_active_until"`
		SubscriptionLastChecked string `json:"chatgpt_subscription_last_checked"`

		Organizations []CodexOrganization `json:"organizations"`
	} `json:"https://api.openai.com/auth"`
}

// CodexOrganization is one entry of the id_token's organizations[] claim.
type CodexOrganization struct {
	ID        string `json:"id"`
	IsDefault bool   `json:"is_default"`
	Role      string `json:"role"`
	Title     string `json:"title"`
}

// SubscriptionActiveUntil returns the end of the current subscription term, or
// the zero time when the claim is absent or unparseable.
//
// A credential whose term has lapsed keeps serving traffic until upstream
// decides otherwise, so this is a scheduling HINT, never a health signal — the
// same rule that governs the portal probes. Nothing here may reach MarkFailure.
func (c *CodexIDTokenClaims) SubscriptionActiveUntil() time.Time {
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(c.CodexAuthInfo.SubscriptionActiveUntil))
	if err != nil {
		return time.Time{}
	}
	return t
}

// DefaultOrganization returns the org marked is_default, falling back to the
// first entry. Empty when the claim carried none.
func (c *CodexIDTokenClaims) DefaultOrganization() (CodexOrganization, bool) {
	orgs := c.CodexAuthInfo.Organizations
	for _, o := range orgs {
		if o.IsDefault {
			return o, true
		}
	}
	if len(orgs) > 0 {
		return orgs[0], true
	}
	return CodexOrganization{}, false
}

// CodexAccessTokenClaims captures the claims the ACCESS token carries under the
// same namespace.
//
// This exists because the access token is the one thing a refresh is guaranteed
// to return. A refresh response that omits id_token used to leave AccountID
// pinned at its old value forever, since it was only ever read from the ID
// token — and the access token has carried chatgpt_account_id all along
// (crack/codexapp0.147.0/rows/02).
type CodexAccessTokenClaims struct {
	CodexAuthInfo struct {
		ChatgptAccountID string `json:"chatgpt_account_id"`
		ChatgptPlanType  string `json:"chatgpt_plan_type"`
		ChatgptUserID    string `json:"chatgpt_user_id"`
	} `json:"https://api.openai.com/auth"`
	Profile struct {
		Email string `json:"email"`
	} `json:"https://api.openai.com/profile"`
}

// AccountID returns the ChatGPT account ID from the access token, or empty.
func (c *CodexAccessTokenClaims) AccountID() string { return c.CodexAuthInfo.ChatgptAccountID }

// PlanType returns the raw subscription plan from the access token, or empty.
func (c *CodexAccessTokenClaims) PlanType() string { return c.CodexAuthInfo.ChatgptPlanType }

// Email returns the profile email from the access token, or empty.
func (c *CodexAccessTokenClaims) Email() string { return c.Profile.Email }

// ParseCodexAccessToken decodes an access token's payload without verifying its
// signature, for the same reason ParseCodexIDToken does: it arrived over TLS
// directly from auth.openai.com, which already signed it.
func ParseCodexAccessToken(token string) (*CodexAccessTokenClaims, error) {
	payload, err := codexJWTPayload(token)
	if err != nil {
		return nil, err
	}
	var claims CodexAccessTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("unmarshal JWT claims: %w", err)
	}
	return &claims, nil
}

// AccountID returns the ChatGPT account ID from the token, or empty string.
func (c *CodexIDTokenClaims) AccountID() string { return c.CodexAuthInfo.ChatgptAccountID }

// PlanType returns the subscription plan (free/plus/pro/team/business/...)
// in its raw case; normalization to our canonical ids happens at routing
// time in auth.NormalizeCodexPlan.
func (c *CodexIDTokenClaims) PlanType() string { return c.CodexAuthInfo.ChatgptPlanType }

// ParseCodexIDToken decodes a JWT **without** verifying its signature — the
// caller has just received the token from auth.openai.com over TLS, so the
// signature has already been checked by the issuer. This mirrors the Codex
// CLI's own behavior.
func ParseCodexIDToken(token string) (*CodexIDTokenClaims, error) {
	payload, err := codexJWTPayload(token)
	if err != nil {
		return nil, err
	}
	var claims CodexIDTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("unmarshal JWT claims: %w", err)
	}
	return &claims, nil
}

// codexJWTPayload splits a JWT and base64url-decodes its payload segment.
// Shared by the id_token and access_token parsers so the two cannot drift.
func codexJWTPayload(token string) ([]byte, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT: expected 3 parts, got %d", len(parts))
	}
	payload, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode JWT payload: %w", err)
	}
	return payload, nil
}

func base64URLDecode(s string) ([]byte, error) {
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}

// Canonical Codex plan identifiers — match CLIProxyAPI's tier buckets so the
// same model sets apply. "go" is OpenAI's internal label for Team.
const (
	CodexPlanFree = "free"
	CodexPlanPlus = "plus"
	CodexPlanPro  = "pro"
	CodexPlanTeam = "team"
)

// NormalizeCodexPlan collapses OpenAI's plan labels into the four tiers our
// pricing/model-visibility logic cares about. Unknown values default to
// "pro" — matches CLIProxyAPI's default for safety (don't accidentally
// restrict a Team/Enterprise account to the Free model list).
func NormalizeCodexPlan(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "free":
		return CodexPlanFree
	case "plus":
		return CodexPlanPlus
	case "pro":
		return CodexPlanPro
	case "team", "business", "go":
		return CodexPlanTeam
	case "":
		return CodexPlanPro
	default:
		return CodexPlanPro
	}
}
