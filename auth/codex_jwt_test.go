package auth

import (
	"encoding/base64"
	"testing"
	"time"
)

// makeJWT builds a signature-less-but-well-formed JWT around a payload. The
// parsers deliberately do not verify signatures (the token arrived over TLS
// straight from auth.openai.com), so a placeholder third segment is enough.
func makeJWT(payload string) string {
	enc := func(s string) string {
		return base64.RawURLEncoding.EncodeToString([]byte(s))
	}
	return enc(`{"alg":"RS256","typ":"JWT"}`) + "." + enc(payload) + ".sig"
}

// Claim shape from crack/codexapp0.147.0/rows/02-jwt-claims-oauth-token-response.json.
const capturedIDTokenPayload = `{
  "email": "user@example.com",
  "email_verified": true,
  "sub": "auth0|abc",
  "https://api.openai.com/auth": {
    "chatgpt_account_id": "460c07ab-2d26-423b-b687-8ed83a562cb8",
    "chatgpt_plan_type": "plus",
    "chatgpt_user_id": "user-Hl",
    "chatgpt_subscription_active_start": "2026-07-14T00:00:00Z",
    "chatgpt_subscription_active_until": "2026-09-14T00:00:00Z",
    "chatgpt_subscription_last_checked": "2026-08-14T16:28:44Z",
    "organizations": [
      {"id": "org-A", "is_default": false, "role": "member", "title": "Side Org"},
      {"id": "org-B", "is_default": true, "role": "owner", "title": "Main Org"}
    ]
  }
}`

func TestParseCodexIDTokenSubscriptionClaims(t *testing.T) {
	claims, err := ParseCodexIDToken(makeJWT(capturedIDTokenPayload))
	if err != nil {
		t.Fatalf("ParseCodexIDToken: %v", err)
	}
	if got := claims.AccountID(); got != "460c07ab-2d26-423b-b687-8ed83a562cb8" {
		t.Errorf("AccountID = %q", got)
	}
	if got := claims.PlanType(); got != "plus" {
		t.Errorf("PlanType = %q, want plus", got)
	}
	want := time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC)
	if got := claims.SubscriptionActiveUntil(); !got.Equal(want) {
		t.Errorf("SubscriptionActiveUntil = %v, want %v", got, want)
	}
	org, ok := claims.DefaultOrganization()
	if !ok {
		t.Fatal("DefaultOrganization not found")
	}
	if org.ID != "org-B" || org.Role != "owner" {
		t.Errorf("default org = %+v, want org-B/owner", org)
	}
}

// The claims are optional; an older token without them must still parse, and
// the accessors must degrade rather than panic.
func TestParseCodexIDTokenWithoutSubscriptionClaims(t *testing.T) {
	claims, err := ParseCodexIDToken(makeJWT(`{"email":"a@b.c","https://api.openai.com/auth":{"chatgpt_account_id":"acct"}}`))
	if err != nil {
		t.Fatalf("ParseCodexIDToken: %v", err)
	}
	if got := claims.SubscriptionActiveUntil(); !got.IsZero() {
		t.Errorf("missing claim must yield the zero time, got %v", got)
	}
	if _, ok := claims.DefaultOrganization(); ok {
		t.Error("no organizations claim must report none")
	}
}

// No is_default flag: fall back to the first entry rather than reporting none.
func TestDefaultOrganizationFallsBackToFirst(t *testing.T) {
	claims, err := ParseCodexIDToken(makeJWT(
		`{"https://api.openai.com/auth":{"organizations":[{"id":"org-1"},{"id":"org-2"}]}}`))
	if err != nil {
		t.Fatalf("ParseCodexIDToken: %v", err)
	}
	org, ok := claims.DefaultOrganization()
	if !ok || org.ID != "org-1" {
		t.Errorf("fallback org = %+v ok=%v, want org-1", org, ok)
	}
}

func TestSubscriptionActiveUntilRejectsGarbage(t *testing.T) {
	claims, err := ParseCodexIDToken(makeJWT(
		`{"https://api.openai.com/auth":{"chatgpt_subscription_active_until":"not-a-time"}}`))
	if err != nil {
		t.Fatalf("ParseCodexIDToken: %v", err)
	}
	if got := claims.SubscriptionActiveUntil(); !got.IsZero() {
		t.Errorf("unparseable claim must yield the zero time, got %v", got)
	}
}

// The access token carries chatgpt_account_id under the same namespace. This is
// the fallback that stops AccountID going stale when a refresh returns no
// id_token.
func TestParseCodexAccessToken(t *testing.T) {
	payload := `{
      "https://api.openai.com/auth": {
        "chatgpt_account_id": "acct-from-access",
        "chatgpt_plan_type": "pro",
        "chatgpt_user_id": "user-1"
      },
      "https://api.openai.com/profile": {"email": "from-access@example.com"}
    }`
	claims, err := ParseCodexAccessToken(makeJWT(payload))
	if err != nil {
		t.Fatalf("ParseCodexAccessToken: %v", err)
	}
	if got := claims.AccountID(); got != "acct-from-access" {
		t.Errorf("AccountID = %q", got)
	}
	if got := claims.PlanType(); got != "pro" {
		t.Errorf("PlanType = %q, want pro", got)
	}
	if got := claims.Email(); got != "from-access@example.com" {
		t.Errorf("Email = %q", got)
	}
}

func TestCodexJWTParsersRejectMalformed(t *testing.T) {
	for _, tok := range []string{"", "onlyonepart", "two.parts", "a.!!!notbase64!!!.c"} {
		if _, err := ParseCodexIDToken(tok); err == nil {
			t.Errorf("ParseCodexIDToken(%q) should fail", tok)
		}
		if _, err := ParseCodexAccessToken(tok); err == nil {
			t.Errorf("ParseCodexAccessToken(%q) should fail", tok)
		}
	}
}
