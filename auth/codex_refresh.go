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

	log "github.com/sirupsen/logrus"
)

// OpenAI (Codex) OAuth constants. Mirrors the ChatGPT Codex CLI — see
// CLIProxyAPI/internal/auth/codex/openai_auth.go for provenance.
const (
	openaiTokenURL = "https://auth.openai.com/oauth/token"
	openaiClientID = "app_EMoamEEZ73f0CkXaXp7hrann"
)

// refreshCodexLocked refreshes an OpenAI/ChatGPT OAuth access token. Also
// reparses the returned id_token so plan_type / account_id / email stay in
// sync with whatever the upstream reports now (subscription tier can change
// between refreshes). Caller must hold a.refreshMu.
func (a *Auth) refreshCodexLocked(ctx context.Context, useUTLS bool) error {
	a.mu.RLock()
	refresh := a.RefreshToken
	a.mu.RUnlock()
	if refresh == "" {
		return fmt.Errorf("no refresh token")
	}

	data := url.Values{
		"client_id":     {openaiClientID},
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
		"scope":         {"openid profile email"},
	}
	client := ClientFor(a.ProxyURL, useUTLS)

	// Build a fresh request per attempt — the url.Values body reader is
	// consumed on send and can't be replayed across retries.
	buildReq := func() (*http.Request, error) {
		r, rerr := http.NewRequestWithContext(ctx, http.MethodPost, openaiTokenURL, strings.NewReader(data.Encode()))
		if rerr != nil {
			return nil, rerr
		}
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Accept", "application/json")
		return r, nil
	}

	// Transient transport failures (CF edge RST mid-TLS handshake, a SOCKS5
	// proxy hiccup, a stale pooled h2 conn) are common on the chatgpt.com /
	// auth.openai.com path and do NOT mean the refresh_token is bad. Retry a
	// few times with backoff before giving up. Crucially, a transient failure
	// that survives retries must NOT MarkFailure: OAuth creds auto-promote to a
	// sticky hard-failure after `hardFailureThreshold` consecutive MarkFailures,
	// so a few minutes of proxy weather (the background refresher runs every
	// minute) used to strand an otherwise-valid Codex credential as a permanent
	// "session expired" until someone cleared it by hand.
	var resp *http.Response
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt) * 300 * time.Millisecond):
			}
		}
		req, berr := buildReq()
		if berr != nil {
			return berr
		}
		resp, lastErr = client.Do(req)
		if lastErr == nil {
			break
		}
		if !IsTransientNetErr(lastErr) {
			break
		}
	}
	if lastErr != nil {
		if IsTransientNetErr(lastErr) {
			// Don't retire the credential on wire weather — the refresher will
			// try again on its next tick. Surface the reason in the log only.
			log.Warnf("auth: codex refresh %s transient transport error (credential left healthy): %v", a.ID, lastErr)
			return fmt.Errorf("codex refresh %s: %w", a.ID, lastErr)
		}
		a.MarkFailure(fmt.Sprintf("codex refresh transport: %v", lastErr))
		return fmt.Errorf("codex refresh %s: %w", a.ID, lastErr)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		bodyStr := string(body)
		lower := strings.ToLower(bodyStr)
		switch {
		case strings.Contains(lower, "refresh_token_reused"), strings.Contains(lower, "refresh_token_invalidated"):
			// Burned / invalidated refresh token — terminal. OpenAI aggressively
			// rotates and treats a reused (or server-invalidated, e.g. "session
			// ended") refresh as evidence of token leakage. Require re-login
			// before this credential is used again.
			a.MarkHardFailure(fmt.Sprintf("codex refresh_token reused/invalidated: %s", bodyStr))
		case resp.StatusCode == http.StatusUnauthorized, resp.StatusCode == http.StatusBadRequest && strings.Contains(lower, "invalid_grant"):
			a.MarkHardFailure(fmt.Sprintf("codex refresh rejected (http %d): %s", resp.StatusCode, bodyStr))
		case resp.StatusCode == http.StatusTooManyRequests, resp.StatusCode >= 500:
			// Upstream-side transient (auth.openai.com 5xx / rate limit). Don't
			// escalate — same reasoning as the transport-error path above.
			log.Warnf("auth: codex refresh %s upstream transient http %d (credential left healthy)", a.ID, resp.StatusCode)
		default:
			a.MarkFailure(fmt.Sprintf("codex refresh http %d", resp.StatusCode))
		}
		return fmt.Errorf("codex refresh %s: http %d: %s", a.ID, resp.StatusCode, bodyStr)
	}
	var tr struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tr); err != nil {
		a.MarkFailure(fmt.Sprintf("codex refresh parse: %v", err))
		return fmt.Errorf("codex refresh %s: parse: %w", a.ID, err)
	}
	// Re-parse ID token for fresh plan_type / account_id / email.
	var planType, accountID, email string
	if tr.IDToken != "" {
		if claims, perr := ParseCodexIDToken(tr.IDToken); perr == nil && claims != nil {
			planType = claims.PlanType()
			accountID = claims.AccountID()
			email = claims.Email
		}
	}
	a.mu.Lock()
	a.AccessToken = tr.AccessToken
	if tr.RefreshToken != "" {
		a.RefreshToken = tr.RefreshToken
	}
	if tr.IDToken != "" {
		a.IDToken = tr.IDToken
	}
	if tr.ExpiresIn > 0 {
		a.ExpiresAt = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	}
	if planType != "" {
		a.PlanType = planType
	}
	if accountID != "" {
		a.AccountID = accountID
	}
	if email != "" && a.Email == "" {
		a.Email = email
	}
	a.mu.Unlock()
	a.MarkSuccess()
	if err := saveAuth(a); err != nil {
		log.Warnf("auth: persist refreshed codex token %s: %v", a.ID, err)
	} else {
		log.Infof("auth: refreshed codex %s (exp=%s plan=%s)", a.ID, a.ExpiresAt.Format(time.RFC3339), a.PlanType)
	}
	return nil
}
