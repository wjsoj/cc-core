package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/wjsoj/cc-core/mimicry"
)

// OpenAI (Codex) OAuth constants. Mirrors the ChatGPT Codex CLI — see
// CLIProxyAPI/internal/auth/codex/openai_auth.go for provenance.
const (
	openaiTokenURL = "https://auth.openai.com/oauth/token"
	openaiClientID = "app_EMoamEEZ73f0CkXaXp7hrann"
)

// maxReasonBodyBytes bounds how much of an upstream error body is retained on a
// credential. Long enough to keep the machine-readable `error`/`code` fields
// that classification and an operator both need, short enough that an echoed
// request or a stack trace cannot ride along.
const maxReasonBodyBytes = 256

// truncateForReason renders an upstream body for storage in a failure reason.
func truncateForReason(body []byte) string {
	s := strings.TrimSpace(string(body))
	if len(s) <= maxReasonBodyBytes {
		return s
	}
	return s[:maxReasonBodyBytes] + "… (truncated)"
}

// THE THREE GRANTS AT auth.openai.com/oauth/token DO NOT SHARE A REQUEST SHAPE.
//
// cc-core applied one helper to all of them on the assumption that they were
// identical. The Codex Desktop 0.153.4 capture
// (crack/codexapp0.153.4/rows/01, /02, /04, SPEC §2) disproves it:
//
//	grant                content-type                        identity headers
//	refresh_token        application/json                    originator + user-agent PRESENT
//	authorization_code   application/x-www-form-urlencoded   ABSENT
//	token-exchange       application/x-www-form-urlencoded   ABSENT
//
// Adding originator/UA to the auth-code leg is exactly as wrong as omitting
// them from the refresh leg — either way one request in the login flow has a
// header set no genuine client emits.
//
// Header ORDER differs too (refresh: content-type, accept, originator,
// user-agent, host, content-length; the others drop the middle pair). Go's
// Request.Write emits the header map alphabetically and there is no hook to
// reorder it short of the connection wrapper codexws/handshake_order.go uses
// for the WebSocket upgrade. The header SET is matched here; the order is not,
// and cannot be without that machinery.

// The refresh grant sends the FULL Desktop User-Agent, build parenthetical
// included.
//
// An earlier draft of the capture SPEC read the full-vs-base User-Agent split
// as a per-endpoint rule and put oauth/token on the base side. Re-reading the
// rows disproved that: most endpoints appear with BOTH forms in the same
// capture, and the two that never vary — oauth/token and the WebSocket upgrade
// — both use the full one. The split is almost certainly between two
// components of the Desktop app rather than between endpoints, which is not
// something a proxy can or should reproduce. See crack/codexapp0.153.4/SPEC.md
// §1.

// applyCodexRefreshGrantHeaders shapes the refresh_token grant (row `01`).
// This is the ONE grant that identifies itself: JSON body, Desktop originator,
// Desktop UA (the full one — see above).
func applyCodexRefreshGrantHeaders(req *http.Request) {
	// The identity comes from the ACTIVE profile, not from the captured one.
	//
	// crack/codexapp0.153.4/rows/01 shows a Codex Desktop refresh because the
	// client being captured was Desktop. What the row establishes is the
	// STRUCTURE — this grant, alone of the three, identifies itself with an
	// originator and a User-Agent. Which identity it uses is a property of the
	// client, and ours is whatever DefaultCodexProfile returns.
	//
	// Pinning Desktop here would mean forwarding traffic and opening WebSockets
	// as codex-tui while refreshing the same credential's token as Codex
	// Desktop: one account presenting two clients, which no real installation
	// does and which is a single join away from being obvious.
	profile := mimicry.DefaultCodexProfile()
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Originator", profile.Originator)
	req.Header.Set("User-Agent", profile.UserAgent)
}

// applyCodexFormGrantHeaders shapes the authorization_code and RFC 8693
// token-exchange grants (rows `02`, `04`): form-encoded, four headers, no
// identity at all.
//
// Two things are load-bearing:
//
//   - There is NO User-Agent. Leaving it unset is not neutral — net/http
//     substitutes "Go-http-client/1.1", which is the single loudest
//     third-party tell in the whole login flow. Deleting the key is also not
//     enough, and Set("User-Agent", "") is a no-op for the same reason: both
//     http1 Request.write and http2 encodeHeaders fall back to the default
//     when the key is ABSENT. Assigning a nil slice makes the key present
//     with no value, which is the documented way to suppress it entirely.
//     TestHeaderDelDoesNotSuppressGoUserAgent pins this.
//
//   - Accept is "*/*", not "application/json". The token endpoint answers
//     JSON regardless, so this only ever mattered as a fingerprint.
func applyCodexFormGrantHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header["User-Agent"] = nil
	req.Header.Set("Accept", "*/*")
}

// buildCodexRefreshBody renders the refresh_token grant body.
//
// A struct, not url.Values and not a map: the real client sends JSON with the
// fields in the order client_id, grant_type, refresh_token, and both
// alternatives destroy that (url.Values.Encode and json.Marshal over a map
// both sort keys). Struct field order is the marshal order — the same trick
// finishAnthropicLogin uses in login.go.
//
// There is NO `scope`. cc-core used to send "openid profile email"; the
// capture shows exactly three fields, and the authorization_code response
// grants a wider scope than was ever requested anyway, so re-asserting a
// narrower one on refresh was both a fingerprint tell and semantically wrong.
func buildCodexRefreshBody(refreshToken string) []byte {
	payload := struct {
		ClientID     string `json:"client_id"`
		GrantType    string `json:"grant_type"`
		RefreshToken string `json:"refresh_token"`
	}{
		ClientID:     openaiClientID,
		GrantType:    "refresh_token",
		RefreshToken: refreshToken,
	}
	buf, _ := json.Marshal(payload)
	return buf
}

// codexTokenResponse is the shape both the authorization_code and the
// refresh_token grants return. EarliestRefreshAt and OAIIS are the two fields
// cc-core dropped on the floor until the 0.153.4 capture; see the Auth struct
// for what they are for.
type codexTokenResponse struct {
	AccessToken       string `json:"access_token"`
	RefreshToken      string `json:"refresh_token"`
	IDToken           string `json:"id_token"`
	TokenType         string `json:"token_type"`
	ExpiresIn         int    `json:"expires_in"`
	EarliestRefreshAt int64  `json:"earliest_refresh_at"`
	OAIIS             string `json:"oai_is"`
}

// EarliestRefresh renders earliest_refresh_at as a time. Zero when the field
// was absent (older backends, or a response shape we have not captured).
func (r codexTokenResponse) EarliestRefresh() time.Time {
	if r.EarliestRefreshAt <= 0 {
		return time.Time{}
	}
	return time.Unix(r.EarliestRefreshAt, 0)
}

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

	body := buildCodexRefreshBody(refresh)
	client := ClientFor(a.ProxyURL, useUTLS)

	// Build a fresh request per attempt — the body reader is consumed on send
	// and can't be replayed across retries.
	buildReq := func() (*http.Request, error) {
		r, rerr := http.NewRequestWithContext(ctx, http.MethodPost, openaiTokenURL, bytes.NewReader(body))
		if rerr != nil {
			return nil, rerr
		}
		applyCodexRefreshGrantHeaders(r)
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
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		// Classify on the FULL body, but never store or return it whole.
		//
		// Whatever goes into MarkHardFailure/MarkFailure lands in
		// LastFailureReason, which Snapshot() surfaces to the admin panel, and
		// the returned error may be bubbled into a client-facing response by a
		// consumer. auth.openai.com's rejections can echo request context back,
		// so an unbounded copy of a token-endpoint body is the wrong thing to
		// keep on a credential record.
		lower := strings.ToLower(string(respBody))
		bodyStr := truncateForReason(respBody)
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
	var tr codexTokenResponse
	if err := json.Unmarshal(respBody, &tr); err != nil {
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
	// Fall back to the ACCESS token for anything the ID token did not supply.
	//
	// A refresh is only guaranteed to return an access_token; id_token is
	// optional, and when it is absent the fields above stay empty and the
	// credential keeps whatever it was created with — so a plan upgrade or an
	// account migration would never be picked up. The access token carries
	// chatgpt_account_id / chatgpt_plan_type under the same claim namespace
	// (crack/codexapp0.147.0/rows/02), so there is no reason to go stale.
	if planType == "" || accountID == "" || email == "" {
		if claims, perr := ParseCodexAccessToken(tr.AccessToken); perr == nil && claims != nil {
			if planType == "" {
				planType = claims.PlanType()
			}
			if accountID == "" {
				accountID = claims.AccountID()
			}
			if email == "" {
				email = claims.Email()
			}
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
	// earliest_refresh_at is re-issued on every refresh and moves forward with
	// the new token; a response that omits it leaves the previous value in
	// place rather than silently re-enabling early refresh.
	if t := tr.EarliestRefresh(); !t.IsZero() {
		a.EarliestRefreshAt = t
	}
	if tr.OAIIS != "" {
		a.OAIIS = tr.OAIIS
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
