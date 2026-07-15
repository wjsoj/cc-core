package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Codex "rate-limit reset credit" endpoints. These back the ChatGPT/Codex
// one-off quota-reset-card feature: a subscription account can hold a small
// number of credits that, when consumed, immediately reset the account's
// rolling rate-limit window(s) instead of waiting for the natural reset.
//
//   - GET  .../rate-limit-reset-credits          → how many credits remain
//     (available_count) plus per-credit expiry metadata.
//   - POST .../rate-limit-reset-credits/consume  → redeem exactly one credit;
//     the body carries a client-generated redeem_request_id the backend uses
//     as an idempotency key.
//
// wham/usage already surfaces rate_limit_reset_credits.available_count (see
// CodexUsageInfo), so a plain "how many left" read can piggyback on a usage
// probe. FetchCodexResetCredits exists for callers that want the richer
// per-credit detail (expiry) without the rest of the usage payload.
const (
	codexWhamResetCreditsURL = "https://chatgpt.com/backend-api/wham/rate-limit-reset-credits"
	codexWhamResetConsumeURL = "https://chatgpt.com/backend-api/wham/rate-limit-reset-credits/consume"

	// The rate-limit reset credit ("quota reset card") is redeemed from the
	// Codex Desktop app, not the codex-tui CLI. The wham/usage probe can pass
	// with the minimal CLI header set, but the credits/consume endpoints are
	// most reliable when the request presents as Codex Desktop — this mirrors
	// the proven sub2api header set (originator "Codex Desktop", openai-beta
	// "codex-1", the browser sec-fetch-* markers) paired with the Chrome UA that
	// matches this package's HelloChrome_Auto uTLS fingerprint.
	codexDesktopOriginator = "Codex Desktop"
	codexDesktopOpenAIBeta = "codex-1"
	codexDesktopLanguage   = "en-US"
)

// CodexResetCreditDetail is the sanitized metadata for a single available reset
// credit. Only the expiry is surfaced — do NOT add upstream ids/tokens here, as
// this crosses into admin UI payloads.
type CodexResetCreditDetail struct {
	ExpiresAt string `json:"expires_at,omitempty"`
}

// CodexResetCredits is the GET .../rate-limit-reset-credits response projection.
type CodexResetCredits struct {
	AvailableCount int                      `json:"available_count"`
	Credits        []CodexResetCreditDetail `json:"credits,omitempty"`
	// Updated is when we last successfully fetched this view.
	Updated time.Time `json:"updated"`
}

// CodexResetCredit captures the redeemed-credit metadata returned by the
// consume endpoint.
type CodexResetCredit struct {
	ID              string `json:"id,omitempty"`
	ResetType       string `json:"reset_type,omitempty"`
	Status          string `json:"status,omitempty"`
	GrantedAt       string `json:"granted_at,omitempty"`
	ExpiresAt       string `json:"expires_at,omitempty"`
	RedeemStartedAt string `json:"redeem_started_at,omitempty"`
	RedeemedAt      string `json:"redeemed_at,omitempty"`
}

// CodexResetResult is the POST .../rate-limit-reset-credits/consume response
// projection. WindowsReset reports how many rate-limit windows the redeemed
// credit reset (typically 1).
type CodexResetResult struct {
	Code         string            `json:"code"`
	Credit       *CodexResetCredit `json:"credit,omitempty"`
	WindowsReset int               `json:"windows_reset"`
}

// FetchCodexResetCredits reads how many one-off rate-limit reset credits the
// account currently holds, along with each credit's expiry. It refreshes the
// access token first if necessary and reuses the pooled keep-alive client —
// same transport discipline as FetchCodexUsage (a flaky chatgpt.com response
// never taints the live /responses health view). Errors are returned, not
// logged, so the caller decides whether to surface them.
func (a *Auth) FetchCodexResetCredits(ctx context.Context, useUTLS bool) (*CodexResetCredits, error) {
	token, accountID, client, err := a.prepareCodexWhamCall(ctx, useUTLS)
	if err != nil {
		return nil, err
	}

	buildReq := func() (*http.Request, error) {
		r, err := http.NewRequestWithContext(ctx, http.MethodGet, codexWhamResetCreditsURL, nil)
		if err != nil {
			return nil, err
		}
		applyCodexWhamHeaders(r, token, accountID)
		return r, nil
	}

	body, err := doCodexWhamRequest(ctx, client, buildReq)
	if err != nil {
		return nil, err
	}
	out := &CodexResetCredits{}
	if err := json.Unmarshal(body, out); err != nil {
		return nil, fmt.Errorf("rate-limit-reset-credits decode: %w", err)
	}
	out.Updated = time.Now()
	return out, nil
}

// ResetCodexCredit consumes exactly one rate-limit reset credit, immediately
// resetting the account's rolling rate-limit window(s). The redeem_request_id
// is auto-generated (uuid-v4 shaped); the backend treats it as an idempotency
// key so an accidental double-submit does not burn two credits. On success the
// returned CodexResetResult carries the redeemed-credit metadata and how many
// windows were reset.
//
// Callers that display "credits remaining" should re-run FetchCodexResetCredits
// (or FetchCodexUsage) afterwards — this call does not itself return the new
// balance.
func (a *Auth) ResetCodexCredit(ctx context.Context, useUTLS bool) (*CodexResetResult, error) {
	token, accountID, client, err := a.prepareCodexWhamCall(ctx, useUTLS)
	if err != nil {
		return nil, err
	}

	redeemID, err := generateRedeemRequestID()
	if err != nil {
		return nil, fmt.Errorf("generate redeem id: %w", err)
	}
	reqBody, err := json.Marshal(map[string]string{"redeem_request_id": redeemID})
	if err != nil {
		return nil, fmt.Errorf("marshal redeem body: %w", err)
	}

	buildReq := func() (*http.Request, error) {
		r, err := http.NewRequestWithContext(ctx, http.MethodPost, codexWhamResetConsumeURL, bytes.NewReader(reqBody))
		if err != nil {
			return nil, err
		}
		applyCodexWhamHeaders(r, token, accountID)
		r.Header.Set("Content-Type", "application/json")
		return r, nil
	}

	body, err := doCodexWhamRequest(ctx, client, buildReq)
	if err != nil {
		return nil, err
	}
	out := &CodexResetResult{}
	if err := json.Unmarshal(body, out); err != nil {
		return nil, fmt.Errorf("rate-limit-reset-credits/consume decode: %w", err)
	}
	return out, nil
}

// prepareCodexWhamCall validates the credential, refreshes the token if needed,
// and returns the access token, chatgpt-account-id, and a pooled client — the
// shared preamble for every wham/* probe on this Auth.
func (a *Auth) prepareCodexWhamCall(ctx context.Context, useUTLS bool) (token, accountID string, client *http.Client, err error) {
	if a == nil {
		return "", "", nil, fmt.Errorf("nil auth")
	}
	if a.Kind != KindOAuth {
		return "", "", nil, fmt.Errorf("codex reset-credit requires OAuth credential (got %v)", a.Kind)
	}
	if NormalizeProvider(a.Provider) != ProviderOpenAI {
		return "", "", nil, fmt.Errorf("codex reset-credit is OpenAI-only (auth is %s)", a.Provider)
	}
	if err := a.EnsureFresh(ctx, 5*time.Minute, useUTLS); err != nil {
		return "", "", nil, fmt.Errorf("token refresh: %w", err)
	}
	token, _ = a.Credentials()
	if token == "" {
		return "", "", nil, fmt.Errorf("no access token after refresh")
	}
	accountID, _ = a.CodexIdentity()
	// Pooled keep-alive client, same rationale as FetchCodexUsage: SOCKS5
	// proxies choke on rapid back-to-back TLS handshakes; reusing the
	// connection sidesteps the "connection reset by peer" flakiness.
	return token, accountID, ClientFor(a.ProxyURL, useUTLS), nil
}

// applyCodexWhamHeaders presents the request as the Codex Desktop app talking to
// the reset-credit backend — the client that actually redeems quota reset cards,
// and the most reliable identity for the credits/consume endpoints. It mirrors
// the sub2api header set: originator "Codex Desktop", openai-beta "codex-1", and
// the browser sec-fetch-* markers, paired with the Chrome UA (browserUA) that
// matches this package's HelloChrome_Auto uTLS fingerprint so UA and TLS stay
// consistent past Cloudflare. (FetchCodexUsage deliberately keeps the codex-tui
// CLI identity for wham/usage — a different, lower-stakes probe.)
func applyCodexWhamHeaders(r *http.Request, token, accountID string) {
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Accept", "application/json")
	r.Header.Set("Accept-Encoding", "identity")
	r.Header.Set("User-Agent", browserUA)
	r.Header.Set("Originator", codexDesktopOriginator)
	r.Header.Set("OpenAI-Beta", codexDesktopOpenAIBeta)
	r.Header.Set("Oai-Language", codexDesktopLanguage)
	r.Header.Set("Sec-Fetch-Site", "none")
	r.Header.Set("Sec-Fetch-Mode", "no-cors")
	r.Header.Set("Sec-Fetch-Dest", "empty")
	r.Header.Set("Priority", "u=4, i")
	if accountID != "" {
		r.Header.Set("Chatgpt-Account-Id", accountID)
	}
}

// doCodexWhamRequest runs buildReq with the same best-effort transient-failure
// retry FetchCodexUsage uses (SOCKS5 handshake resets, GOAWAY, broken pipe), and
// returns the response body on a 2xx. Non-2xx responses are surfaced verbatim as
// errors — the caller needs to see 401/403/429 unchanged. buildReq is a factory
// because a request body cannot be replayed across retries.
func doCodexWhamRequest(ctx context.Context, client *http.Client, buildReq func() (*http.Request, error)) ([]byte, error) {
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
		return nil, fmt.Errorf("wham request: %w", lastErr)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet := string(body)
		if len(snippet) > 300 {
			snippet = snippet[:300] + "...(truncated)"
		}
		return nil, fmt.Errorf("wham HTTP %d: %s", resp.StatusCode, snippet)
	}
	return body, nil
}

// generateRedeemRequestID produces a UUID-v4-shaped string without pulling in a
// new dependency. ChatGPT uses this as the idempotency key for the consume call.
func generateRedeemRequestID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant RFC 4122
	h := hex.EncodeToString(b)
	return strings.Join([]string{h[0:8], h[8:12], h[12:16], h[16:20], h[20:]}, "-"), nil
}
