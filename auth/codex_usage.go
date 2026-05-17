package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// CodexUsageInfo mirrors the GET https://chatgpt.com/backend-api/wham/usage
// response observed on the Codex web settings/analytics page. It is the
// *official portal* view of a ChatGPT-subscription account's Codex usage:
// primary (5h) and secondary (weekly) rolling rate-limit windows, credit
// balance, spend control, and plan-type — all derivable without ever sending
// a real /responses request. We use it as an active probe so the admin
// surfaces stay up-to-date even when no proxy traffic is flowing.
//
// Field shapes match the JSON verbatim; missing fields decode as zero values
// and the caller can branch on Updated.IsZero() to detect "never fetched".
type CodexUsageInfo struct {
	UserID    string                  `json:"user_id"`
	AccountID string                  `json:"account_id"`
	Email     string                  `json:"email"`
	PlanType  string                  `json:"plan_type"`
	RateLimit *CodexUsageRateLimit    `json:"rate_limit,omitempty"`
	Credits   *CodexUsageCredits      `json:"credits,omitempty"`
	Spend     *CodexUsageSpendControl `json:"spend_control,omitempty"`
	// RateLimitReachedType is set when one of the windows is exhausted —
	// observed values include "primary"/"secondary"; we keep the raw string
	// so future variants pass through unchanged.
	RateLimitReachedType string `json:"rate_limit_reached_type,omitempty"`

	// Updated is when we last successfully fetched this view.
	Updated time.Time `json:"updated"`
}

type CodexUsageRateLimit struct {
	Allowed          bool                   `json:"allowed"`
	LimitReached     bool                   `json:"limit_reached"`
	PrimaryWindow    *CodexUsageRateWindow  `json:"primary_window,omitempty"`
	SecondaryWindow  *CodexUsageRateWindow  `json:"secondary_window,omitempty"`
	CodeReviewWindow map[string]interface{} `json:"code_review_rate_limit,omitempty"`
}

type CodexUsageRateWindow struct {
	UsedPercent        float64 `json:"used_percent"`
	LimitWindowSeconds int64   `json:"limit_window_seconds"`
	ResetAfterSeconds  int64   `json:"reset_after_seconds"`
	ResetAt            int64   `json:"reset_at"` // unix seconds
}

type CodexUsageCredits struct {
	HasCredits           bool     `json:"has_credits"`
	Unlimited            bool     `json:"unlimited"`
	OverageLimitReached  bool     `json:"overage_limit_reached"`
	Balance              string   `json:"balance"`
	ApproxLocalMessages  []int    `json:"approx_local_messages"`
	ApproxCloudMessages  []int    `json:"approx_cloud_messages"`
}

type CodexUsageSpendControl struct {
	Reached         bool     `json:"reached"`
	IndividualLimit *float64 `json:"individual_limit,omitempty"`
}

// Codex web-portal endpoints. Pinned here because every other request shape
// in this package is also pinned to a captured client version.
const (
	codexWhamUsageURL = "https://chatgpt.com/backend-api/wham/usage"

	// Web client signature observed in the captured analytics page request.
	// chatgpt.com inspects oai-client-version + a few sibling headers; sending
	// these matches what the real settings/analytics page sends and avoids
	// the "unknown client" rejection path. Bump in lockstep when the web app
	// version drifts (low cadence — these headers were stable across months
	// of capture).
	codexWebClientVersion     = "prod-bede35f9dcd856d080e012478f0c1031faa2588e"
	codexWebClientBuildNumber = "6631702"
	codexWebUserAgent         = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
		"(KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36"
)

// FetchCodexUsage actively queries the wham/usage endpoint and stores the
// result on the Auth. Safe to call from any goroutine; refreshes the access
// token first if necessary. Returns the freshly stored snapshot and a copy
// is also accessible via a.Snapshot().CodexUsage.
//
// Side effects:
//   - On success, stores a.CodexUsage and bumps a.CodexUsageAt.
//   - Mirrors primary/secondary windows into a.CodexRateLimits so the
//     legacy `x-codex-*` UI panel keeps rendering without a separate code
//     path. This is the same shape the upstream /responses headers use.
//   - When rate_limit.limit_reached is true, MarkUsageLimitReached() is
//     called with the earliest reset_at across the two windows, so the
//     scheduler skips the credential until it actually recovers.
//
// Errors are returned (not logged) so the caller can decide whether a failure
// should be surfaced (admin "refresh now" button) or swallowed (background
// poll). Network errors do NOT mark the credential failed — wham/usage is an
// auxiliary signal and a flaky chatgpt.com response shouldn't taint the live
// /responses health view.
func (a *Auth) FetchCodexUsage(ctx context.Context, useUTLS bool) (*CodexUsageInfo, error) {
	if a == nil {
		return nil, fmt.Errorf("nil auth")
	}
	if a.Kind != KindOAuth {
		return nil, fmt.Errorf("codex usage probe requires OAuth credential (got %s)", a.Kind)
	}
	if NormalizeProvider(a.Provider) != ProviderOpenAI {
		return nil, fmt.Errorf("codex usage probe is OpenAI-only (auth is %s)", a.Provider)
	}

	if err := a.EnsureFresh(ctx, 5*time.Minute, useUTLS); err != nil {
		return nil, fmt.Errorf("token refresh: %w", err)
	}
	token, _ := a.Credentials()
	if token == "" {
		return nil, fmt.Errorf("no access token after refresh")
	}

	// chatgpt.com is TLS-fingerprinted by Cloudflare — use a fresh per-call
	// client to avoid h2 reuse pitfalls (see NewPlainHTTPClient docs).
	client := NewPlainHTTPClient(a.ProxyURL, useUTLS)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, codexWhamUsageURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Accept-Language", "en")
	req.Header.Set("User-Agent", codexWebUserAgent)
	req.Header.Set("Referer", "https://chatgpt.com/codex/cloud/settings/analytics")
	req.Header.Set("Oai-Client-Version", codexWebClientVersion)
	req.Header.Set("Oai-Client-Build-Number", codexWebClientBuildNumber)
	req.Header.Set("Oai-Language", "en")
	req.Header.Set("X-Openai-Target-Path", "/backend-api/wham/usage")
	req.Header.Set("X-Openai-Target-Route", "/backend-api/wham/usage")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("wham/usage GET: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet := string(body)
		if len(snippet) > 300 {
			snippet = snippet[:300] + "...(truncated)"
		}
		return nil, fmt.Errorf("wham/usage HTTP %d: %s", resp.StatusCode, snippet)
	}
	info := &CodexUsageInfo{}
	if err := json.Unmarshal(body, info); err != nil {
		return nil, fmt.Errorf("wham/usage decode: %w", err)
	}
	info.Updated = time.Now()

	// Persist snapshot + project into the existing x-codex-* surface.
	a.mu.Lock()
	a.CodexUsage = info
	a.CodexUsageAt = info.Updated
	if rl := info.RateLimit; rl != nil {
		captured := make(map[string]string, 8)
		if pw := rl.PrimaryWindow; pw != nil {
			captured["x-codex-primary-used-percent"] = strconv.FormatFloat(pw.UsedPercent, 'f', -1, 64)
			captured["x-codex-primary-reset-after-seconds"] = strconv.FormatInt(pw.ResetAfterSeconds, 10)
			if pw.ResetAt > 0 {
				captured["x-codex-primary-window-expires-at-iso"] = time.Unix(pw.ResetAt, 0).UTC().Format(time.RFC3339)
			}
			if pw.LimitWindowSeconds > 0 {
				captured["x-codex-primary-window-seconds"] = strconv.FormatInt(pw.LimitWindowSeconds, 10)
			}
		}
		if sw := rl.SecondaryWindow; sw != nil {
			captured["x-codex-secondary-used-percent"] = strconv.FormatFloat(sw.UsedPercent, 'f', -1, 64)
			captured["x-codex-secondary-reset-after-seconds"] = strconv.FormatInt(sw.ResetAfterSeconds, 10)
			if sw.ResetAt > 0 {
				captured["x-codex-secondary-window-expires-at-iso"] = time.Unix(sw.ResetAt, 0).UTC().Format(time.RFC3339)
			}
			if sw.LimitWindowSeconds > 0 {
				captured["x-codex-secondary-window-seconds"] = strconv.FormatInt(sw.LimitWindowSeconds, 10)
			}
		}
		if len(captured) > 0 {
			a.CodexRateLimits = captured
			a.CodexRateLimitsAt = info.Updated
		}
	}
	a.mu.Unlock()

	// Quota signal: if either window has tipped over, push the cooldown
	// into the scheduler so the pool stops handing this credential out.
	// We pick the soonest reset_at across the two windows so the cooldown
	// expires as soon as either window opens back up.
	if rl := info.RateLimit; rl != nil && rl.LimitReached {
		var earliest int64
		if rl.PrimaryWindow != nil && rl.PrimaryWindow.ResetAt > 0 {
			earliest = rl.PrimaryWindow.ResetAt
		}
		if rl.SecondaryWindow != nil && rl.SecondaryWindow.ResetAt > 0 {
			if earliest == 0 || rl.SecondaryWindow.ResetAt < earliest {
				earliest = rl.SecondaryWindow.ResetAt
			}
		}
		var resetAt time.Time
		if earliest > 0 {
			resetAt = time.Unix(earliest, 0)
		}
		a.MarkUsageLimitReached(resetAt)
	}

	return info, nil
}
