package kiroauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// DefaultUserAgent is the User-Agent the real kiro-cli sends on auth endpoints.
// Verified against crack/kiro/login/rows/04 and 13.
const DefaultUserAgent = "Kiro-CLI"

// HTTPDoer is anything that can perform an HTTP request — usually *http.Client.
// Callers pass their own client to plug in proxies, custom TLS, etc.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// Client groups the three Kiro auth endpoints behind a small surface.
// Zero value is usable (uses http.DefaultClient and DefaultAuthRegion).
type Client struct {
	HTTP      HTTPDoer
	Region    string // auth region, defaults to DefaultAuthRegion
	UserAgent string // defaults to DefaultUserAgent
}

func (c *Client) http() HTTPDoer {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}
func (c *Client) region() string {
	if c.Region != "" {
		return c.Region
	}
	return DefaultAuthRegion
}
func (c *Client) ua() string {
	if c.UserAgent != "" {
		return c.UserAgent
	}
	return DefaultUserAgent
}

// TokenResponse is the unified shape across PKCE exchange and refresh.
// Field set follows the captures: see crack/kiro/login/docs/04 and crack/kiro/docs/01.
type TokenResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken,omitempty"`
	ProfileARN   string `json:"profileArn,omitempty"`
	ExpiresIn    int64  `json:"expiresIn,omitempty"` // seconds
	ExpiresAt    string `json:"expiresAt,omitempty"` // RFC3339, set by some flavors
}

// ApplyTo writes the response onto an existing Credentials, rotating
// refresh_token if the server returned a new one.
//
// IMPORTANT: when this returns, the caller MUST persist the credential
// to disk BEFORE making any further request — losing a rotated refresh
// token locks the account out permanently.
func (r *TokenResponse) ApplyTo(c *Credentials) {
	if r.AccessToken != "" {
		c.AccessToken = r.AccessToken
	}
	if r.RefreshToken != "" {
		c.RefreshToken = r.RefreshToken
	}
	if r.ProfileARN != "" {
		c.ProfileARN = r.ProfileARN
	}
	switch {
	case r.ExpiresAt != "":
		c.ExpiresAt = r.ExpiresAt
	case r.ExpiresIn > 0:
		c.SetExpiresIn(time.Duration(r.ExpiresIn) * time.Second)
	}
}

// ExchangeCode performs PKCE code-for-token exchange against
// POST /oauth/token. Verified shape: {code, code_verifier, redirect_uri}.
// Expected response: {accessToken, refreshToken, profileArn, expiresIn:3600}.
//
// See crack/kiro/login/docs/04 for the canonical wire payload.
func (c *Client) ExchangeCode(ctx context.Context, code, verifier, redirectURI string) (*TokenResponse, error) {
	body := map[string]string{
		"code":          code,
		"code_verifier": verifier,
		"redirect_uri":  redirectURI,
	}
	return c.postAuth(ctx, "/oauth/token", body)
}

// RefreshSocial refreshes a Social-tier token via POST /refreshToken.
// Body is just {refreshToken}. Response rotates the refresh token; the
// caller MUST persist before reuse.
//
// See crack/kiro/docs/01 for the canonical wire payload.
func (c *Client) RefreshSocial(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	if refreshToken == "" {
		return nil, errors.New("kiroauth: RefreshSocial: empty refresh token")
	}
	body := map[string]string{"refreshToken": refreshToken}
	return c.postAuth(ctx, "/refreshToken", body)
}

// Logout revokes a refresh-chain via POST /logout {refreshToken}. The
// associated accessToken is immediately rejected even before it expires.
//
// See crack/kiro/login/docs/06.
func (c *Client) Logout(ctx context.Context, refreshToken string) error {
	if refreshToken == "" {
		return errors.New("kiroauth: Logout: empty refresh token")
	}
	body := map[string]string{"refreshToken": refreshToken}
	_, err := c.postAuth(ctx, "/logout", body)
	// /logout normally returns empty body; postAuth tolerates that.
	return err
}

// RefreshIdC performs an AWS Identity Center (SSO OIDC) refresh against
// oidc.<region>.amazonaws.com/token. Standard OAuth2 refresh grant.
func (c *Client) RefreshIdC(ctx context.Context, clientID, clientSecret, refreshToken, region string) (*TokenResponse, error) {
	if clientID == "" || clientSecret == "" || refreshToken == "" {
		return nil, errors.New("kiroauth: RefreshIdC: clientID, clientSecret, refreshToken all required")
	}
	if region == "" {
		region = c.region()
	}
	body := map[string]string{
		"clientId":     clientID,
		"clientSecret": clientSecret,
		"refreshToken": refreshToken,
		"grantType":    "refresh_token",
	}
	url := "https://" + IdCOIDCHost(region) + "/token"
	return c.postJSON(ctx, url, body)
}

func (c *Client) postAuth(ctx context.Context, path string, body any) (*TokenResponse, error) {
	url := AuthBaseURL(c.region()) + path
	return c.postJSON(ctx, url, body)
}

func (c *Client) postJSON(ctx context.Context, url string, body any) (*TokenResponse, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("kiroauth: marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("kiroauth: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.ua())

	resp, err := c.http().Do(req)
	if err != nil {
		return nil, fmt.Errorf("kiroauth: do: %w", err)
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &APIError{
			URL:        url,
			StatusCode: resp.StatusCode,
			Body:       string(data),
		}
	}
	if len(data) == 0 {
		// /logout returns empty body
		return &TokenResponse{}, nil
	}
	var tr TokenResponse
	if err := json.Unmarshal(data, &tr); err != nil {
		return nil, fmt.Errorf("kiroauth: parse response: %w; body=%s", err, truncate(data, 256))
	}
	return &tr, nil
}

// APIError represents a non-2xx response from a Kiro auth endpoint.
type APIError struct {
	URL        string
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("kiroauth: %s: HTTP %d: %s", e.URL, e.StatusCode, truncate([]byte(e.Body), 256))
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "…"
}
