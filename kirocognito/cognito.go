// Package kirocognito wraps the two AWS Cognito Identity calls Kiro uses
// to mint anonymous AWS STS credentials for the client-telemetry endpoint:
//
//	GetId                    → returns a long-lived IdentityId (per-pool)
//	GetCredentialsForIdentity → exchanges IdentityId for short-lived STS creds
//
// These STS credentials are then used by kiroapi.SendToolkitTelemetry to
// SigV4-sign the /metrics request. They are NOT used by the q.us-east-1
// business API, which uses Kiro's own Bearer accessToken.
//
// The pool ID is the public anonymous pool every Kiro install hits — verified
// in crack/kiro/login/docs/01 and 07. There is no per-user authentication
// here; we are merely getting throwaway IAM creds.
package kirocognito

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/wjsoj/cc-core/kirotransport"
)

// PublicAnonymousPoolID is the Cognito Identity Pool every Kiro client uses.
// Re-verify on every kiro-cli release; rotated values would show up in
// crack/kiro/login/rows/01.
const PublicAnonymousPoolID = "us-east-1:820fd6d1-95c0-4ca4-bffb-3f01d32da842"

// DefaultRegion is "us-east-1" — the pool's home region.
const DefaultRegion = "us-east-1"

// HTTPDoer is anything that can perform an HTTP request.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// Provider mints anonymous STS credentials, caching them until ~5 min before
// expiry. Safe for concurrent use.
type Provider struct {
	HTTP   HTTPDoer
	Region string // defaults to DefaultRegion
	PoolID string // defaults to PublicAnonymousPoolID

	mu         sync.Mutex
	cachedID   string
	cached     kirotransport.AWSCredentials
	cachedTill time.Time
}

func (p *Provider) http() HTTPDoer {
	if p.HTTP != nil {
		return p.HTTP
	}
	return http.DefaultClient
}
func (p *Provider) region() string {
	if p.Region != "" {
		return p.Region
	}
	return DefaultRegion
}
func (p *Provider) poolID() string {
	if p.PoolID != "" {
		return p.PoolID
	}
	return PublicAnonymousPoolID
}

// Credentials returns cached STS creds, refreshing if expired or near-expiry.
func (p *Provider) Credentials(ctx context.Context) (kirotransport.AWSCredentials, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if time.Now().Before(p.cachedTill) && p.cached.AccessKeyID != "" {
		return p.cached, nil
	}

	if p.cachedID == "" {
		id, err := p.getID(ctx)
		if err != nil {
			return kirotransport.AWSCredentials{}, err
		}
		p.cachedID = id
	}

	creds, expiresAt, err := p.getCredentials(ctx, p.cachedID)
	if err != nil {
		// IdentityId may have been invalidated; force fresh GetId next time.
		p.cachedID = ""
		return kirotransport.AWSCredentials{}, err
	}
	p.cached = creds
	// Refresh 5 min before actual expiry.
	p.cachedTill = expiresAt.Add(-5 * time.Minute)
	return creds, nil
}

// Invalidate forces the next Credentials call to re-issue GetId + GetCreds.
// Call this when the API returns 401 / signature-expired errors.
func (p *Provider) Invalidate() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cachedID = ""
	p.cached = kirotransport.AWSCredentials{}
	p.cachedTill = time.Time{}
}

func (p *Provider) host() string {
	return "cognito-identity." + p.region() + ".amazonaws.com"
}
func (p *Provider) baseURL() string { return "https://" + p.host() + "/" }

type getIDRequest struct {
	IdentityPoolID string `json:"IdentityPoolId"`
}
type getIDResponse struct {
	IdentityID string `json:"IdentityId"`
}

func (p *Provider) getID(ctx context.Context) (string, error) {
	body, _ := json.Marshal(getIDRequest{IdentityPoolID: p.poolID()})
	var out getIDResponse
	if err := p.call(ctx, kirotransport.TargetCognitoGetID, body, &out); err != nil {
		return "", err
	}
	if out.IdentityID == "" {
		return "", fmt.Errorf("kirocognito: GetId returned empty IdentityId")
	}
	return out.IdentityID, nil
}

type getCredsRequest struct {
	IdentityID string `json:"IdentityId"`
}
type getCredsResponse struct {
	IdentityID  string `json:"IdentityId"`
	Credentials struct {
		AccessKeyID  string  `json:"AccessKeyId"`
		SecretKey    string  `json:"SecretKey"`
		SessionToken string  `json:"SessionToken"`
		Expiration   float64 `json:"Expiration"` // unix seconds
	} `json:"Credentials"`
}

func (p *Provider) getCredentials(ctx context.Context, identityID string) (kirotransport.AWSCredentials, time.Time, error) {
	body, _ := json.Marshal(getCredsRequest{IdentityID: identityID})
	var out getCredsResponse
	if err := p.call(ctx, kirotransport.TargetCognitoGetCredentialsForIdentity, body, &out); err != nil {
		return kirotransport.AWSCredentials{}, time.Time{}, err
	}
	creds := kirotransport.AWSCredentials{
		AccessKeyID:     out.Credentials.AccessKeyID,
		SecretAccessKey: out.Credentials.SecretKey,
		SessionToken:    out.Credentials.SessionToken,
	}
	exp := time.Unix(int64(out.Credentials.Expiration), 0)
	return creds, exp, nil
}

func (p *Provider) call(ctx context.Context, target string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("kirocognito: build req: %w", err)
	}
	kirotransport.ApplySmithyHeaders(req, kirotransport.SmithyJSON11, target)
	// Cognito is unauthenticated for anonymous pools — no Authorization header.
	resp, err := p.http().Do(req)
	if err != nil {
		return fmt.Errorf("kirocognito: %s: %w", target, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("kirocognito: %s: HTTP %d: %s", target, resp.StatusCode, truncate(data, 256))
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("kirocognito: %s: parse: %w", target, err)
	}
	return nil
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "…"
}
