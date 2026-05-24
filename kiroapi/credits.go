package kiroapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/wjsoj/cc-core/kirotransport"
)

// CreditsResponse is the typed shape of GET /getUsageLimits.
// Matches the wire layout kiro.rs UsageLimitsResponse uses.
type CreditsResponse struct {
	// NextDateReset is the Unix timestamp when the primary quota resets.
	NextDateReset    float64           `json:"nextDateReset,omitempty"`
	SubscriptionInfo *SubscriptionInfo `json:"subscriptionInfo,omitempty"`
	UsageBreakdownList []UsageBreakdown `json:"usageBreakdownList,omitempty"`
}

// SubscriptionInfo describes the credential's current Kiro plan tier.
type SubscriptionInfo struct {
	// SubscriptionTitle is the human-facing plan name: "KIRO PRO+", "KIRO FREE",
	// "KIRO TRIAL", etc.
	SubscriptionTitle string `json:"subscriptionTitle,omitempty"`
}

// UsageBreakdown is one consumption bucket. Typical responses carry a single
// entry for the AGENTIC_REQUEST resource.
type UsageBreakdown struct {
	// CurrentUsage is the integer-rounded request count consumed this period.
	CurrentUsage int64 `json:"currentUsage"`
	// CurrentUsageWithPrecision is the fractional request count (Sonnet at 1.3
	// per request, Opus at 2.2, etc. — the multipliers from
	// ListAvailableModels apply here).
	CurrentUsageWithPrecision float64 `json:"currentUsageWithPrecision"`
	// UsageLimit is the integer cap for this period.
	UsageLimit int64 `json:"usageLimit"`
	// UsageLimitWithPrecision is the fractional cap.
	UsageLimitWithPrecision float64 `json:"usageLimitWithPrecision"`
	// NextDateReset is the Unix timestamp when this bucket resets.
	NextDateReset float64 `json:"nextDateReset,omitempty"`

	// Bonuses are promotional / referral credits that stack on top of the base
	// usageLimit. Only those with status == "ACTIVE" actually count toward the
	// total — see CreditsResponse.UsageTotal().
	Bonuses []Bonus `json:"bonuses,omitempty"`

	// FreeTrialInfo is set for trial credentials; same active/expired gating
	// as Bonuses.
	FreeTrialInfo *FreeTrialInfo `json:"freeTrialInfo,omitempty"`
}

// Bonus is one stackable credit grant.
type Bonus struct {
	CurrentUsage float64 `json:"currentUsage"`
	UsageLimit   float64 `json:"usageLimit"`
	// Status is "ACTIVE" or "EXPIRED" (case-sensitive in the wire format).
	Status string `json:"status,omitempty"`
}

// IsActive returns true only when Status == "ACTIVE".
func (b *Bonus) IsActive() bool { return b.Status == "ACTIVE" }

// FreeTrialInfo describes a credential currently on a free trial.
type FreeTrialInfo struct {
	CurrentUsage              int64   `json:"currentUsage"`
	CurrentUsageWithPrecision float64 `json:"currentUsageWithPrecision"`
	UsageLimit                int64   `json:"usageLimit"`
	UsageLimitWithPrecision   float64 `json:"usageLimitWithPrecision"`
	FreeTrialExpiry           float64 `json:"freeTrialExpiry,omitempty"` // unix ts
	FreeTrialStatus           string  `json:"freeTrialStatus,omitempty"` // "ACTIVE" | "EXPIRED"
}

// IsActive returns true only when FreeTrialStatus == "ACTIVE".
func (f *FreeTrialInfo) IsActive() bool { return f.FreeTrialStatus == "ACTIVE" }

// Plan returns the subscription title or "" when unknown.
func (r *CreditsResponse) Plan() string {
	if r.SubscriptionInfo == nil {
		return ""
	}
	return r.SubscriptionInfo.SubscriptionTitle
}

// Primary returns the first usage breakdown entry (the AGENTIC_REQUEST one)
// or nil if the response is empty.
func (r *CreditsResponse) Primary() *UsageBreakdown {
	if len(r.UsageBreakdownList) == 0 {
		return nil
	}
	return &r.UsageBreakdownList[0]
}

// UsageTotal returns the precise total consumption — base usage plus any
// active free-trial usage plus any active bonus usage.
//
// Use this instead of reading CurrentUsageWithPrecision directly: the raw
// field counts only the base bucket, so a Pro trial+bonus account can show
// 0/N base usage while consuming bonuses heavily.
func (r *CreditsResponse) UsageTotal() float64 {
	p := r.Primary()
	if p == nil {
		return 0
	}
	total := p.CurrentUsageWithPrecision
	if p.FreeTrialInfo != nil && p.FreeTrialInfo.IsActive() {
		total += p.FreeTrialInfo.CurrentUsageWithPrecision
	}
	for _, b := range p.Bonuses {
		if b.IsActive() {
			total += b.CurrentUsage
		}
	}
	return total
}

// LimitTotal returns the precise total cap — base limit plus active free-trial
// limit plus active bonus limits. Symmetric with UsageTotal.
func (r *CreditsResponse) LimitTotal() float64 {
	p := r.Primary()
	if p == nil {
		return 0
	}
	total := p.UsageLimitWithPrecision
	if p.FreeTrialInfo != nil && p.FreeTrialInfo.IsActive() {
		total += p.FreeTrialInfo.UsageLimitWithPrecision
	}
	for _, b := range p.Bonuses {
		if b.IsActive() {
			total += b.UsageLimit
		}
	}
	return total
}

// Remaining is LimitTotal - UsageTotal, floored at zero.
func (r *CreditsResponse) Remaining() float64 {
	v := r.LimitTotal() - r.UsageTotal()
	if v < 0 {
		return 0
	}
	return v
}

// NextResetAt returns the next reset moment, or zero Time when unknown.
func (r *CreditsResponse) NextResetAt() time.Time {
	if r.NextDateReset > 0 {
		return time.Unix(int64(r.NextDateReset), 0)
	}
	if p := r.Primary(); p != nil && p.NextDateReset > 0 {
		return time.Unix(int64(p.NextDateReset), 0)
	}
	return time.Time{}
}

// GetCredits queries the per-credential quota endpoint.
//
//	GET https://q.<region>.amazonaws.com/getUsageLimits
//	    ?origin=AI_EDITOR
//	    &resourceType=AGENTIC_REQUEST
//	    [&profileArn=<urlescape>]
//
// Bearer auth. Same header set as the Smithy calls (User-Agent, x-amz-user-agent,
// amz-sdk-invocation-id, amz-sdk-request); ApplyBearerAuth handles tokentype
// for ksk_ credentials.
//
// origin should be "AI_EDITOR" for IDE flavor or "KIRO_CLI" for CLI flavor —
// the captures consistently use "AI_EDITOR" for kiro IDE.
func (c *Client) GetCredits(ctx context.Context, profileARN string) (*CreditsResponse, error) {
	origin := "AI_EDITOR"
	if c.Flavor == kirotransport.FlavorCLI {
		origin = "KIRO_CLI"
	}

	endpoint := "https://q." + c.region() + ".amazonaws.com/getUsageLimits"
	q := url.Values{}
	q.Set("origin", origin)
	q.Set("resourceType", "AGENTIC_REQUEST")
	if profileARN != "" {
		q.Set("profileArn", profileARN)
	}
	endpoint += "?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("kiroapi: GetCredits: build req: %w", err)
	}
	kirotransport.ApplyCommonAWSHeaders(req, c.Flavor, c.MachineID)
	kirotransport.ApplyBearerAuth(req, c.Token, c.IsAPIKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.http().Do(req)
	if err != nil {
		return nil, fmt.Errorf("kiroapi: GetCredits: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &HTTPError{Op: "GetCredits", StatusCode: resp.StatusCode, Body: string(data)}
	}
	var out CreditsResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("kiroapi: GetCredits: parse: %w", err)
	}
	return &out, nil
}
