package kiroapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/wjsoj/cc-core/kirocognito"
	"github.com/wjsoj/cc-core/kirotransport"
)

// ToolkitTelemetryClient posts to client-telemetry.<region>.amazonaws.com/metrics.
//
// These are AWS Toolkit Telemetry events — separate from the business
// SendTelemetryEvent calls — and are signed with SigV4 using STS credentials
// minted via the anonymous Cognito pool (kirocognito.Provider).
//
// Sending these matches what real kiro-cli does on every CLI invocation. From
// a fingerprint perspective, NOT sending them is a tell — a proxy that never
// posts /metrics looks unlike any real client.
//
// Errors are returned but most callers ignore them.
type ToolkitTelemetryClient struct {
	HTTP    HTTPDoer
	Region  string
	Cognito *kirocognito.Provider
}

func (c *ToolkitTelemetryClient) http() HTTPDoer {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}
func (c *ToolkitTelemetryClient) region() string {
	if c.Region != "" {
		return c.Region
	}
	return "us-east-1"
}
func (c *ToolkitTelemetryClient) endpoint() string {
	return "https://client-telemetry." + c.region() + ".amazonaws.com/metrics"
}

// ToolkitMetric is one event in the batch posted to /metrics. The shape is the
// AWS Toolkit "metric datum" format; see crack/kiro/rows/04 for a full example.
type ToolkitMetric struct {
	MetricName string             `json:"MetricName"`
	Value      float64            `json:"Value"`
	Unit       string             `json:"Unit"` // e.g. "Count", "None"
	EpochTimestamp int64          `json:"EpochTimestamp"`
	Metadata   []ToolkitMetadatum `json:"Metadata,omitempty"`
}

// ToolkitMetadatum is one name/value tag attached to a ToolkitMetric.
type ToolkitMetadatum struct {
	Key   string `json:"Key"`
	Value string `json:"Value"`
}

// ToolkitBatch is the request body.
type ToolkitBatch struct {
	AWSProduct        string          `json:"AWSProduct"`
	AWSProductVersion string          `json:"AWSProductVersion"`
	ClientID          string          `json:"ClientID"`
	OS                string          `json:"OS"`
	OSVersion         string          `json:"OSVersion"`
	ParentProduct     string          `json:"ParentProduct,omitempty"`
	ParentProductVer  string          `json:"ParentProductVersion,omitempty"`
	MetricData        []ToolkitMetric `json:"MetricData"`
}

// Send posts the batch. The Cognito provider must be configured (or nil for
// signing-bypass when testing).
func (c *ToolkitTelemetryClient) Send(ctx context.Context, batch *ToolkitBatch) error {
	if batch == nil || len(batch.MetricData) == 0 {
		return nil
	}
	payload, err := json.Marshal(batch)
	if err != nil {
		return fmt.Errorf("kiroapi: toolkit telemetry: marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint(), bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("kiroapi: toolkit telemetry: build: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", kirotransport.UserAgent(kirotransport.FlavorCLI, ""))

	if c.Cognito != nil {
		creds, err := c.Cognito.Credentials(ctx)
		if err != nil {
			return fmt.Errorf("kiroapi: toolkit telemetry: cognito: %w", err)
		}
		if err := kirotransport.SignV4(req, creds, "execute-api", c.region(), time.Now(), payload); err != nil {
			return fmt.Errorf("kiroapi: toolkit telemetry: sigv4: %w", err)
		}
	}

	resp, err := c.http().Do(req)
	if err != nil {
		return fmt.Errorf("kiroapi: toolkit telemetry: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &HTTPError{Op: "ToolkitTelemetry", StatusCode: resp.StatusCode}
	}
	return nil
}
