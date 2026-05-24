package kiroapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/wjsoj/cc-core/kirotransport"
	"github.com/wjsoj/cc-core/kirotransport/eventstream"
)

// HTTPDoer is anything that can perform an HTTP request.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// Client talks to the q.<region>.amazonaws.com endpoints (the "Bearer-token"
// half of the Kiro API). Zero value is usable but caller MUST set Token.
//
// Concurrency: safe for concurrent use; each call builds a fresh *http.Request.
type Client struct {
	HTTP      HTTPDoer
	Token     string                 // Kiro accessToken (Bearer) or ksk_ API key
	IsAPIKey  bool                   // sets `tokentype: API_KEY` header
	Region    string                 // defaults to "us-east-1"
	Flavor    kirotransport.Flavor   // FlavorIDE | FlavorCLI
	MachineID string                 // stable per-account fingerprint
	OptOut    *bool                  // nil → omit; true → "true"; false → "false"
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
	return "us-east-1"
}
func (c *Client) endpoint() string {
	return "https://q." + c.region() + ".amazonaws.com/"
}

// ListAvailableModels returns the model catalog the credential is allowed to
// use. Empty profileArn is permitted; the server falls back to a default.
func (c *Client) ListAvailableModels(ctx context.Context, profileARN string) (*ListAvailableModelsResponse, error) {
	origin := "KIRO_IDE"
	if c.Flavor == kirotransport.FlavorCLI {
		origin = "KIRO_CLI"
	}
	body, _ := json.Marshal(ListAvailableModelsRequest{Origin: origin, ProfileARN: profileARN})

	req, err := c.buildRequest(ctx, body, kirotransport.TargetListAvailableModels)
	if err != nil {
		return nil, err
	}
	resp, err := c.http().Do(req)
	if err != nil {
		return nil, fmt.Errorf("kiroapi: ListAvailableModels: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &HTTPError{Op: "ListAvailableModels", StatusCode: resp.StatusCode, Body: string(data)}
	}
	var out ListAvailableModelsResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("kiroapi: ListAvailableModels: parse: %w", err)
	}
	return &out, nil
}

// SendTelemetryEvent fires the per-turn business telemetry. Errors are
// returned but typically ignored by callers (it's metrics).
func (c *Client) SendTelemetryEvent(ctx context.Context, in *SendTelemetryEventRequest) error {
	body, _ := json.Marshal(in)
	req, err := c.buildRequest(ctx, body, kirotransport.TargetSendTelemetryEvent)
	if err != nil {
		return err
	}
	resp, err := c.http().Do(req)
	if err != nil {
		return fmt.Errorf("kiroapi: SendTelemetryEvent: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &HTTPError{Op: "SendTelemetryEvent", StatusCode: resp.StatusCode}
	}
	return nil
}

// GenerateAssistantResponse starts the streaming chat call. Returns a Stream
// that produces decoded frames; caller MUST call Stream.Close().
//
// The HTTP request is sent before returning; the caller controls how long the
// stream stays open via ctx cancellation.
func (c *Client) GenerateAssistantResponse(ctx context.Context, in *GenerateAssistantResponseRequest) (*Stream, error) {
	body, _ := json.Marshal(in)
	req, err := c.buildRequest(ctx, body, kirotransport.TargetGenerateAssistantResponse)
	if err != nil {
		return nil, err
	}
	// Streaming responses must NOT request gzip — server sends raw eventstream.
	req.Header.Set("Accept", "application/vnd.amazon.eventstream")

	resp, err := c.http().Do(req)
	if err != nil {
		return nil, fmt.Errorf("kiroapi: GenerateAssistantResponse: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return nil, &HTTPError{Op: "GenerateAssistantResponse", StatusCode: resp.StatusCode, Body: string(data)}
	}
	return &Stream{
		body:    resp.Body,
		decoder: eventstream.NewDecoder(),
		req:     resp.Header,
	}, nil
}

func (c *Client) buildRequest(ctx context.Context, body []byte, amzTarget string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("kiroapi: build req: %w", err)
	}
	kirotransport.ApplySmithyHeaders(req, kirotransport.SmithyJSON10, amzTarget)
	kirotransport.ApplyCommonAWSHeaders(req, c.Flavor, c.MachineID)
	kirotransport.ApplyBearerAuth(req, c.Token, c.IsAPIKey)
	if c.OptOut != nil {
		if *c.OptOut {
			req.Header.Set("x-amzn-codewhisperer-optout", "true")
		} else {
			req.Header.Set("x-amzn-codewhisperer-optout", "false")
		}
	}
	return req, nil
}

// HTTPError is a non-2xx response from the q.<region> endpoints.
type HTTPError struct {
	Op         string
	StatusCode int
	Body       string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("kiroapi: %s: HTTP %d: %s", e.Op, e.StatusCode, truncate(e.Body, 256))
}
