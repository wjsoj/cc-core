package kiroapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/wjsoj/cc-core/kirotransport"
	"github.com/wjsoj/cc-core/kirotransport/eventstream"
)

func TestListAvailableModelsWireShape(t *testing.T) {
	var sawTarget, sawAuth, sawCT string
	var sawBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawTarget = r.Header.Get("x-amz-target")
		sawAuth = r.Header.Get("Authorization")
		sawCT = r.Header.Get("Content-Type")
		_ = json.NewDecoder(r.Body).Decode(&sawBody)
		_, _ = io.WriteString(w, `{"defaultModel":{"modelId":"auto"},"models":[{"modelId":"auto","modelName":"auto","rateMultiplier":1.0,"supportedInputTypes":["TEXT"]}]}`)
	}))
	defer srv.Close()
	c := &Client{
		HTTP:   &hostRewriter{base: srv.URL, next: srv.Client()},
		Token:  "aoaABC",
		Flavor: kirotransport.FlavorCLI,
	}
	out, err := c.ListAvailableModels(context.Background(), "arn:test")
	if err != nil {
		t.Fatal(err)
	}
	if sawTarget != "AmazonCodeWhispererService.ListAvailableModels" {
		t.Fatalf("target: %s", sawTarget)
	}
	if sawCT != "application/x-amz-json-1.0" {
		t.Fatalf("content-type: %s", sawCT)
	}
	if sawAuth != "Bearer aoaABC" {
		t.Fatalf("auth: %s", sawAuth)
	}
	if sawBody["origin"] != "KIRO_CLI" || sawBody["profileArn"] != "arn:test" {
		t.Fatalf("body: %+v", sawBody)
	}
	if out.DefaultModel.ModelID != "auto" || len(out.Models) != 1 {
		t.Fatalf("response parse: %+v", out)
	}
}

func TestListAvailableModelsAPIKeyHeader(t *testing.T) {
	var sawType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawType = r.Header.Get("tokentype")
		_, _ = io.WriteString(w, `{"defaultModel":{"modelId":"x"},"models":[]}`)
	}))
	defer srv.Close()
	c := &Client{
		HTTP:     &hostRewriter{base: srv.URL, next: srv.Client()},
		Token:    "ksk_xyz",
		IsAPIKey: true,
	}
	_, _ = c.ListAvailableModels(context.Background(), "")
	if sawType != "API_KEY" {
		t.Fatalf("API_KEY tokentype not sent: %q", sawType)
	}
}

func TestSendTelemetryEvent(t *testing.T) {
	var sawTarget string
	var sawBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawTarget = r.Header.Get("x-amz-target")
		_ = json.NewDecoder(r.Body).Decode(&sawBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	c := &Client{HTTP: &hostRewriter{base: srv.URL, next: srv.Client()}, Token: "t"}
	err := c.SendTelemetryEvent(context.Background(), &SendTelemetryEventRequest{
		ClientToken:    "uuid",
		TelemetryEvent: json.RawMessage(`{"chatAddMessageEvent":{"conversationId":"c"}}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if sawTarget != "AmazonCodeWhispererService.SendTelemetryEvent" {
		t.Fatalf("target: %s", sawTarget)
	}
	if sawBody["clientToken"] != "uuid" {
		t.Fatalf("body: %+v", sawBody)
	}
}

func TestGenerateAssistantResponseStream(t *testing.T) {
	// Build a fake event-stream body with: assistantResponseEvent ×2 + messageMetadataEvent.
	body := buildStream([]frameSpec{
		{headers: map[string]string{":message-type": "event", ":event-type": "assistantResponseEvent"}, payload: []byte(`{"content":"Hello"}`)},
		{headers: map[string]string{":message-type": "event", ":event-type": "assistantResponseEvent"}, payload: []byte(`{"content":" world"}`)},
		{headers: map[string]string{":message-type": "event", ":event-type": "messageMetadataEvent"}, payload: []byte(`{"conversationId":"c1","utteranceId":"u1"}`)},
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-amz-target") != kirotransport.TargetGenerateAssistantResponse {
			t.Errorf("target: %s", r.Header.Get("x-amz-target"))
		}
		w.Header().Set("Content-Type", kirotransport.EventStreamContentType)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	c := &Client{HTTP: &hostRewriter{base: srv.URL, next: srv.Client()}, Token: "t"}
	stream, err := c.GenerateAssistantResponse(context.Background(), &GenerateAssistantResponseRequest{
		ConversationState: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()

	var combined strings.Builder
	var gotMeta *MessageMetadataEvent
	for stream.Next() {
		et, payload, err := ParseEvent(stream.Frame())
		if err != nil {
			t.Fatal(err)
		}
		switch v := payload.(type) {
		case *AssistantResponseEvent:
			combined.WriteString(v.Content)
		case *MessageMetadataEvent:
			gotMeta = v
		default:
			_ = et
		}
	}
	if err := stream.Err(); err != nil {
		t.Fatalf("stream err: %v", err)
	}
	if combined.String() != "Hello world" {
		t.Fatalf("concat: %q", combined.String())
	}
	if gotMeta == nil || gotMeta.ConversationID != "c1" {
		t.Fatalf("metadata: %+v", gotMeta)
	}
}

func TestParseEventError(t *testing.T) {
	h := eventstream.NewHeaders()
	h.SetString(":message-type", "error")
	h.SetString(":error-code", "ThrottlingException")
	frame, _, _ := eventstream.ParseFrame(eventstream.EncodeFrame(h, []byte("slow down")))
	_, _, err := ParseEvent(frame)
	if err == nil {
		t.Fatal("expected error")
	}
	if _, ok := err.(*RemoteError); !ok {
		t.Fatalf("expected *RemoteError, got %T", err)
	}
}

func TestParseEventException(t *testing.T) {
	h := eventstream.NewHeaders()
	h.SetString(":message-type", "exception")
	h.SetString(":exception-type", "MonthlyRequestLimitExceeded")
	frame, _, _ := eventstream.ParseFrame(eventstream.EncodeFrame(h, []byte("over quota")))
	_, _, err := ParseEvent(frame)
	if err == nil {
		t.Fatal("expected exception")
	}
	if _, ok := err.(*RemoteException); !ok {
		t.Fatalf("expected *RemoteException, got %T", err)
	}
}

func TestHTTPErrorOnNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"message":"expired"}`)
	}))
	defer srv.Close()
	c := &Client{HTTP: &hostRewriter{base: srv.URL, next: srv.Client()}, Token: "bad"}
	_, err := c.ListAvailableModels(context.Background(), "")
	if err == nil {
		t.Fatal("expected http error")
	}
	if _, ok := err.(*HTTPError); !ok {
		t.Fatalf("expected *HTTPError, got %T", err)
	}
}

func TestToolkitTelemetryWithoutSigning(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/metrics" {
			t.Errorf("path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	c := &ToolkitTelemetryClient{HTTP: &hostRewriter{base: srv.URL, next: srv.Client()}}
	err := c.Send(context.Background(), &ToolkitBatch{
		AWSProduct:        "AmazonQ-For-CLI",
		AWSProductVersion: "2.4.1",
		ClientID:          "fake-uuid",
		OS:                "linux",
		OSVersion:         "6.6",
		MetricData: []ToolkitMetric{
			{MetricName: "cliSubcommandExecuted", Value: 1, Unit: "Count", EpochTimestamp: time.Now().Unix() * 1000},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
}

// --- helpers ---

type frameSpec struct {
	headers map[string]string
	payload []byte
}

func (f frameSpec) build() []byte {
	h := eventstream.NewHeaders()
	for k, v := range f.headers {
		h.SetString(k, v)
	}
	return eventstream.EncodeFrame(h, f.payload)
}

func buildStream(specs []frameSpec) []byte {
	var out []byte
	for _, s := range specs {
		out = append(out, s.build()...)
	}
	return out
}

// hostRewriter swaps host to the test server.
type hostRewriter struct {
	base string
	next *http.Client
}

func (r *hostRewriter) Do(req *http.Request) (*http.Response, error) {
	u, _ := url.Parse(r.base)
	req.URL.Scheme = u.Scheme
	req.URL.Host = u.Host
	return r.next.Do(req)
}
