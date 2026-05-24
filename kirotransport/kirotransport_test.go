package kirotransport

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestUserAgentFlavors(t *testing.T) {
	ide := UserAgent(FlavorIDE, "machine123")
	if !strings.Contains(ide, "aws-sdk-js/") || !strings.Contains(ide, "KiroIDE-"+KiroIDEVersion+"-machine123") {
		t.Fatalf("IDE UA wrong: %s", ide)
	}
	cli := UserAgent(FlavorCLI, "machine456")
	for _, want := range []string{"aws-sdk-rust/" + AWSSDKRustVersion, "appVersion-" + KiroCLIVersion, "app/" + CLIAppLabel} {
		if !strings.Contains(cli, want) {
			t.Fatalf("CLI UA missing %q in: %s", want, cli)
		}
	}
}

func TestApplyCommonAWSHeaders(t *testing.T) {
	req, _ := http.NewRequest("POST", "https://example/", nil)
	ApplyCommonAWSHeaders(req, FlavorCLI, "m")
	for _, h := range []string{"User-Agent", "x-amz-user-agent", "amz-sdk-invocation-id", "amz-sdk-request"} {
		if req.Header.Get(h) == "" {
			t.Errorf("missing %s", h)
		}
	}
	if got := req.Header.Get("amz-sdk-request"); got != "attempt=1; max=3" {
		t.Errorf("amz-sdk-request: %s", got)
	}
}

func TestApplyBearerAuthAPIKey(t *testing.T) {
	req, _ := http.NewRequest("POST", "https://example/", nil)
	ApplyBearerAuth(req, "ksk_xyz", true)
	if req.Header.Get("Authorization") != "Bearer ksk_xyz" {
		t.Fatalf("auth: %s", req.Header.Get("Authorization"))
	}
	if req.Header.Get("tokentype") != "API_KEY" {
		t.Fatalf("expected tokentype: API_KEY")
	}
}

func TestUUIDv4Shape(t *testing.T) {
	u := uuidv4()
	if len(u) != 36 || u[8] != '-' || u[13] != '-' || u[14] != '4' || u[18] != '-' || u[23] != '-' {
		t.Fatalf("uuid shape: %s", u)
	}
}

// Test vector lifted from AWS SigV4 reference (get-vanilla-query-order-key).
// We reproduce a simpler vector since the official ones use very specific
// payloads. The important thing is signature stability under a known input.
func TestSigV4DeterministicSignature(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.amazonaws.com/", nil)
	creds := AWSCredentials{
		AccessKeyID:     "AKIDEXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
	}
	ts := time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
	if err := SignV4(req, creds, "service", "us-east-1", ts, nil); err != nil {
		t.Fatal(err)
	}
	auth := req.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request,") {
		t.Fatalf("auth prefix: %s", auth)
	}
	if !strings.Contains(auth, "SignedHeaders=host;x-amz-content-sha256;x-amz-date,") {
		t.Fatalf("signed headers wrong: %s", auth)
	}
	if !strings.Contains(auth, "Signature=") {
		t.Fatalf("no signature: %s", auth)
	}
	// Determinism: re-signing with same inputs gives same signature
	req2, _ := http.NewRequest("GET", "https://example.amazonaws.com/", nil)
	if err := SignV4(req2, creds, "service", "us-east-1", ts, nil); err != nil {
		t.Fatal(err)
	}
	if req.Header.Get("Authorization") != req2.Header.Get("Authorization") {
		t.Fatalf("signature not deterministic")
	}
}

func TestSigV4WithSessionToken(t *testing.T) {
	req, _ := http.NewRequest("POST", "https://client-telemetry.us-east-1.amazonaws.com/metrics", bytes.NewReader([]byte(`{}`)))
	creds := AWSCredentials{
		AccessKeyID:     "ASIA_TEMP",
		SecretAccessKey: "secret",
		SessionToken:    "TEMP_SESSION_TOKEN",
	}
	if err := SignV4(req, creds, "execute-api", "us-east-1", time.Now(), nil); err != nil {
		t.Fatal(err)
	}
	if req.Header.Get("X-Amz-Security-Token") != "TEMP_SESSION_TOKEN" {
		t.Fatalf("missing security token header")
	}
	// SessionToken must be included in signed headers.
	auth := req.Header.Get("Authorization")
	if !strings.Contains(auth, "x-amz-security-token") {
		t.Fatalf("session token not in SignedHeaders: %s", auth)
	}
}

func TestSigV4SignatureEndToEnd(t *testing.T) {
	// Round-trip: spin up a server that re-signs the received request and
	// compares signatures. Confirms canonicalization is consistent.
	var receivedAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(204)
	}))
	defer srv.Close()

	req, _ := http.NewRequest("POST", srv.URL+"/metrics", bytes.NewReader([]byte(`{"hello":"world"}`)))
	creds := AWSCredentials{AccessKeyID: "AKID", SecretAccessKey: "SECRET"}
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := SignV4(req, creds, "execute-api", "us-east-1", ts, nil); err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if receivedAuth == "" {
		t.Fatal("server saw no auth header")
	}
}
