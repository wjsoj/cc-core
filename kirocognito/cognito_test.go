package kirocognito

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
)

func TestProviderCredentialsCached(t *testing.T) {
	var getIDCalls, getCredsCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("x-amz-target") {
		case "AWSCognitoIdentityService.GetId":
			getIDCalls++
			_, _ = io.WriteString(w, `{"IdentityId":"us-east-1:abc-123"}`)
		case "AWSCognitoIdentityService.GetCredentialsForIdentity":
			getCredsCalls++
			_, _ = io.WriteString(w, jsonCredsExpIn(3600))
		default:
			t.Errorf("unexpected target: %s", r.Header.Get("x-amz-target"))
		}
	}))
	defer srv.Close()

	p := &Provider{
		HTTP: &hostRewriter{base: srv.URL, next: srv.Client()},
	}

	c1, err := p.Credentials(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if c1.AccessKeyID != "ASIA_TEST" || c1.SessionToken == "" {
		t.Fatalf("creds: %+v", c1)
	}

	// Second call within TTL: must not re-hit network.
	c2, err := p.Credentials(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if c2 != c1 {
		t.Fatal("expected cached creds reused")
	}
	if getIDCalls != 1 || getCredsCalls != 1 {
		t.Fatalf("cached call re-hit network: id=%d creds=%d", getIDCalls, getCredsCalls)
	}

	// Force refresh after Invalidate.
	p.Invalidate()
	_, _ = p.Credentials(context.Background())
	if getIDCalls != 2 || getCredsCalls != 2 {
		t.Fatalf("Invalidate did not force re-issue: id=%d creds=%d", getIDCalls, getCredsCalls)
	}
}

func TestProviderTargetAndContentType(t *testing.T) {
	var sawCT, sawTarget string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawCT = r.Header.Get("Content-Type")
		sawTarget = r.Header.Get("x-amz-target")
		if strings.HasSuffix(sawTarget, "GetId") {
			_, _ = io.WriteString(w, `{"IdentityId":"x"}`)
		} else {
			_, _ = io.WriteString(w, jsonCredsExpIn(3600))
		}
	}))
	defer srv.Close()

	p := &Provider{HTTP: &hostRewriter{base: srv.URL, next: srv.Client()}}
	_, err := p.Credentials(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if sawCT != "application/x-amz-json-1.1" {
		t.Errorf("Content-Type: %s", sawCT)
	}
	if !strings.Contains(sawTarget, "GetCredentialsForIdentity") {
		t.Errorf("target: %s", sawTarget)
	}
}

func TestProviderExpiry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.Header.Get("x-amz-target"), "GetId") {
			_, _ = io.WriteString(w, `{"IdentityId":"x"}`)
			return
		}
		// Force expiry 1 second in the future so cachedTill ends up in the past
		// (cachedTill = exp - 5min).
		_, _ = io.WriteString(w, jsonCredsAt(time.Now().Add(time.Second)))
	}))
	defer srv.Close()
	p := &Provider{HTTP: &hostRewriter{base: srv.URL, next: srv.Client()}}
	if _, err := p.Credentials(context.Background()); err != nil {
		t.Fatal(err)
	}
	// cachedTill is now ~5 min ago. Next call must refresh.
	calls := 0
	srv.Close()
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if strings.HasSuffix(r.Header.Get("x-amz-target"), "GetId") {
			_, _ = io.WriteString(w, `{"IdentityId":"y"}`)
			return
		}
		_, _ = io.WriteString(w, jsonCredsExpIn(3600))
	}))
	defer srv2.Close()
	// Repoint
	p.HTTP = &hostRewriter{base: srv2.URL, next: srv2.Client()}
	if _, err := p.Credentials(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls == 0 {
		t.Fatal("expected refresh call after expiry")
	}
}

// jsonCredsExpIn / jsonCredsAt produce a fake GetCredentialsForIdentity body.
func jsonCredsExpIn(seconds int64) string {
	return jsonCredsAt(time.Now().Add(time.Duration(seconds) * time.Second))
}
func jsonCredsAt(t time.Time) string {
	out := map[string]any{
		"IdentityId": "us-east-1:abc-123",
		"Credentials": map[string]any{
			"AccessKeyId":  "ASIA_TEST",
			"SecretKey":    "secret",
			"SessionToken": "session-tok",
			"Expiration":   float64(t.Unix()),
		},
	}
	b, _ := json.Marshal(out)
	return string(b)
}

// hostRewriter sends all requests to a single base URL.
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
