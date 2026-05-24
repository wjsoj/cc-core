package kiroauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPKCEChallengeMatchesVerifier(t *testing.T) {
	p, err := NewPKCE()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(p.Verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if p.Challenge != want {
		t.Fatalf("challenge: got %s want %s", p.Challenge, want)
	}
	if len(p.State) == 0 || len(p.State) > 11 {
		t.Fatalf("state length unexpected: %q", p.State)
	}
}

func TestSignInURLShape(t *testing.T) {
	p := PKCE{Verifier: "v", Challenge: "ch", State: "st"}
	url := SignInURL(p, "http://localhost:3128")
	for _, want := range []string{
		"https://app.kiro.dev/signin",
		"state=st",
		"code_challenge=ch",
		"code_challenge_method=S256",
		"redirect_uri=http%3A%2F%2Flocalhost%3A3128",
		"redirect_from=kirocli",
	} {
		if !strings.Contains(url, want) {
			t.Fatalf("missing %q in %s", want, url)
		}
	}
}

func TestCanonicalizeAuthMethod(t *testing.T) {
	tests := map[string]AuthMethod{
		"Social":     "social",
		"IDC":        AuthIdC,
		"builder-id": AuthIdC,
		"IAM":        AuthIdC,
		"api_key":    AuthAPIKey,
		"APIKEY":     AuthAPIKey,
		"":           "",
	}
	for in, want := range tests {
		if got := canonicalizeAuthMethod(in); got != want {
			t.Errorf("canonicalize(%q): got %q want %q", in, got, want)
		}
	}
}

func TestCredentialsMethodAndAPIKey(t *testing.T) {
	c := Credentials{KiroAPIKey: "ksk_abc"}
	if !c.IsAPIKey() || c.Method() != AuthAPIKey {
		t.Fatalf("kiro api key not detected")
	}
	c = Credentials{AuthMethod: "Social"}
	if c.Method() != AuthSocial {
		t.Fatalf("social method: got %q", c.Method())
	}
	c = Credentials{}
	if c.Method() != AuthSocial {
		t.Fatalf("default method should be social, got %q", c.Method())
	}
}

func TestEffectiveRegions(t *testing.T) {
	c := Credentials{Region: "eu-west-1"}
	if got := c.EffectiveAuthRegion(""); got != "eu-west-1" {
		t.Fatalf("auth region: %q", got)
	}
	if got := c.EffectiveAPIRegion("ap-northeast-1"); got != "ap-northeast-1" {
		t.Fatalf("api region should NOT fall through to .Region, got %q", got)
	}
	c.APIRegion = "us-west-2"
	if got := c.EffectiveAPIRegion("us-east-1"); got != "us-west-2" {
		t.Fatalf("api region override: %q", got)
	}
	c2 := Credentials{}
	if got := c2.EffectiveAuthRegion(""); got != DefaultAuthRegion {
		t.Fatalf("default auth region: %q", got)
	}
}

func TestExpiry(t *testing.T) {
	c := Credentials{}
	if !c.IsExpired(0) {
		t.Fatal("empty ExpiresAt should be considered expired")
	}
	c.SetExpiresIn(time.Hour)
	if c.IsExpired(time.Minute) {
		t.Fatal("just-set 1h expiry should not be expired with 1m skew")
	}
	if !c.IsExpired(2 * time.Hour) {
		t.Fatal("1h expiry should look expired with 2h skew")
	}
}

func TestLoadSaveSingleAndMulti(t *testing.T) {
	dir := t.TempDir()
	pathSingle := filepath.Join(dir, "single.json")
	if err := os.WriteFile(pathSingle, []byte(`{"refreshToken":"r1","authMethod":"Social"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := Load(pathSingle)
	if err != nil {
		t.Fatal(err)
	}
	if f.IsArray() {
		t.Fatal("expected single form")
	}
	if got := f.All()[0]; got.RefreshToken != "r1" || got.AuthMethod != AuthSocial {
		t.Fatalf("parse single: %+v", got)
	}

	pathMulti := filepath.Join(dir, "multi.json")
	if err := os.WriteFile(pathMulti, []byte(`[
		{"refreshToken":"a","priority":2},
		{"refreshToken":"b","priority":0},
		{"refreshToken":"c","priority":1}
	]`), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err = Load(pathMulti)
	if err != nil {
		t.Fatal(err)
	}
	if !f.IsArray() {
		t.Fatal("expected array form")
	}
	got := f.Sorted()
	if got[0].RefreshToken != "b" || got[1].RefreshToken != "c" || got[2].RefreshToken != "a" {
		t.Fatalf("priority sort: %+v", got)
	}

	// Update + Save round-trip
	updated := got[0]
	updated.RefreshToken = "b-new"
	updated.AccessToken = "at"
	if err := f.Update(updated, "b"); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out.json")
	if err := f.Save(out); err != nil {
		t.Fatal(err)
	}
	reloaded, err := Load(out)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range reloaded.All() {
		if c.RefreshToken == "b-new" && c.AccessToken == "at" {
			found = true
		}
	}
	if !found {
		t.Fatalf("update not persisted: %+v", reloaded.All())
	}
}

func TestLoadMissingAndEmpty(t *testing.T) {
	dir := t.TempDir()
	f, err := Load(filepath.Join(dir, "nope.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.All()) != 0 {
		t.Fatal("missing file should yield empty")
	}
	empty := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(empty, []byte("   \n\t"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err = Load(empty)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.All()) != 0 {
		t.Fatal("empty file should yield empty")
	}
}

// captureRequest stores the last received request body for assertions.
type capturedRequest struct {
	Path string
	Body map[string]string
	UA   string
}

func TestExchangeCodeWireShape(t *testing.T) {
	var got capturedRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Path = r.URL.Path
		got.UA = r.Header.Get("User-Agent")
		_ = json.NewDecoder(r.Body).Decode(&got.Body)
		_, _ = io.WriteString(w, `{"accessToken":"at","refreshToken":"rt","profileArn":"arn:test","expiresIn":3600}`)
	}))
	defer srv.Close()

	c := &Client{HTTP: srv.Client()}
	// point all auth URLs at our test server via a custom HTTP transport that rewrites the URL
	c.HTTP = &urlRewriter{base: srv.URL, next: srv.Client()}

	tr, err := c.ExchangeCode(context.Background(), "code123", "verifier456", "http://localhost:3128/oauth/callback?login_option=github")
	if err != nil {
		t.Fatal(err)
	}
	if got.Path != "/oauth/token" {
		t.Fatalf("path: %s", got.Path)
	}
	if got.UA != DefaultUserAgent {
		t.Fatalf("UA: %s", got.UA)
	}
	if got.Body["code"] != "code123" || got.Body["code_verifier"] != "verifier456" {
		t.Fatalf("body: %+v", got.Body)
	}
	// /oauth/token MUST NOT carry grant_type, client_id, state — verified against capture.
	for _, illegal := range []string{"grant_type", "client_id", "state", "scope"} {
		if _, ok := got.Body[illegal]; ok {
			t.Errorf("/oauth/token should not send %q (per capture)", illegal)
		}
	}
	if tr.AccessToken != "at" || tr.RefreshToken != "rt" || tr.ProfileARN != "arn:test" || tr.ExpiresIn != 3600 {
		t.Fatalf("response parse: %+v", tr)
	}

	// Apply to creds
	cred := Credentials{}
	tr.ApplyTo(&cred)
	if cred.AccessToken != "at" || cred.RefreshToken != "rt" {
		t.Fatalf("ApplyTo: %+v", cred)
	}
	if cred.IsExpired(0) {
		t.Fatal("ApplyTo should set ExpiresAt to ~1h in future")
	}
}

func TestRefreshSocialMinimalBody(t *testing.T) {
	var got capturedRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Path = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&got.Body)
		_, _ = io.WriteString(w, `{"accessToken":"new-at","refreshToken":"new-rt","expiresIn":3600}`)
	}))
	defer srv.Close()
	c := &Client{HTTP: &urlRewriter{base: srv.URL, next: srv.Client()}}

	tr, err := c.RefreshSocial(context.Background(), "old-rt")
	if err != nil {
		t.Fatal(err)
	}
	if got.Path != "/refreshToken" {
		t.Fatalf("path: %s", got.Path)
	}
	if got.Body["refreshToken"] != "old-rt" || len(got.Body) != 1 {
		t.Fatalf("/refreshToken must send ONLY {refreshToken}: %+v", got.Body)
	}
	if tr.RefreshToken != "new-rt" {
		t.Fatal("refresh did not rotate")
	}
}

func TestLogoutEmptyResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	c := &Client{HTTP: &urlRewriter{base: srv.URL, next: srv.Client()}}
	if err := c.Logout(context.Background(), "rt"); err != nil {
		t.Fatal(err)
	}
}

func TestErrorResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"message":"invalid_grant"}`)
	}))
	defer srv.Close()
	c := &Client{HTTP: &urlRewriter{base: srv.URL, next: srv.Client()}}
	_, err := c.RefreshSocial(context.Background(), "bad")
	if err == nil {
		t.Fatal("expected error")
	}
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T", err)
	}
	if apiErr.StatusCode != 401 {
		t.Fatalf("status: %d", apiErr.StatusCode)
	}
}

// urlRewriter swaps the request host so all *.kiro.dev / *.amazonaws.com URLs
// end up hitting the test server, while preserving the path.
type urlRewriter struct {
	base string
	next *http.Client
}

func (r *urlRewriter) Do(req *http.Request) (*http.Response, error) {
	// Rewrite scheme+host to point at the httptest server.
	original := req.URL
	req.URL.Scheme = "http"
	parsed := mustParse(r.base)
	req.URL.Host = parsed.Host
	defer func() { req.URL = original }()
	return r.next.Do(req)
}

func mustParse(s string) *struct{ Host string } {
	// Tiny URL parse just for tests.
	out := &struct{ Host string }{}
	// Strip "http://"
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimPrefix(s, "https://")
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	out.Host = s
	return out
}
