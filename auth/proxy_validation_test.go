package auth

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestValidateProxyURL(t *testing.T) {
	for _, value := range []string{"", "http://proxy.example", "https://user:pass@proxy.example:8443", "socks5://127.0.0.1:1080", "socks5h://[::1]:1080"} {
		if err := ValidateProxyURL(value); err != nil {
			t.Fatalf("valid %q: %v", value, err)
		}
	}
	for _, value := range []string{"proxy.example:8080", "ftp://proxy.example", "http://", "http://proxy.example/path", "http://proxy.example?q=1", "socks5://proxy.example", " http://proxy.example"} {
		if err := ValidateProxyURL(value); err == nil {
			t.Fatalf("invalid proxy accepted: %q", value)
		}
	}
}

func TestCredentialParsingAndLoginRejectInvalidProxy(t *testing.T) {
	body := []byte(`{"type":"claude","access_token":"token","refresh_token":"refresh","account_uuid":"account","proxy_url":"ftp://proxy.example"}`)
	if _, err := ParseFile("credential.json", body); err == nil {
		t.Fatal("credential parser accepted invalid proxy")
	}
	if _, _, err := StartLogin(ProviderAnthropic, "ftp://proxy.example", "label"); err == nil {
		t.Fatal("login session accepted invalid proxy")
	}
}

func TestInvalidConfiguredProxyNeverDialsDirect(t *testing.T) {
	var directCalls int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		directCalls++
		_, _ = io.WriteString(w, "unexpected")
	}))
	defer upstream.Close()

	for _, client := range []*http.Client{
		ClientFor("://bad proxy", false),
		ClientFor("://bad proxy", true),
		NewPlainHTTPClient("://bad proxy", false),
		NewPlainHTTPClient("://bad proxy", true),
	} {
		req, _ := http.NewRequest(http.MethodGet, upstream.URL, nil)
		if _, err := client.Do(req); err == nil || !strings.Contains(err.Error(), "invalid configured proxy") {
			t.Fatalf("invalid proxy did not fail closed: %v", err)
		}
	}
	if directCalls != 0 {
		t.Fatalf("invalid proxy fell back to direct transport: calls=%d", directCalls)
	}
}

func TestConfiguredProxyConnectionFailureNeverDialsTarget(t *testing.T) {
	var directCalls int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		directCalls++
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxyURL := "http://" + listener.Addr().String()
	_ = listener.Close()
	client := ClientFor(proxyURL, false)
	client.Timeout = time.Second
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, upstream.URL, nil)
	if _, err := client.Do(req); err == nil {
		t.Fatal("dead configured proxy unexpectedly succeeded")
	}
	if directCalls != 0 {
		t.Fatalf("dead proxy fell back to target directly: calls=%d", directCalls)
	}
}

func TestConfiguredProxyAuthenticationFailureNeverDialsTarget(t *testing.T) {
	var directCalls int
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		directCalls++
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Proxy-Authenticate", `Basic realm="test"`)
		w.WriteHeader(http.StatusProxyAuthRequired)
	}))
	defer proxyServer.Close()

	client := ClientFor(proxyServer.URL, false)
	req, _ := http.NewRequest(http.MethodGet, target.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("proxy auth status=%d", resp.StatusCode)
	}
	if directCalls != 0 {
		t.Fatalf("proxy auth failure fell back to target directly: calls=%d", directCalls)
	}
}
