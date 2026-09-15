package checkout

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wjsoj/cc-core/auth"
)

func TestProxyMandatory(t *testing.T) {
	for _, raw := range []string{"http://127.0.0.1:1234", "socks5://host", "socks5://host:0", "socks5://host:65536", "socks5://host:1080/path", "socks5://host:1080?bypass=1"} {
		if _, err := NewClient(raw); err == nil {
			t.Fatalf("accepted invalid proxy %q", raw)
		}
	}
}

// c.http.Transport is now *auth.utlsTransport (unexported), so this can no
// longer type-assert into *http.Transport and poke .Proxy / .DialContext —
// that broke the instant NewClient switched to auth.NewPlainHTTPClient.
// auth.DialTLSConn is the exact primitive utlsTransport.dialTLS calls, so
// exercising it directly with proxyURL="" proves the same property against
// the real dial path checkout.NewClient("") now uses, not a stand-in for it.
//
// A real net.Dialer never consults HTTP_PROXY-style env vars — only
// net/http's own ProxyFromEnvironment does, and DialTLSConn's direct branch
// is a bare net.Dialer — so this is close to unconditionally true. The env
// vars stay set anyway, as insurance against that changing silently.
func TestEmptyProxyMeansDirectIgnoringEnvironment(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("ALL_PROXY", "socks5://127.0.0.1:1")
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Not a TLS server: write garbage so the handshake fails fast and
		// definitively, on OUR listener, rather than the test hanging until
		// its context deadline trying to decide whether it connected at all.
		_, _ = conn.Write([]byte("not a tls server"))
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = auth.DialTLSConn(ctx, "localhost", l.Addr().String(), "", true, []string{"h2", "http/1.1"})
	if err == nil {
		t.Fatal("expected a TLS handshake failure against a non-TLS listener")
	}
	// Port 1 is refused (unprivileged) or times out — either way the error
	// text names it, or the dial simply never reaches our listener within
	// the deadline. A TLS-handshake-shaped error, in contrast, can only
	// happen after our listener's garbage bytes were actually read.
	if strings.Contains(err.Error(), "127.0.0.1:1") || strings.Contains(err.Error(), "refused") || strings.Contains(err.Error(), "deadline exceeded") {
		t.Fatalf("direct connection used an environment proxy (or never reached the real listener): %v", err)
	}
}

// A local SOCKS fixture forwards to a local TLS fixture. No test reaches
// ChatGPT/Stripe. It records the exact remote-DNS names carried by SOCKS5 —
// the property this test exists for.
//
// It can no longer also prove "redirects are not followed" or "a non-
// allowlisted host is rejected" through a live round trip: uTLS's dial path
// (auth.DialTLSConn) builds utls.Config{ServerName: host} itself with no
// hook to inject a trusted local CA, so the TLS handshake against this
// fixture's self-signed cert is *expected* to fail now — which is fine for
// proving the SOCKS5 CONNECT carried the right hostname (that happens before
// TLS even starts), but leaves no successful response to redirect from.
// Those two properties still hold and are still covered — as unit tests
// below that don't need a live request at all: the host allowlist check in
// request() runs before any dial (TestNonAllowlistedHostNeverDials), and
// CheckRedirect is a plain field on c.http we can call directly
// (TestRedirectsAreNeverFollowed).
func TestAllHostsUseSOCKSRemoteDNS(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var mu sync.Mutex
	var targets []string
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, e := listener.Accept()
			if e != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				h := make([]byte, 2)
				if _, e = io.ReadFull(conn, h); e != nil {
					return
				}
				methods := make([]byte, int(h[1]))
				if _, e = io.ReadFull(conn, methods); e != nil {
					return
				}
				_, _ = conn.Write([]byte{5, 0})
				head := make([]byte, 5)
				if _, e = io.ReadFull(conn, head); e != nil {
					return
				}
				if head[3] != 3 {
					return
				}
				host := make([]byte, int(head[4]))
				if _, e = io.ReadFull(conn, host); e != nil {
					return
				}
				port := make([]byte, 2)
				if _, e = io.ReadFull(conn, port); e != nil {
					return
				}
				mu.Lock()
				targets = append(targets, string(host))
				mu.Unlock()
				dst, e := net.Dial("tcp", upstream.Listener.Addr().String())
				if e != nil {
					return
				}
				defer dst.Close()
				_, _ = conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
				done := make(chan struct{})
				go func() { _, _ = io.Copy(dst, conn); close(done) }()
				_, _ = io.Copy(conn, dst)
				_ = conn.Close()
				<-done
			}()
		}
	}()
	t.Setenv("HTTPS_PROXY", "http://invalid.invalid:1")
	t.Setenv("NO_PROXY", "*")
	c, err := NewClient("socks5h://" + listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Every request below is expected to FAIL the TLS handshake — the
	// fixture's self-signed cert has no path to a trust anchor uTLS's
	// ClientHello was built with — but the SOCKS5 CONNECT that carries the
	// hostname happens before TLS starts, so the failure doesn't cost us
	// the one thing this test verifies.
	for _, host := range []string{"chatgpt.com", "api.stripe.com"} {
		var out map[string]bool
		if err = c.request(context.Background(), "", "https://"+host+"/test", nil, false, &out); err == nil {
			t.Fatal("expected a TLS trust failure against the untrusted local fixture")
		}
	}
	_ = listener.Close()
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(targets, ",") != "chatgpt.com,api.stripe.com" {
		t.Fatalf("SOCKS5 CONNECT did not carry the hostname (DNS resolved locally instead?): %v", targets)
	}
}

// The host allowlist in request() is a plain string comparison that runs
// before url.Parse's result is used for anything else — no dial, no proxy,
// no TLS. Proven here with no network at all, which also means it holds
// regardless of what transport backs c.http.
func TestNonAllowlistedHostNeverDials(t *testing.T) {
	c, err := NewClient("")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var out any
	if err := c.request(context.Background(), "", "https://example.invalid/steal", nil, false, &out); err == nil {
		t.Fatal("host escape accepted")
	}
}

// CheckRedirect is a plain field on c.http — calling it directly proves
// redirects are refused without needing a live server to redirect from.
func TestRedirectsAreNeverFollowed(t *testing.T) {
	c, err := NewClient("")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.http.CheckRedirect == nil {
		t.Fatal("CheckRedirect must be set — the default net/http policy follows redirects")
	}
	req, _ := http.NewRequest(http.MethodGet, "https://chatgpt.com/redirected", nil)
	if err := c.http.CheckRedirect(req, nil); err != http.ErrUseLastResponse {
		t.Fatalf("CheckRedirect = %v, want http.ErrUseLastResponse (stop, don't follow)", err)
	}
}
func TestProxyFailureIsRedactedAndNoFallback(t *testing.T) {
	// Port is closed; a direct fallback would incorrectly reach the upstream.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	_ = listener.Close()
	c, err := NewClient("socks5://privateuser:privatepass@" + addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var out any
	err = c.request(ctx, "privateauth", "https://chatgpt.com/test", nil, false, &out)
	if err == nil {
		t.Fatal("proxy failure accepted")
	}
	for _, secret := range []string{"privateuser", "privatepass", "privateauth", addr} {
		if strings.Contains(err.Error(), secret) {
			t.Fatal("secret exposed")
		}
	}
	// The old "MinVersion == TLS 1.2" check doesn't translate: uTLS
	// negotiates via a real Chrome ClientHello (HelloChrome_Auto) rather
	// than a configurable crypto/tls.Config, and a current Chrome install
	// doesn't offer TLS 1.0/1.1 to begin with — there is no equivalent
	// "weak TLS" misconfiguration left to catch here.
}
