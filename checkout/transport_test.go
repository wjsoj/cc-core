package checkout

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestProxyMandatory(t *testing.T) {
	for _, raw := range []string{"http://127.0.0.1:1234", "socks5://host", "socks5://host:0", "socks5://host:65536", "socks5://host:1080/path", "socks5://host:1080?bypass=1"} {
		if _, err := NewClient(raw); err == nil {
			t.Fatalf("accepted invalid proxy %q", raw)
		}
	}
}

func TestEmptyProxyMeansDirectIgnoringEnvironment(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("ALL_PROXY", "socks5://127.0.0.1:1")
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	c, err := NewClient("  ")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	tr := c.http.Transport.(*http.Transport)
	if tr.Proxy != nil {
		t.Fatal("direct mode must not use environment proxies")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := tr.DialContext(ctx, "tcp", l.Addr().String())
	if err != nil {
		t.Fatal("direct connection used an environment proxy")
	}
	defer conn.Close()
}

// A local SOCKS fixture forwards only to a local TLS fixture. No test reaches
// ChatGPT/Stripe. It records the exact remote-DNS names carried by SOCKS5.
func TestAllHostsUseSOCKSRemoteDNS(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/redirect" {
			w.Header().Set("Location", "https://example.invalid/steal")
			w.WriteHeader(302)
			return
		}
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
	// Trust only the local fixture; ServerName changes only in this test, leaving
	// the production default TLS validation intact.
	fixtureTLS := upstream.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	fixtureTLS.ServerName = "example.com"
	c.http.Transport.(*http.Transport).TLSClientConfig = fixtureTLS
	c.http.Transport.(*http.Transport).DisableKeepAlives = true
	for _, host := range []string{"chatgpt.com", "api.stripe.com"} {
		var out map[string]bool
		if err = c.request(context.Background(), "", "https://"+host+"/test", nil, false, &out); err != nil {
			t.Fatal(err)
		}
	}
	var out any
	if err = c.request(context.Background(), "", "https://chatgpt.com/redirect", nil, false, &out); err == nil {
		t.Fatal("redirect accepted")
	}
	if err = c.request(context.Background(), "", "https://example.invalid/steal", nil, false, &out); err == nil {
		t.Fatal("host escape accepted")
	}
	c.Close()
	_ = listener.Close()
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(targets, ",") != "chatgpt.com,api.stripe.com,chatgpt.com" {
		t.Fatalf("unexpected targets: %v", targets)
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
	if c.http.Transport.(*http.Transport).TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatal("weak TLS")
	}
}
