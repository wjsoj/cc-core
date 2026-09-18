package browser

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type dialFixture func(string, string) (net.Conn, error)

func (d dialFixture) Dial(network, address string) (net.Conn, error) { return d(network, address) }

func TestSOCKSAuthenticationAndRemoteDNS(t *testing.T) {
	u, _ := url.Parse("socks5://fixture_user:fixture_pass@8.8.8.8:1080")
	seen := make(chan bool, 1)
	dial, err := socksDialer(u, dialFixture(func(network, address string) (net.Conn, error) {
		if address != "8.8.8.8:1080" {
			return nil, errors.New("proxy endpoint changed")
		}
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			_ = server.SetDeadline(time.Now().Add(3 * time.Second))
			rd := bufio.NewReader(server)
			read := func(n int) []byte {
				data := make([]byte, n)
				if _, err := io.ReadFull(rd, data); err != nil {
					return nil
				}
				return data
			}
			header := read(2)
			if len(header) != 2 || header[0] != 5 {
				seen <- false
				return
			}
			if read(int(header[1])) == nil {
				seen <- false
				return
			}
			_, _ = server.Write([]byte{5, 2})
			auth := read(2)
			if len(auth) != 2 || auth[0] != 1 {
				seen <- false
				return
			}
			user := read(int(auth[1]))
			length := read(1)
			if len(length) != 1 {
				seen <- false
				return
			}
			pass := read(int(length[0]))
			_, _ = server.Write([]byte{1, 0})
			header = read(5)
			if len(header) != 5 || header[0] != 5 || header[1] != 1 || header[3] != 3 {
				seen <- false
				return
			}
			host := read(int(header[4]))
			port := read(2)
			ok := string(user) == "fixture_user" && string(pass) == "fixture_pass" && string(host) == "api.stripe.com" && len(port) == 2 && port[0] == 1 && port[1] == 187
			_, _ = server.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
			seen <- ok
		}()
		return client, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := dial(ctx, "tcp", "api.stripe.com:443")
	if err != nil {
		t.Fatal("SOCKS handshake failed")
	}
	conn.Close()
	if !<-seen {
		t.Fatal("SOCKS credentials or destination domain not preserved")
	}
}

func TestDestinationPolicy(t *testing.T) {
	for _, host := range []string{"chatgpt.com:443", "api.stripe.com:443", "js.stripe.com:443", "newassets.hcaptcha.com:443", "challenges.cloudflare.com:443"} {
		if !allowedTarget(host) {
			t.Fatalf("allowed target rejected: %s", host)
		}
	}
	for _, host := range []string{"evilstripe.com:443", "chatgpt.com.evil.test:443", "chatgpt.com:80", "chatgpt.com.:443", "127.0.0.1:443", "[::1]:443", "user@chatgpt.com:443", "cloudflare.com:443", "https://chatgpt.com:443", "chatgpt.com:443/path"} {
		if allowedTarget(host) {
			t.Fatalf("forbidden target allowed: %s", host)
		}
	}
}

func TestPublicIPs(t *testing.T) {
	for _, addr := range []string{"127.0.0.1", "::1", "::ffff:127.0.0.1", "10.0.0.1", "169.254.169.254", "192.0.2.1", "198.18.1.1", "100.64.0.1", "2001:db8::1", "64:ff9b::808:808", "fc00::1", "240.0.0.1"} {
		if publicIP(netip.MustParseAddr(addr)) {
			t.Fatalf("private/reserved address allowed: %s", addr)
		}
	}
	if !publicIP(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("public IPv4 rejected")
	}
}

func TestProxyRequiresPinnedPublicIP(t *testing.T) {
	for _, raw := range []string{"socks5://localhost:1080", "socks5://127.0.0.1:1080", "http://8.8.8.8:80", "socks5://user:secret@10.0.0.1:1080"} {
		if _, err := egressDialer(raw); err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatal("proxy validation or redaction failed")
		}
	}
	// Constructing a dialer performs no connection and does not use env proxies.
	t.Setenv("ALL_PROXY", "http://invalid.local:1")
	for _, raw := range []string{"", "socks5://user:secret@8.8.8.8:1080", "socks5h://8.8.8.8:1080"} {
		if _, err := egressDialer(raw); err != nil {
			t.Fatal(err)
		}
	}
}

func connect(t *testing.T, b *bridge, target string) (net.Conn, *bufio.Reader, *http.Response) {
	t.Helper()
	c, err := net.DialTimeout("tcp", b.listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	if err != nil {
		t.Fatal(err)
	}
	rd := bufio.NewReader(c)
	res, err := http.ReadResponse(rd, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	return c, rd, res
}

func TestBridgeTunnelsHostnameAndCloses(t *testing.T) {
	var target string
	var calls atomic.Int32
	b, err := newBridge(context.Background(), func(_ context.Context, network, address string) (net.Conn, error) {
		target = address
		calls.Add(1)
		client, server := net.Pipe()
		go func() { defer server.Close(); _, _ = io.Copy(server, server) }()
		return client, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.close)
	c, rd, res := connect(t, b, "api.stripe.com:443")
	if res.StatusCode != 200 || calls.Load() != 1 || target != "api.stripe.com:443" {
		t.Fatal("tunnel destination changed")
	}
	_, _ = c.Write([]byte("fixture"))
	value := make([]byte, 7)
	if _, err = io.ReadFull(rd, value); err != nil || string(value) != "fixture" {
		t.Fatal("tunnel failed")
	}
	b.close()
	if _, err = c.Read(make([]byte, 1)); err == nil {
		t.Fatal("tunnel survived close")
	}
}

func TestBridgeRejectsBeforeDialAndNeverFallsBack(t *testing.T) {
	var calls atomic.Int32
	b, err := newBridge(context.Background(), func(context.Context, string, string) (net.Conn, error) {
		calls.Add(1)
		return nil, errors.New("socks5://user:secret@proxy")
	})
	if err != nil {
		t.Fatal(err)
	}
	defer b.close()
	_, _, res := connect(t, b, "127.0.0.1:443")
	if res.StatusCode != 403 || calls.Load() != 0 {
		t.Fatal("forbidden destination was dialed")
	}
	res.Body.Close()
	_, _, res = connect(t, b, "chatgpt.com:443")
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != 502 || calls.Load() != 1 || strings.Contains(string(body), "secret") {
		t.Fatal("failed proxy was retried or disclosed")
	}
}
