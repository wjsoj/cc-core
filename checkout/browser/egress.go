// Package browser runs isolated Chromium sessions for checkout automation.
// It does not solve challenges, disguise automation, or infer paid status from
// a URL. User sessions must never share a Browser instance.
package browser

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/wjsoj/cc-core/checkout"
	"golang.org/x/net/proxy"
)

type dialContext func(context.Context, string, string) (net.Conn, error)

// Chromium cannot authenticate to SOCKS5 directly. Both direct and SOCKS modes
// use this private, CONNECT-only bridge. TLS stays end-to-end; no interception,
// Authorization headers, cookies or response bodies are read by the bridge.
// Unknown payment/bank hosts fail closed and require an explicit policy update.
type bridge struct {
	listener net.Listener
	server   *http.Server
	ctx      context.Context
	cancel   context.CancelFunc
	dial     dialContext
	mu       sync.Mutex
	closed   bool
	conns    map[net.Conn]struct{}
	slots    chan struct{}
	wg       sync.WaitGroup
}

var providerDomains = []string{
	"chatgpt.com", "openai.com", "oaistatic.com", "oaiusercontent.com",
	"stripe.com", "stripe.network", "hcaptcha.com",
}

func allowedTarget(authority string) bool {
	host, port, err := net.SplitHostPort(authority)
	if err != nil || port != "443" || strings.ContainsAny(host, "@/%\\\x00") {
		return false
	}
	host = strings.ToLower(host)
	if host == "challenges.cloudflare.com" {
		return true
	}
	for _, domain := range providerDomains {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}

// Exclude private, documentation, translation and reserved ranges. In direct
// mode every resolved address is checked before dialing a pinned IP, preventing
// DNS rebinding to the worker's private network.
var reserved = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001::/23"), netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"), netip.MustParsePrefix("3fff::/20"),
}

func publicIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.Zone() != "" {
		return false
	}
	if ip.Is6() && !netip.MustParsePrefix("2000::/3").Contains(ip) {
		return false
	}
	for _, p := range reserved {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

func egressDialer(raw string) (dialContext, error) {
	// Reuse the checkout contract; ignore ALL_PROXY/HTTP_PROXY/NO_PROXY.
	client, err := checkout.NewClient(raw)
	if err != nil {
		return nil, err
	}
	client.Close()
	d := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	if strings.TrimSpace(raw) == "" {
		return func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, errors.New("invalid destination")
			}
			ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
			if err != nil || len(ips) == 0 {
				return nil, errors.New("destination resolution failed")
			}
			for _, ip := range ips {
				if !publicIP(ip) {
					return nil, errors.New("private destination denied")
				}
			}
			return d.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
		}, nil
	}
	u, _ := url.Parse(strings.TrimSpace(raw))
	// The public HTTP service resolves, validates and pins the user proxy once
	// for both Go and Chromium. Never silently resolve it to a different IP here.
	ip, err := netip.ParseAddr(u.Hostname())
	if err != nil || !publicIP(ip) {
		return nil, errors.New("browser proxy must be a validated public IP")
	}
	return socksDialer(u, d)
}

func socksDialer(u *url.URL, forward proxy.Dialer) (dialContext, error) {
	var credentials *proxy.Auth
	if u.User != nil {
		password, _ := u.User.Password()
		credentials = &proxy.Auth{User: u.User.Username(), Password: password}
	}
	socks, err := proxy.SOCKS5("tcp", u.Host, credentials, forward)
	if err != nil {
		return nil, errors.New("invalid SOCKS5 configuration")
	}
	cd, ok := socks.(proxy.ContextDialer)
	if !ok {
		return nil, errors.New("SOCKS5 context support required")
	}
	// Passing the domain name to SOCKS5 delegates destination DNS to that proxy.
	return cd.DialContext, nil
}

func newBridge(parent context.Context, dial dialContext) (*bridge, error) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, errors.New("cannot start browser egress")
	}
	ctx, cancel := context.WithCancel(parent)
	b := &bridge{listener: l, ctx: ctx, cancel: cancel, dial: dial, conns: make(map[net.Conn]struct{}), slots: make(chan struct{}, 64)}
	b.server = &http.Server{Handler: b, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 8192}
	b.wg.Add(1)
	go func() { defer b.wg.Done(); _ = b.server.Serve(l) }()
	return b, nil
}

func (b *bridge) address() string { return "http://" + b.listener.Addr().String() }

func (b *bridge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect || !allowedTarget(r.Host) || r.URL.Host != r.Host {
		http.Error(w, "destination denied", http.StatusForbidden)
		return
	}
	select {
	case b.slots <- struct{}{}:
		defer func() { <-b.slots }()
	default:
		http.Error(w, "busy", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(b.ctx, 15*time.Second)
	upstream, err := b.dial(ctx, "tcp", r.Host)
	cancel()
	if err != nil {
		// Never include the dial error: it can contain proxy credentials.
		http.Error(w, "egress unavailable", http.StatusBadGateway)
		return
	}
	defer upstream.Close()
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "tunnel unavailable", 500)
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer client.Close()
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.conns[client] = struct{}{}
	b.conns[upstream] = struct{}{}
	b.wg.Add(1)
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		delete(b.conns, client)
		delete(b.conns, upstream)
		b.mu.Unlock()
		b.wg.Done()
	}()
	deadline := time.Now().Add(20 * time.Minute)
	_ = client.SetDeadline(deadline)
	_ = upstream.SetDeadline(deadline)
	if _, err = buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if buffered.Flush() != nil {
		return
	}
	done := make(chan struct{})
	go func() { _, _ = io.Copy(upstream, buffered); _ = upstream.Close(); close(done) }()
	_, _ = io.Copy(client, upstream)
	_ = client.Close()
	_ = upstream.Close()
	<-done
}

func (b *bridge) close() {
	b.mu.Lock()
	if !b.closed {
		b.closed = true
		b.cancel()
		for c := range b.conns {
			_ = c.Close()
		}
	}
	b.mu.Unlock()
	_ = b.server.Close()
	b.wg.Wait()
}
