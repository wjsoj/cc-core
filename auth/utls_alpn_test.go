package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

// newLocalhostTLS mints a self-signed cert for "localhost" and returns the
// server cert plus a RootCAs pool that trusts it, so the test verifies the
// chain normally (no InsecureSkipVerify).
func newLocalhostTLS(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// dialUTLSWithALPN replicates DialTLSConn's uTLS branch (Chrome preset + the
// ALPN override) against a local server, verifying against the supplied roots.
// It proves the override makes the wire ClientHello advertise only the requested
// protocols even though the Chrome parrot hardcodes [h2,http/1.1].
func dialUTLSWithALPN(t *testing.T, addr string, roots *x509.CertPool, nextProtos []string) string {
	t.Helper()
	raw, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatalf("tcp dial: %v", err)
	}
	uc := utls.UClient(raw, &utls.Config{ServerName: "localhost", RootCAs: roots, NextProtos: nextProtos}, utls.HelloChrome_Auto)
	if len(nextProtos) > 0 {
		if err := uc.BuildHandshakeState(); err != nil {
			t.Fatalf("build handshake: %v", err)
		}
		for _, ext := range uc.Extensions {
			if alpn, ok := ext.(*utls.ALPNExtension); ok {
				alpn.AlpnProtocols = nextProtos
			}
		}
	}
	if err := uc.HandshakeContext(context.Background()); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer uc.Close()
	return uc.ConnectionState().NegotiatedProtocol
}

// TestUTLSALPNOverride verifies the fix for the Codex WebSocket dial: a server
// that supports both h2 and http/1.1 must negotiate http/1.1 when we pin it, and
// h2 when we offer the full Chrome list. Without the override the Chrome parrot
// always advertised [h2,http/1.1] and the server picked h2 — answering a WS
// Upgrade with an HTTP/2 SETTINGS frame ("malformed HTTP response").
func TestUTLSALPNOverride(t *testing.T) {
	cert, roots := newLocalhostTLS(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if tc, ok := c.(*tls.Conn); ok {
				_ = tc.HandshakeContext(context.Background())
			}
			_ = c.Close()
		}
	}()

	if got := dialUTLSWithALPN(t, ln.Addr().String(), roots, []string{"http/1.1"}); got != "http/1.1" {
		t.Errorf("pinned http/1.1: negotiated %q, want http/1.1 (ALPN override not applied)", got)
	}
	if got := dialUTLSWithALPN(t, ln.Addr().String(), roots, []string{"h2", "http/1.1"}); got != "h2" {
		t.Errorf("full list: negotiated %q, want h2", got)
	}
}
