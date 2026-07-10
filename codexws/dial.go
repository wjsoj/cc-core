// Package codexws is the Codex-over-WebSocket upstream transport. Real
// codex-tui 0.141.0 streams a turn over a WebSocket
// (OpenAI-Beta: responses_websockets=2026-02-06,
// wss://chatgpt.com/backend-api/codex/responses) rather than the legacy HTTP
// POST /responses SSE path. A long-lived WebSocket carries protocol-level
// ping/pong, so it survives the multi-second silent gaps (reasoning -> answer,
// tool thinking) that truncate an idle HTTP SSE stream and surface to clients
// as "stream disconnected before completion".
//
// The handshake reuses cc-core's Chrome uTLS fingerprint (auth.DialTLSConn with
// ALPN forced to http/1.1, since a WebSocket Upgrade cannot run over h2), so the
// WS path stays byte-identical to the HTTP path that already evades Cloudflare
// JA3/JA4 fingerprinting. gorilla/websocket is used because its
// Dialer.NetDialTLSContext hook is the only clean way to hand a pre-handshaked
// uTLS conn to a WebSocket client; coder/websocket only exposes an *http.Client.
package codexws

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	gorillaws "github.com/gorilla/websocket"

	"github.com/wjsoj/cc-core/auth"
)

const (
	// defaultReadLimit caps a single inbound WS message. Codex events such as
	// rate_limits snapshots or large deltas exceed gorilla's 32KB default, so we
	// lift it to 16 MiB to match real codex-tui tolerances.
	defaultReadLimit = 16 << 20
	// defaultHandshakeTimeout bounds the TLS + WS upgrade.
	defaultHandshakeTimeout = 10 * time.Second
)

// Message-type constants re-exported so app callers depend only on codexws, not
// gorilla/websocket directly.
const (
	TextMessage   = gorillaws.TextMessage
	BinaryMessage = gorillaws.BinaryMessage
	CloseMessage  = gorillaws.CloseMessage
	PingMessage   = gorillaws.PingMessage
	PongMessage   = gorillaws.PongMessage
)

// DialConfig configures a single upstream WebSocket handshake.
type DialConfig struct {
	URL       string        // wss://chatgpt.com/backend-api/codex/responses
	Header    http.Header   // handshake headers (see BuildUpstreamHeaders)
	ProxyURL  string        // per-credential proxy (a.ProxyURL); "" = direct
	UseUTLS   bool          // true => Chrome uTLS ClientHello; false => crypto/tls
	Timeout   time.Duration // handshake budget; 0 => 10s
	ReadLimit int64         // single-message cap; 0 => 16 MiB
}

// Conn is the upstream WebSocket handed to the app layer. gorilla's concurrency
// contract applies: at most one concurrent reader and one concurrent writer; the
// caller must serialize ReadMessage and serialize the write methods. Ping and
// Close are safe to call concurrently with reads and writes.
type Conn interface {
	WriteJSON(v any) error
	WriteMessage(messageType int, data []byte) error
	ReadMessage() (messageType int, p []byte, err error)
	Ping(deadline time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
	// HandshakeResponse is the upstream's 101 (or non-101) response: status +
	// headers (cf-ray, x-request-id, x-codex-* rate limits) for logging and
	// 401/403/429 health classification.
	HandshakeResponse() *http.Response
	Close() error
}

// Dial completes the uTLS (or std-TLS) handshake with ALPN=http/1.1, then the
// WebSocket Upgrade over that conn. On a non-101 upstream reply it returns the
// *http.Response (with err) so callers can read the error body and classify the
// credential (401/403/429 -> Pool.ReportUpstreamError).
func Dial(ctx context.Context, cfg DialConfig) (Conn, *http.Response, error) {
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, nil, fmt.Errorf("codexws: parse url %q: %w", cfg.URL, err)
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	addr := net.JoinHostPort(host, port)

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultHandshakeTimeout
	}

	dialer := &gorillaws.Dialer{
		HandshakeTimeout: timeout,
		ReadBufferSize:   4096,
		WriteBufferSize:  4096,
		// Real codex-tui negotiates permessage-deflate; advertising it keeps the
		// WS upgrade fingerprint close to the genuine client.
		EnableCompression: true,
		// gorilla passes the URL host:port; we ignore it and dial our parsed
		// host/addr so the uTLS ServerName (SNI) is set correctly. Returning an
		// already-handshaked TLS conn tells gorilla to skip its own TLS.
		NetDialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return auth.DialTLSConn(ctx, host, addr, cfg.ProxyURL, cfg.UseUTLS, []string{"http/1.1"})
		},
	}

	ws, resp, err := dialer.DialContext(ctx, cfg.URL, cfg.Header)
	if err != nil {
		return nil, resp, err
	}
	limit := cfg.ReadLimit
	if limit <= 0 {
		limit = defaultReadLimit
	}
	ws.SetReadLimit(limit)
	return &gorillaConn{ws: ws, resp: resp}, resp, nil
}

// IsUnexpectedClose reports whether err is an abnormal WebSocket close (i.e. the
// stream dropped without a clean 1000/1001/1005 close), distinguishing a real
// disconnect from an orderly end-of-turn.
func IsUnexpectedClose(err error) bool {
	return gorillaws.IsUnexpectedCloseError(err,
		gorillaws.CloseNormalClosure,
		gorillaws.CloseGoingAway,
		gorillaws.CloseNoStatusReceived,
	)
}

type gorillaConn struct {
	ws   *gorillaws.Conn
	resp *http.Response
}

func (c *gorillaConn) WriteJSON(v any) error { return c.ws.WriteJSON(v) }
func (c *gorillaConn) WriteMessage(messageType int, d []byte) error {
	return c.ws.WriteMessage(messageType, d)
}
func (c *gorillaConn) ReadMessage() (int, []byte, error)  { return c.ws.ReadMessage() }
func (c *gorillaConn) SetReadDeadline(t time.Time) error  { return c.ws.SetReadDeadline(t) }
func (c *gorillaConn) SetWriteDeadline(t time.Time) error { return c.ws.SetWriteDeadline(t) }
func (c *gorillaConn) HandshakeResponse() *http.Response  { return c.resp }
func (c *gorillaConn) Close() error                       { return c.ws.Close() }

func (c *gorillaConn) Ping(deadline time.Time) error {
	return c.ws.WriteControl(gorillaws.PingMessage, nil, deadline)
}
