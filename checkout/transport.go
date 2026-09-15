// Package checkout implements the captured ChatGPT checkout protocol. These are
// private upstream endpoints, not a supported OpenAI public API.
package checkout

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/wjsoj/cc-core/auth"
)

// Client has one immutable egress path for its entire lifetime. Neither proxy
// environment variables nor NO_PROXY are consulted.
type Client struct{ http *http.Client }

// NewClient uses direct connections when proxyURL is empty, otherwise the
// specified SOCKS5 endpoint exclusively (optionally user:password). Proxy
// failures never fall back to direct connections.
// socks5 and socks5h BOTH resolve upstream hostnames at the proxy. The proxy
// hostname itself, if not an IP literal, must be resolved locally.
//
// The validation below is stricter than auth.ValidateProxyURL (which also
// accepts http/https proxies and is more permissive on shape) — this is the
// security boundary for a visitor-supplied proxy URL on a public endpoint,
// and it stays exactly as it always has. Only the transport built AFTER
// validation passes changed — see newHTTPClient.
func NewClient(proxyURL string) (*Client, error) {
	proxyURL = strings.TrimSpace(proxyURL)
	if proxyURL != "" {
		u, err := url.Parse(proxyURL)
		if err != nil || u == nil || (u.Scheme != "socks5" && u.Scheme != "socks5h") || u.Hostname() == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
			return nil, errors.New("必须配置 socks5://[用户名:密码@]主机:端口")
		}
		port, err := strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return nil, errors.New("SOCKS5 端口无效")
		}
		if u.User != nil {
			password, _ := u.User.Password()
			if len(u.User.Username()) == 0 || len(u.User.Username()) > 255 || len(password) > 255 {
				return nil, errors.New("SOCKS5 凭据格式无效")
			}
		}
	}
	return newHTTPClient(proxyURL), nil
}

// newHTTPClient uses auth.NewPlainHTTPClient(proxyURL, true) instead of a
// bespoke crypto/tls transport. Earlier requests returned 403 HTML, but this
// alone does not establish the cause or prove that changing TLS fixes it.
// Browser verification, authorization and payment eligibility remain upstream
// decisions. This client neither solves challenges nor retries around them.
//
// NewPlainHTTPClient — not the pooled, cached ClientFor — matches how this
// Client is actually used: checkout.NewClient is already called fresh per
// gptpay request and torn down at the end of it (Service.client / Close),
// so there is no cross-request connection here to pool in the first place.
// Pooled reuse is also documented as the cause of "connection reset by
// peer" against chatgpt.com/backend-api specifically (ClientFor's own doc
// comment), which this sidesteps by construction.
func newHTTPClient(proxyURL string) *Client {
	c := auth.NewPlainHTTPClient(proxyURL, true)
	c.Timeout = 60 * time.Second
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{http: c}
}

func (c *Client) Close() { c.http.CloseIdleConnections() }

// Errors deliberately exclude URL, proxy credentials, upstream bodies and PAN.
func (c *Client) request(ctx context.Context, token, target string, body io.Reader, form bool, out any) error {
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "https" || (u.Host != "chatgpt.com" && u.Host != "api.stripe.com") || u.User != nil || u.Fragment != "" {
		return errors.New("禁止访问非支付上游")
	}
	method := http.MethodGet
	if body != nil {
		method = http.MethodPost
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return errors.New("请求参数无效")
	}
	// Prevent automatic replay of financial POSTs even if a transport supports it.
	req.GetBody = nil
	req.Header.Set("User-Agent", "GPTPay/1.0")
	req.Header.Set("Accept", "application/json")
	// The shared transport does not guarantee automatic decompression. Request
	// identity rather than advertising browser encodings we cannot decode.
	req.Header.Set("Accept-Encoding", "identity")
	if token != "" && u.Host == "chatgpt.com" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		ct := "application/json"
		if form {
			ct = "application/x-www-form-urlencoded"
		}
		req.Header.Set("Content-Type", ct)
	}
	operation := paymentOperation(u.Host, u.Path)
	res, err := c.http.Do(req)
	if err != nil {
		return &UpstreamError{Operation: operation, Kind: "network"}
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return paymentFailure(operation, res.StatusCode, res.Header)
	}
	if res.Header.Get("Cf-Mitigated") == "challenge" {
		return paymentFailure(operation, res.StatusCode, res.Header)
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, 2*1024*1024+1))
	if err != nil || len(raw) > 2*1024*1024 || json.Unmarshal(raw, out) != nil {
		return &UpstreamError{Operation: operation, Kind: "invalid_response", Status: res.StatusCode}
	}
	return nil
}

func (c *Client) oai(ctx context.Context, token, path string, body any, out any) error {
	if !validToken(token) {
		return errors.New("登录态无效")
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return errors.New("支付参数无效")
		}
		rd = strings.NewReader(string(b))
	}
	return c.request(ctx, token, "https://chatgpt.com/backend-api/payments/checkout"+path, rd, false, out)
}
func (c *Client) stripe(ctx context.Context, path string, form url.Values, out any) error {
	return c.request(ctx, "", "https://api.stripe.com/v1/"+path, strings.NewReader(form.Encode()), true, out)
}
