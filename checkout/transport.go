// Package checkout implements the captured ChatGPT checkout protocol. These are
// private upstream endpoints, not a supported OpenAI public API.
package checkout

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// Client has one immutable egress path for its entire lifetime. Neither proxy
// environment variables nor NO_PROXY are consulted.
type Client struct{ http *http.Client }

// NewClient uses direct connections when proxyURL is empty, otherwise the
// specified SOCKS5 endpoint exclusively (optionally user:password). Proxy
// failures never fall back to direct connections.
// socks5 and socks5h BOTH resolve upstream hostnames at the proxy. The proxy
// hostname itself, if not an IP literal, must be resolved locally.
func NewClient(proxyURL string) (*Client, error) {
	proxyURL = strings.TrimSpace(proxyURL)
	if proxyURL == "" {
		return newHTTPClient((&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext), nil
	}
	u, err := url.Parse(proxyURL)
	if err != nil || u == nil || (u.Scheme != "socks5" && u.Scheme != "socks5h") || u.Hostname() == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return nil, errors.New("必须配置 socks5://[用户名:密码@]主机:端口")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("SOCKS5 端口无效")
	}
	var auth *proxy.Auth
	if u.User != nil {
		password, _ := u.User.Password()
		if len(u.User.Username()) == 0 || len(u.User.Username()) > 255 || len(password) > 255 {
			return nil, errors.New("SOCKS5 凭据格式无效")
		}
		auth = &proxy.Auth{User: u.User.Username(), Password: password}
	}
	d, err := proxy.SOCKS5("tcp", u.Host, auth, &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second})
	if err != nil {
		return nil, errors.New("SOCKS5 配置无效")
	}
	cd, ok := d.(proxy.ContextDialer)
	if !ok {
		return nil, errors.New("SOCKS5 不支持取消请求")
	}
	return newHTTPClient(cd.DialContext), nil
}

func newHTTPClient(dial func(context.Context, string, string) (net.Conn, error)) *Client {
	tr := &http.Transport{Proxy: nil, DialContext: dial, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 15 * time.Second, ResponseHeaderTimeout: 45 * time.Second, IdleConnTimeout: 30 * time.Second, MaxConnsPerHost: 8, MaxIdleConns: 8, ForceAttemptHTTP2: true}
	return &Client{http: &http.Client{Transport: tr, Timeout: 60 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
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
	res, err := c.http.Do(req)
	if err != nil {
		return errors.New("所选网络请求失败；如已提交付款，只能查询结果，勿重复支付")
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return errors.New("支付上游拒绝请求 (HTTP " + strconv.Itoa(res.StatusCode) + ")；未确认支付成功")
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, 2*1024*1024+1))
	if err != nil || len(raw) > 2*1024*1024 || json.Unmarshal(raw, out) != nil {
		return errors.New("支付上游响应无效；未确认支付成功")
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
