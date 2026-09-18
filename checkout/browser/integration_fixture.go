//go:build gptpay_integration

package browser

// This file is excluded from ordinary builds. It exists solely for cross-module
// end-to-end tests with the real browser executor and synthetic upstream pages.

import (
	"context"
	"encoding/base64"
	"errors"
	"net"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/chromedp"
)

// StartIntegrationFixture cannot reach an upstream network: all CONNECT dials
// fail, and intercepted page requests receive only the supplied fixture data.
// Never compile production binaries with the gptpay_integration build tag.
func StartIntegrationFixture(ctx context.Context, config Config, response func(method, url string) (int, string, string)) (*Browser, error) {
	if config.Proxy != "" || response == nil {
		return nil, errors.New("invalid offline fixture configuration")
	}
	b, err := start(ctx, config, func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("integration fixture: external network disabled")
	})
	if err != nil {
		return nil, err
	}
	chromedp.ListenTarget(b.ctx, func(event any) {
		e, ok := event.(*fetch.EventRequestPaused)
		if !ok {
			return
		}
		code, body, mime := response(e.Request.Method, e.Request.URL)
		if code < 100 || code > 599 || len(body) > 2*1024*1024 {
			code, body, mime = 404, "fixture response unavailable", "text/plain"
		}
		go func() {
			executor := cdp.WithExecutor(b.ctx, chromedp.FromContext(b.ctx).Target)
			_ = fetch.FulfillRequest(e.RequestID, int64(code)).WithResponseHeaders([]*fetch.HeaderEntry{{Name: "Content-Type", Value: mime}, {Name: "Access-Control-Allow-Origin", Value: "https://chatgpt.com"}}).WithBody(base64.StdEncoding.EncodeToString([]byte(body))).Do(executor)
		}()
	})
	if err = b.run(ctx, fetch.Enable()); err != nil {
		b.Close()
		return nil, err
	}
	return b, nil
}
