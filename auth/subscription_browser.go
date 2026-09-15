package auth

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
)

// SubscriptionBrowserContext carries non-secret browser context for a read-only
// subscription probe. It must not contain captured cookies/device identifiers.
// TimezoneOffsetMinutes follows JavaScript Date.getTimezoneOffset (UTC - local).
type SubscriptionBrowserContext struct {
	TimezoneOffsetMinutes int
}

type subscriptionBrowserKey struct{}

// applySubscriptionBrowserHeaders pins the reproducible HTTP metadata from
// crack/chatgpt-checkout/rows/199 (accounts/check, HTTP 200). This is HTTP-level
// parity, NOT a claim to reproduce Chrome TLS, cookies, challenge state or the
// checkout/verify Referer. That Referer contains another order's client secret.
func applySubscriptionBrowserHeaders(r *http.Request, browser SubscriptionBrowserContext) {
	h := r.Header
	h.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36")
	h.Set("Accept", "*/*")
	h.Set("Accept-Language", "en-US,en;q=0.9")
	h.Set("Oai-Language", "en-US")
	h.Set("Sec-Ch-Ua", `"Chromium";v="148", "Google Chrome";v="148", "Not/A)Brand";v="99"`)
	h.Set("Sec-Ch-Ua-Platform", `"macOS"`)
	h.Set("Sec-Ch-Ua-Mobile", "?0")
	h.Set("Sec-Ch-Ua-Arch", `"arm"`)
	h.Set("Sec-Ch-Ua-Bitness", `"64"`)
	h.Set("Sec-Ch-Ua-Model", `""`)
	h.Set("Sec-Ch-Ua-Full-Version", `"148"`)
	h.Set("Sec-Ch-Ua-Full-Version-List", `"Chromium";v="148", "Google Chrome";v="148", "Not/A)Brand";v="99.0.0.0"`)
	h.Set("Sec-Ch-Ua-Platform-Version", `"15.1.1"`)
	h.Set("Priority", "u=1, i")
	// Keep identity encoding: net/http does not transparently decode Brotli.
	// Advertising the capture's gzip/br without a decoder breaks valid JSON.
	if r.URL.Path == "/backend-api/accounts/check/v4-2023-04-27" {
		q := r.URL.Query()
		q.Set("timezone_offset_min", strconv.Itoa(browser.TimezoneOffsetMinutes))
		r.URL.RawQuery = q.Encode()
		h.Set("X-Openai-Target-Path", r.URL.Path)
		h.Set("X-Openai-Target-Route", "/backend-api/accounts/check/{version}")
	}
}

func subscriptionBrowserContext(ctx context.Context, options []SubscriptionBrowserContext) (context.Context, error) {
	if len(options) == 0 {
		return ctx, nil
	}
	if len(options) != 1 || options[0].TimezoneOffsetMinutes < -840 || options[0].TimezoneOffsetMinutes > 840 {
		return ctx, fmt.Errorf("invalid subscription browser timezone")
	}
	return context.WithValue(ctx, subscriptionBrowserKey{}, options[0]), nil
}
