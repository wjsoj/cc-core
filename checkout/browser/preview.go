package browser

import (
	"bytes"
	"context"
	"errors"
	"image/jpeg"
	"net/url"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	"github.com/wjsoj/cc-core/checkout"
)

// Preview is transient user-visible page content, not a diagnostic recording.
// The HTTP caller must require order ownership, HTTPS and Cache-Control:no-store.
// Never log, persist, put this in telemetry or forward it to an external service.
type Preview struct {
	Image  []byte `json:"image"`
	Mime   string `json:"mime"`
	Width  int    `json:"width"`
	Height int    `json:"height"`
}

func previewAllowed(raw string, session checkout.Session) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" {
		return false
	}
	switch u.Host {
	case "chatgpt.com":
		// Other orders are never part of this browser's workflow.
		if len(u.Path) > len("/checkout/") && u.Path[:len("/checkout/")] == "/checkout/" && u.Path != "/checkout/verify" {
			return "https://chatgpt.com"+u.Path == session.URL()
		}
		return true
	case "checkout.stripe.com", "auth.openai.com":
		return true
	}
	return false
}

func (b *Browser) Preview(ctx context.Context, auth checkout.Auth, session checkout.Session) (Preview, error) {
	var out Preview
	if err := session.Validate(); err != nil {
		return out, err
	}
	err := b.run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		if b.owner == "" || b.owner != checkout.Owner(auth) || b.session != session {
			return errors.New("order ownership mismatch")
		}
		var location string
		if err := chromedp.Location(&location).Do(ctx); err != nil || !previewAllowed(location, session) {
			return errors.New("preview outside checkout workflow")
		}
		data, err := page.CaptureScreenshot().WithFormat(page.CaptureScreenshotFormatJpeg).WithQuality(70).WithCaptureBeyondViewport(false).Do(ctx)
		if err != nil || len(data) > 2*1024*1024 {
			return errors.New("preview unavailable")
		}
		config, err := jpeg.DecodeConfig(bytes.NewReader(data))
		if err != nil || config.Width < 1 || config.Height < 1 || config.Width > 4096 || config.Height > 4096 {
			return errors.New("invalid preview dimensions")
		}
		out = Preview{Image: data, Mime: "image/jpeg", Width: config.Width, Height: config.Height}
		return nil
	}))
	return out, err
}
