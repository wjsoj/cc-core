package browser

import (
	"context"
	"strings"
	"testing"

	"github.com/chromedp/chromedp"
	"github.com/wjsoj/cc-core/checkout"
)

const cardFixture = `<input autocomplete="cc-number"><input autocomplete="cc-exp"><input autocomplete="cc-csc"><script>window.inputEvents=0;document.addEventListener('input',e=>{if(e.isTrusted)window.inputEvents++})</script>`

func syntheticCard() checkout.Card {
	return checkout.Card{Number: "4242424242424242", Month: "12", Year: "2035", CVC: "123"}
}

func TestStripeFrameOriginPolicy(t *testing.T) {
	for _, url := range []string{"https://js.stripe.com/card", "https://checkout.stripe.com/frame"} {
		if stripeOrigin(url) == "" {
			t.Fatal("known frame rejected")
		}
	}
	for _, url := range []string{"http://js.stripe.com/card", "https://js.stripe.com.evil.test/", "https://user@js.stripe.com/", "https://js.stripe.com:8443/", "https://evil.stripe.com/", "data:text/html,test"} {
		if stripeOrigin(url) != "" {
			t.Fatal("unknown frame accepted")
		}
	}
}

func TestChromiumCardFillInlineAndNoSubmit(t *testing.T) {
	b, _ := fixtureBrowserWithResponse(t, func(url string) (int, string, string) {
		if url == "https://chatgpt.com/checkout/openai_llc/oaics_fixture" {
			return 200, billingFixture + cardFixture, "text/html"
		}
		return 0, "", ""
	})
	a, s := createFixture(t, b)
	r, err := b.FillCard(context.Background(), a, s, syntheticCard())
	if err != nil || !r.CompleteCard() {
		t.Fatalf("inline fill: %+v %v", r, err)
	}
	var result struct {
		Submits int  `json:"submits"`
		Events  int  `json:"events"`
		Match   bool `json:"match"`
	}
	err = b.run(context.Background(), chromedp.Evaluate(`({submits:window.submits,events:window.inputEvents,match:document.querySelector('[autocomplete="cc-number"]').value==='4242424242424242'})`, &result))
	if err != nil || result.Submits != 0 || result.Events != 3 || !result.Match {
		t.Fatalf("browser input behavior: %+v %v", result, err)
	}
	wrong := a
	wrong.Token = "different_synthetic_token_12345"
	if _, err = b.FillCard(context.Background(), wrong, s, syntheticCard()); err == nil {
		t.Fatal("foreign account filled card")
	}
	if _, err = b.FillCard(context.Background(), a, checkout.Session{ID: "oaics_other", Entity: s.Entity}, syntheticCard()); err == nil {
		t.Fatal("foreign order filled card")
	}
}

func TestChromiumCardFillCrossOriginIframe(t *testing.T) {
	b, _ := fixtureBrowserWithResponse(t, func(url string) (int, string, string) {
		if url == "https://chatgpt.com/checkout/openai_llc/oaics_fixture" {
			return 200, billingFixture + `<iframe src="https://js.stripe.com/card-fixture"></iframe>`, "text/html"
		}
		if url == "https://js.stripe.com/card-fixture" {
			return 200, "<!doctype html><html><body>" + cardFixture + "</body></html>", "text/html"
		}
		return 0, "", ""
	})
	a, s := createFixture(t, b)
	r, err := b.FillCard(context.Background(), a, s, syntheticCard())
	if err != nil || !r.CompleteCard() {
		t.Fatalf("iframe fill: %+v %v", r, err)
	}
	if len(b.cardFrames) != 1 {
		t.Fatal("cross-origin iframe was not independently attached")
	}
}

func TestChromiumCardMissingOrAmbiguousDoesNotPartiallyFill(t *testing.T) {
	b, _ := fixtureBrowserWithResponse(t, func(url string) (int, string, string) {
		if strings.Contains(url, "/checkout/openai_llc/") {
			return 200, billingFixture + cardFixture + `<input autocomplete="cc-number">`, "text/html"
		}
		return 0, "", ""
	})
	a, s := createFixture(t, b)
	r, err := b.FillCard(context.Background(), a, s, syntheticCard())
	if err != nil || r.CompleteCard() || len(r.Filled) != 0 || len(r.Missing) != 1 || r.Missing[0] != "number" {
		t.Fatalf("ambiguous fields: %+v %v", r, err)
	}
	var empty bool
	err = b.run(context.Background(), chromedp.Evaluate(`[...document.querySelectorAll('input[autocomplete^="cc-"]')].every(el=>el.value==='')`, &empty))
	if err != nil || !empty {
		t.Fatal("partial card data written before all fields resolved")
	}
}

func TestChromiumCardSplitFrames(t *testing.T) {
	b, _ := fixtureBrowserWithResponse(t, func(url string) (int, string, string) {
		if url == "https://chatgpt.com/checkout/openai_llc/oaics_fixture" {
			return 200, billingFixture + `<iframe src="https://js.stripe.com/card-number"></iframe><iframe src="https://js.stripe.com/card-expiry"></iframe><iframe src="https://js.stripe.com/card-cvc"></iframe>`, "text/html"
		}
		field := map[string]string{"https://js.stripe.com/card-number": "cc-number", "https://js.stripe.com/card-expiry": "cc-exp", "https://js.stripe.com/card-cvc": "cc-csc"}[url]
		if field != "" {
			return 200, `<!doctype html><input autocomplete="` + field + `">`, "text/html"
		}
		return 0, "", ""
	})
	a, s := createFixture(t, b)
	r, err := b.FillCard(context.Background(), a, s, syntheticCard())
	if err != nil || !r.CompleteCard() || len(b.cardFrames) != 3 {
		t.Fatalf("split frames: %+v %v", r, err)
	}
}

func TestChromiumHiddenCardFrameNeverReceivesData(t *testing.T) {
	b, _ := fixtureBrowserWithResponse(t, func(url string) (int, string, string) {
		if url == "https://chatgpt.com/checkout/openai_llc/oaics_fixture" {
			return 200, billingFixture + `<iframe style="visibility:hidden" src="https://js.stripe.com/hidden-card"></iframe>`, "text/html"
		}
		if url == "https://js.stripe.com/hidden-card" {
			return 200, cardFixture, "text/html"
		}
		return 0, "", ""
	})
	a, s := createFixture(t, b)
	r, err := b.FillCard(context.Background(), a, s, syntheticCard())
	if err != nil || len(r.Filled) != 0 || len(r.Missing) != 3 || len(b.cardFrames) != 0 {
		t.Fatal("hidden card frame was selected")
	}
}

func TestChromiumPreviewOwnership(t *testing.T) {
	b, _ := fixtureBrowser(t)
	a, s := createFixture(t, b)
	preview, err := b.Preview(context.Background(), a, s)
	if err != nil || preview.Mime != "image/jpeg" || len(preview.Image) == 0 || preview.Width < 1 {
		t.Fatalf("preview failed: %v", err)
	}
	wrong := a
	wrong.Token = "different_synthetic_token_12345"
	if p, err := b.Preview(context.Background(), wrong, s); err == nil || len(p.Image) != 0 {
		t.Fatal("preview crossed account boundary")
	}
}
