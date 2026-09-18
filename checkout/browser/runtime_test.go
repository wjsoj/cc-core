package browser

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/storage"
	"github.com/chromedp/chromedp"
	"github.com/wjsoj/cc-core/checkout"
)

func TestSessionCookies(t *testing.T) {
	for _, length := range []int{20, 3800, 3801, 12000} {
		secret := strings.Repeat("a", length)
		raw, _ := json.Marshal(map[string]string{"sessionToken": secret})
		cookies, err := sessionCookies(string(raw))
		if err != nil {
			t.Fatal(err)
		}
		var joined string
		for _, c := range cookies {
			joined += c.Value
			if c.URL != "https://chatgpt.com/" || c.Domain != "" || !c.HTTPOnly || !c.Secure || c.Expires != nil || len(c.Value) > 3800 {
				t.Fatal("unsafe cookie scope")
			}
		}
		if joined != secret {
			t.Fatal("cookie chunks lost bytes")
		}
	}
	for _, raw := range []string{`{}`, `{"sessionToken":"not valid spaces"}`, `{"sessionToken":"<script>secret</script>"}`} {
		if _, err := sessionCookies(raw); err == nil || strings.Contains(err.Error(), "<script>") {
			t.Fatal("invalid session accepted or echoed")
		}
	}
}

// Opt-in tests launch real Chromium against synthetic, intercepted pages. No
// network request reaches ChatGPT/Stripe, no real session/card is used and no
// payment submission exists in the fixture. Ordinary unit tests need no Chrome.
func fixtureBrowser(t *testing.T) (*Browser, *atomic.Int32) {
	return fixtureBrowserWithResponse(t, nil)
}

type fixtureResponse func(string) (int, string, string)

func fixtureBrowserWithResponse(t *testing.T, response fixtureResponse) (*Browser, *atomic.Int32) {
	t.Helper()
	path := os.Getenv("GPTPAY_TEST_CHROMIUM")
	if path == "" {
		t.Skip("set GPTPAY_TEST_CHROMIUM to run local Chromium integration tests")
	}
	var dials atomic.Int32
	b, err := start(context.Background(), Config{Executable: path, Lifetime: time.Minute}, func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("external network disabled by fixture")
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	var creates atomic.Int32
	chromedp.ListenTarget(b.ctx, func(event any) {
		e, ok := event.(*fetch.EventRequestPaused)
		if !ok {
			return
		}
		body, contentType := billingFixture, "text/html"
		status := 200
		if e.Request.URL == "https://chatgpt.com/backend-api/payments/checkout" {
			creates.Add(1)
			if e.Request.Method != "POST" || e.Request.Headers["Authorization"] != "Bearer synthetic_access_token_only_12345" {
				t.Error("checkout request method/auth mismatch")
			}
			var requestBody []byte
			for _, entry := range e.Request.PostDataEntries {
				decoded, err := base64.StdEncoding.DecodeString(entry.Bytes)
				if err != nil {
					t.Error("invalid captured fixture request body")
				}
				requestBody = append(requestBody, decoded...)
			}
			var payload struct {
				Entry   string `json:"entry_point"`
				Plan    string `json:"plan_name"`
				UI      string `json:"checkout_ui_mode"`
				Billing struct {
					Country  string `json:"country"`
					Currency string `json:"currency"`
				} `json:"billing_details"`
			}
			if json.Unmarshal(requestBody, &payload) != nil || payload.Entry != "all_plans_pricing_modal" || payload.Plan != "chatgptplusplan" || payload.UI != "custom" || payload.Billing.Country != "US" || payload.Billing.Currency != "USD" {
				t.Error("checkout request does not match capture contract")
			}
			body, contentType = `{"checkout_session_id":"oaics_fixture","processor_entity":"openai_llc"}`, "application/json"
		}
		if response != nil {
			code, text, mime := response(e.Request.URL)
			if code != 0 {
				status, body, contentType = code, text, mime
			}
		}
		go func() {
			executor := cdp.WithExecutor(b.ctx, chromedp.FromContext(b.ctx).Target)
			_ = fetch.FulfillRequest(e.RequestID, int64(status)).WithResponseHeaders([]*fetch.HeaderEntry{{Name: "Content-Type", Value: contentType}}).WithBody(base64.StdEncoding.EncodeToString([]byte(body))).Do(executor)
		}()
	})
	if err = b.run(context.Background(), fetch.Enable()); err != nil {
		t.Fatal(err)
	}
	return b, &creates
}

const billingFixture = `<!doctype html><html><body>
<select id="billingAddress-countryInput"><option value="US">United States</option></select>
<input id="billingAddress-nameInput"><input name="email">
<input id="billingAddress-addressLine1Input"><input id="billingAddress-addressLine2Input">
<input id="billingAddress-localityInput"><select id="billingAddress-administrativeAreaInput"><option value="NY">New York</option></select>
<input id="billingAddress-postalCodeInput"><button id="subscribe">Subscribe</button>
<script>window.submits=0;document.querySelector('#subscribe').onclick=()=>window.submits++;</script>
</body></html>`

func createFixture(t *testing.T, b *Browser) (checkout.Auth, checkout.Session) {
	t.Helper()
	raw := `{"accessToken":"synthetic_access_token_only_12345","sessionToken":"synthetic_session_cookie_only_12345"}`
	s, err := b.Create(context.Background(), raw, checkout.Selection{Plan: "chatgptplusplan", Country: "US", Currency: "USD"})
	if err != nil {
		t.Fatal(err)
	}
	a, _ := checkout.ParseAuth(raw)
	return a, s
}

func TestChromiumCreateFillAndOwnership(t *testing.T) {
	b, creates := fixtureBrowser(t)
	a, s := createFixture(t, b)
	billing := checkout.Billing{Name: "Fixture User", Email: "fixture@example.invalid", Line1: "Fixture road", City: "Fixture", State: "NY", Country: "US", PostalCode: "10001"}
	r, err := b.FillBilling(context.Background(), a, s, billing)
	if err != nil || r.WrongPage || len(r.Missing) > 0 || len(r.Filled) != 8 {
		t.Fatalf("fill: %+v %v", r, err)
	}
	if err = b.run(context.Background(), chromedp.Evaluate(`document.body.appendChild(document.querySelector('#billingAddress-nameInput').cloneNode())`, nil)); err != nil {
		t.Fatal(err)
	}
	ambiguous, err := b.FillBilling(context.Background(), a, s, billing)
	if err != nil || len(ambiguous.Missing) != 1 || ambiguous.Missing[0] != "name" {
		t.Fatal("ambiguous billing field was silently accepted")
	}
	if err = b.run(context.Background(), chromedp.Evaluate(`document.querySelectorAll('#billingAddress-nameInput')[1].remove()`, nil)); err != nil {
		t.Fatal(err)
	}
	var values struct {
		Name     string `json:"name"`
		Submits  int    `json:"submits"`
		Timezone string `json:"timezone"`
		Locale   string `json:"locale"`
	}
	err = b.run(context.Background(), chromedp.Evaluate(`({name:document.querySelector('#billingAddress-nameInput').value,submits:window.submits,timezone:Intl.DateTimeFormat().resolvedOptions().timeZone,locale:Intl.DateTimeFormat().resolvedOptions().locale})`, &values))
	if err != nil || values.Name != billing.Name || values.Submits != 0 || values.Timezone != "America/New_York" || values.Locale != "en-US" {
		t.Fatalf("unexpected browser state: %+v %v", values, err)
	}
	if _, err = b.FillBilling(context.Background(), checkout.Auth{Token: "different_synthetic_token"}, s, billing); err == nil {
		t.Fatal("cross-account fill accepted")
	}
	_, err = b.Create(context.Background(), `{"accessToken":"synthetic_access_token_only_12345","sessionToken":"synthetic_session_cookie_only_12345"}`, checkout.Selection{Plan: "chatgptplusplan", Country: "US", Currency: "USD"})
	if err == nil || creates.Load() != 1 {
		t.Fatal("create was repeated")
	}
	if err = b.run(context.Background(), chromedp.Navigate("https://chatgpt.com/")); err != nil {
		t.Fatal(err)
	}
	if _, err = b.FillBilling(context.Background(), a, s, billing); err == nil {
		t.Fatal("filled outside the order page")
	}
	b.Close()
	if err = b.run(context.Background(), chromedp.Evaluate("1", nil)); err == nil {
		t.Fatal("closed browser still accepted actions")
	}
}

func TestChromiumContextsDoNotShareCookies(t *testing.T) {
	first, _ := fixtureBrowser(t)
	createFixture(t, first)
	second, _ := fixtureBrowser(t)
	if err := second.run(context.Background(), chromedp.Navigate("https://chatgpt.com/")); err != nil {
		t.Fatal(err)
	}
	for i, b := range []*Browser{first, second} {
		var count int
		err := b.run(context.Background(), chromedp.ActionFunc(func(ctx context.Context) error {
			c := chromedp.FromContext(ctx)
			cookies, err := storage.GetCookies().WithBrowserContextID(b.contextID).Do(cdp.WithExecutor(ctx, c.Browser))
			count = len(cookies)
			return err
		}))
		if err != nil || i == 0 && count == 0 || i == 1 && count != 0 {
			t.Fatal("HttpOnly cookie isolation failed")
		}
	}
}
