package browser

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"github.com/wjsoj/cc-core/checkout"
)

var sessionTokenPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// ValidateSession checks browser inputs before a public service reserves an
// expensive Chromium process. It authenticates no claims locally; upstream
// requests still validate the supplied login state.
func ValidateSession(raw string) (checkout.Auth, error) {
	auth, err := checkout.ParseAuth(raw)
	if err != nil {
		return checkout.Auth{}, err
	}
	if _, err = sessionCookies(raw); err != nil {
		return checkout.Auth{}, err
	}
	return auth, nil
}

func sessionCookies(raw string) ([]*network.CookieParam, error) {
	if len(raw) > 100000 {
		return nil, errors.New("session too large")
	}
	var payload struct {
		SessionToken string `json:"sessionToken"`
	}
	if json.Unmarshal([]byte(raw), &payload) != nil || len(payload.SessionToken) < 20 || len(payload.SessionToken) > 60000 || !sessionTokenPattern.MatchString(payload.SessionToken) {
		return nil, errors.New("browser checkout requires Session JSON containing sessionToken")
	}
	// Import only the supplied login cookie. Never import clearance, challenge,
	// device-observation cookies or another browser's anti-fraud state.
	const chunkSize = 3800
	var cookies []*network.CookieParam
	for offset := 0; offset < len(payload.SessionToken); offset += chunkSize {
		end := min(offset+chunkSize, len(payload.SessionToken))
		name := "__Secure-next-auth.session-token"
		if len(payload.SessionToken) > chunkSize {
			name += "." + strconv.Itoa(offset/chunkSize)
		}
		cookies = append(cookies, &network.CookieParam{Name: name, Value: payload.SessionToken[offset:end], URL: "https://chatgpt.com/", Path: "/", Secure: true, HTTPOnly: true, SameSite: network.CookieSameSiteLax})
	}
	return cookies, nil
}

func evaluate(function string, args []any, out any) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		encoded, err := json.Marshal(args)
		if err != nil {
			return errors.New("invalid browser input")
		}
		return chromedp.Evaluate("("+function+")(..."+string(encoded)+")", out,
			func(p *runtime.EvaluateParams) *runtime.EvaluateParams { return p.WithAwaitPromise(true) }).Do(ctx)
	})
}

// Create uses a genuine Chromium document and its ordinary fetch implementation
// to create an official checkout. It does not submit a payment. No synthetic
// security headers or verification tokens are generated. An ambiguous create
// is not retried on this Browser; the caller must reconcile or close it.
func (b *Browser) Create(ctx context.Context, rawSession string, selection checkout.Selection) (checkout.Session, error) {
	var session checkout.Session
	if err := selection.Validate(); err != nil {
		return session, err
	}
	auth, err := checkout.ParseAuth(rawSession)
	if err != nil {
		return session, err
	}
	cookies, err := sessionCookies(rawSession)
	if err != nil {
		return session, err
	}
	var reply struct {
		Status int    `json:"status"`
		ID     string `json:"id"`
		Entity string `json:"entity"`
	}
	var rejected bool
	err = b.run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		if b.createAttempted || b.owner != "" {
			rejected = true
			return errors.New("browser already bound")
		}
		b.owner = checkout.Owner(auth)
		b.createAttempted = true
		return nil
	}), network.SetCookies(cookies), chromedp.Navigate("https://chatgpt.com/"),
		evaluate(`async function(token, selection) {
			if (location.origin !== 'https://chatgpt.com') return {status: 0};
			try {
				const response = await fetch('/backend-api/payments/checkout', {
					method: 'POST', credentials: 'same-origin', redirect: 'error',
					headers: {'Authorization': 'Bearer '+token, 'Content-Type': 'application/json'},
					body: JSON.stringify({entry_point:'all_plans_pricing_modal', plan_name:selection.plan,
						billing_details:{country:selection.country,currency:selection.currency}, checkout_ui_mode:'custom'}),
					signal: AbortSignal.timeout(25000)
				});
				if (!response.ok) return {status:response.status};
				const data = await response.json();
				return {status:response.status, id:data.checkout_session_id, entity:data.processor_entity || 'openai_llc'};
			} catch (_) { return {status:0}; }
		}`, []any{auth.Token, selection}, &reply),
		chromedp.ActionFunc(func(ctx context.Context) error {
			session = checkout.Session{ID: reply.ID, Entity: reply.Entity}
			if reply.Status < 200 || reply.Status > 299 || session.Validate() != nil {
				return errors.New("checkout unavailable")
			}
			b.session = session
			return chromedp.Navigate(session.URL()).Do(ctx)
		}),
	)
	if rejected {
		return checkout.Session{}, errors.New("browser already belongs to an order; create was not repeated")
	}
	if reply.Status == 401 || reply.Status == 403 {
		return checkout.Session{}, errors.New("official checkout denied access; user login or verification may be required")
	}
	// A valid session may exist even if navigation failed; return it so the
	// caller can reconcile this order rather than silently create another one.
	if err != nil {
		return session, err
	}
	return session, nil
}

type FillResult struct {
	Filled    []string `json:"filled"`
	Missing   []string `json:"missing"`
	WrongPage bool     `json:"wrong_page"`
}

// FillBilling uses only caller-supplied billing information. Missing/ambiguous
// controls are reported, never guessed. Card frames and Subscribe are untouched.
// Ownership and the exact checkout page are checked before writing any field.
func (b *Browser) FillBilling(ctx context.Context, auth checkout.Auth, session checkout.Session, billing checkout.Billing) (FillResult, error) {
	var result FillResult
	if err := session.Validate(); err != nil {
		return result, err
	}
	if err := billing.Validate(billing.Country); err != nil {
		return result, err
	}
	err := b.run(ctx, chromedp.ActionFunc(func(context.Context) error {
		if b.owner == "" || checkout.Owner(auth) != b.owner || b.session != session {
			return errors.New("order ownership mismatch")
		}
		if b.submitAttempted {
			return errors.New("payment already attempted; query only")
		}
		b.billingHash = ""
		b.cardFilled = false
		return nil
	}), evaluate(fillBillingJS, []any{session.URL(), billing}, &result), chromedp.ActionFunc(func(context.Context) error {
		if !result.WrongPage && len(result.Missing) == 0 {
			b.billingHash = billingDigest(billing)
		}
		return nil
	}))
	if err != nil {
		return result, err
	}
	if result.WrongPage {
		return result, errors.New("browser is not on this order's checkout page")
	}
	return result, nil
}

const fillBillingJS = `async function(expectedURL, billing) {
	const result = {filled:[], missing:[], wrong_page:false};
	if (location.origin+location.pathname !== expectedURL) { result.wrong_page=true; return result; }
	const selectors = {
		country: '#billingAddress-countryInput, select[autocomplete="billing country"]',
		name: '#billingAddress-nameInput, #billingName, input[autocomplete="billing name"]',
		email: 'input[autocomplete="billing email"], input[name="email"]',
		line1: '#billingAddress-addressLine1Input, input[autocomplete="billing address-line1"]',
		line2: '#billingAddress-addressLine2Input, input[autocomplete="billing address-line2"]',
		city: '#billingAddress-localityInput, input[autocomplete="billing address-level2"]',
		state: '#billingAddress-administrativeAreaInput, [autocomplete="billing address-level1"]',
		postal_code: '#billingAddress-postalCodeInput, input[autocomplete="billing postal-code"]'
	};
	for (const [key, selector] of Object.entries(selectors)) {
		if (location.origin+location.pathname !== expectedURL) { result.wrong_page=true; break; }
		const nodes = [...document.querySelectorAll(selector)].filter(el =>
			!el.disabled && !el.readOnly && el.getClientRects().length && getComputedStyle(el).visibility !== 'hidden');
		if (nodes.length !== 1) { if (billing[key]) result.missing.push(key); continue; }
		const el = nodes[0];
		if (!(el instanceof HTMLInputElement) && !(el instanceof HTMLSelectElement)) { result.missing.push(key); continue; }
		const value = billing[key] || '';
		if (el instanceof HTMLSelectElement && ![...el.options].some(o => o.value === value)) { result.missing.push(key); continue; }
		// Native setter plus input/change events works with controlled form inputs.
		const proto = el instanceof HTMLSelectElement ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
		Object.getOwnPropertyDescriptor(proto, 'value').set.call(el, value);
		el.dispatchEvent(new Event('input', {bubbles:true}));
		el.dispatchEvent(new Event('change', {bubbles:true}));
		el.blur();
		await new Promise(resolve => setTimeout(resolve, 100));
		// Country changes may rerender dependent address inputs: resolve afresh.
		const current = [...document.querySelectorAll(selector)].filter(n => n.getClientRects().length && !n.disabled);
		if (current.length === 1 && current[0].value === value) result.filled.push(key);
		else result.missing.push(key);
	}
	return result;
}`
