package browser

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/dom"
	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/cdproto/target"
	"github.com/chromedp/chromedp"
	"github.com/wjsoj/cc-core/checkout"
)

var cardSelectors = map[string]string{
	"number": `input[autocomplete="cc-number"], input[name="cardnumber"], input[data-elements-stable-field-name="cardNumber"]`,
	"expiry": `input[autocomplete="cc-exp"], input[name="exp-date"], input[data-elements-stable-field-name="cardExpiry"]`,
	"cvc":    `input[autocomplete="cc-csc"], input[name="cvc"], input[data-elements-stable-field-name="cardCvc"]`,
	"month":  `input[autocomplete="cc-exp-month"], select[autocomplete="cc-exp-month"]`,
	"year":   `input[autocomplete="cc-exp-year"], select[autocomplete="cc-exp-year"]`,
}

// Both representations at once are ambiguous, even if one happens to be first.
func expiryFields(combined, month, year int) []string {
	if combined == 1 && month == 0 && year == 0 {
		return []string{"expiry"}
	}
	if combined == 0 && month == 1 && year == 1 {
		return []string{"month", "year"}
	}
	return nil
}

type expiryControl struct {
	Kind      string   `json:"kind"`
	MaxLength int      `json:"max_length"`
	Options   []string `json:"options"`
}

func expiryValue(field string, control expiryControl, card checkout.Card) (string, int, error) {
	value := card.Year
	if field == "month" {
		value = card.Month
	}
	n, _ := strconv.Atoi(value)
	if control.Kind == "input" {
		if field == "year" && control.MaxLength == 2 {
			return card.Year[len(card.Year)-2:], -1, nil
		}
		if field == "month" {
			return strconv.Itoa(n), -1, nil
		}
		if control.MaxLength > 0 && control.MaxLength < len(value) {
			return "", -1, errors.New("unsupported expiry input width")
		}
		return value, -1, nil
	}
	if control.Kind != "select" {
		return "", -1, errors.New("unsupported expiry control")
	}
	index := -1
	for i, option := range control.Options {
		v, err := strconv.Atoi(option)
		if err != nil {
			continue
		}
		matches := v == n || field == "year" && len(option) == 2 && v == n%100
		if matches {
			if index != -1 {
				return "", -1, errors.New("ambiguous expiry option")
			}
			index = i
			value = option
		}
	}
	if index == -1 {
		return "", -1, errors.New("expiry option unavailable")
	}
	return value, index, nil
}

type cardTarget struct {
	ctx    context.Context
	origin string
}

func stripeOrigin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" {
		return ""
	}
	// Explicit document hosts, not every arbitrary Stripe subdomain.
	if u.Host != "js.stripe.com" && u.Host != "checkout.stripe.com" {
		return ""
	}
	return "https://" + u.Host
}

// cardTargets uses only actual child frames of this checkout, never unrelated
// tabs/popups or another browser context. OOPIF attachments live until Browser
// close; canceling an attached chromedp context would close the iframe itself.
func (b *Browser) cardTargets(ctx context.Context) ([]cardTarget, error) {
	result := []cardTarget{{ctx: b.ctx, origin: "https://chatgpt.com"}}
	infos, err := target.GetTargets().Do(cdp.WithExecutor(ctx, chromedp.FromContext(b.ctx).Browser))
	if err != nil {
		return nil, err
	}
	if _, err = dom.GetDocument().Do(ctx); err != nil {
		return nil, err
	}
	if b.cardFrames == nil {
		b.cardFrames = make(map[target.ID]context.Context)
	}
	for _, info := range infos {
		origin := stripeOrigin(info.URL)
		if origin == "" || info.Type != "iframe" || info.BrowserContextID != b.contextID {
			continue
		}
		// OOPIFs are not necessarily included in Page.getFrameTree. Resolve
		// their embedding element through THIS page's DOM agent instead.
		backendID, _, err := dom.GetFrameOwner(cdp.FrameID(info.TargetID)).Do(ctx)
		if err != nil {
			continue
		}
		object, err := dom.ResolveNode().WithBackendNodeID(backendID).Do(ctx)
		if err != nil {
			continue
		}
		value, exception, err := runtime.CallFunctionOn(`function(){return this instanceof HTMLIFrameElement && this.getClientRects().length>0 && getComputedStyle(this).visibility!=='hidden'}`).WithObjectID(object.ObjectID).WithReturnByValue(true).Do(ctx)
		_ = runtime.ReleaseObject(object.ObjectID).Do(ctx)
		var visible bool
		if err != nil || exception != nil || value == nil || json.Unmarshal(value.Value, &visible) != nil || !visible {
			continue
		}
		frame := b.cardFrames[info.TargetID]
		if frame == nil {
			if len(b.cardFrames) >= 16 {
				return nil, errors.New("payment frame limit reached")
			}
			var cancel context.CancelFunc
			frame, cancel = chromedp.NewContext(b.ctx, chromedp.WithTargetID(info.TargetID))
			// Initial attachment must outlive the individual fill request.
			timer := time.AfterFunc(15*time.Second, cancel)
			err = chromedp.Run(frame)
			timer.Stop()
			if err != nil {
				cancel()
				return nil, err
			}
			b.cardFrames[info.TargetID] = frame
			if b.observer != nil {
				b.observer.attach(frame)
			}
			if err = chromedp.Run(frame, observationNetworkEnable()); err != nil {
				return nil, err
			}
		}
		result = append(result, cardTarget{ctx: frame, origin: origin})
	}
	return result, nil
}

func (b *Browser) checkOrderPage(ctx context.Context, auth checkout.Auth, session checkout.Session) error {
	if b.owner == "" || b.owner != checkout.Owner(auth) || b.session != session {
		return errors.New("order ownership mismatch")
	}
	var same bool
	if err := evaluate(`function(url){return location.origin+location.pathname===url}`, []any{session.URL()}, &same).Do(ctx); err != nil || !same {
		return errors.New("not on this order's checkout page")
	}
	return nil
}

// FillCard fills only the three uniquely identified payment fields and never
// clicks Subscribe. It does not tokenize a card via a parallel protocol client.
// Values exist only for this call and in the official page's input controls;
// output contains field names, never PAN, CVC, expiry, or raw browser errors.
func (b *Browser) FillCard(ctx context.Context, auth checkout.Auth, session checkout.Session, card checkout.Card) (FillResult, error) {
	result := FillResult{Filled: []string{}, Missing: []string{}}
	if err := session.Validate(); err != nil {
		return result, err
	}
	if err := card.Validate(); err != nil {
		return result, err
	}
	err := b.run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		if err := b.checkOrderPage(ctx, auth, session); err != nil {
			return err
		}
		if b.submitAttempted {
			return errors.New("payment already attempted; query only")
		}
		b.cardFilled = false
		targets, err := b.cardTargets(ctx)
		if err != nil {
			return err
		}
		found := make(map[string][]cardTarget)
		for _, frame := range targets {
			var counts map[string]int
			executor := cdp.WithExecutor(ctx, chromedp.FromContext(frame.ctx).Target)
			err = evaluate(cardProbeJS, []any{frame.origin, cardSelectors}, &counts).Do(executor)
			if err != nil {
				return err
			}
			for field, count := range counts {
				for n := 0; n < count && n < 2; n++ {
					found[field] = append(found[field], frame)
				}
			}
		}
		expiry := expiryFields(len(found["expiry"]), len(found["month"]), len(found["year"]))
		for _, field := range []string{"number", "expiry", "cvc"} {
			if field == "expiry" {
				if expiry == nil {
					result.Missing = append(result.Missing, field)
				}
				continue
			}
			if len(found[field]) != 1 {
				result.Missing = append(result.Missing, field)
			}
		}
		// Probe all fields before transmitting any card data to a document.
		if len(result.Missing) > 0 {
			return nil
		}
		month := card.Month
		if len(month) == 1 {
			month = "0" + month
		}
		values := map[string]string{"number": card.Number, "expiry": month + "/" + card.Year[len(card.Year)-2:], "cvc": card.CVC}
		defer clear(values)
		fields := append(append([]string{"number"}, expiry...), "cvc")
		selectSteps := make(map[string]int)
		if len(expiry) == 2 {
			for _, field := range expiry {
				frame := found[field][0]
				executor := cdp.WithExecutor(ctx, chromedp.FromContext(frame.ctx).Target)
				var control expiryControl
				if err = evaluate(expiryControlJS, []any{frame.origin, cardSelectors[field]}, &control).Do(executor); err != nil {
					return err
				}
				value, steps, err := expiryValue(field, control, card)
				if err != nil {
					result.Missing = append(result.Missing, "expiry")
					return nil
				}
				values[field] = value
				if steps >= 0 {
					selectSteps[field] = steps
				}
			}
		}
		for _, field := range fields {
			if err = b.checkOrderPage(ctx, auth, session); err != nil {
				return err
			}
			frame := found[field][0]
			executor := cdp.WithExecutor(ctx, chromedp.FromContext(frame.ctx).Target)
			var focused bool
			err = evaluate(cardFocusJS, []any{frame.origin, cardSelectors[field]}, &focused).Do(executor)
			if err != nil || !focused {
				return errors.New("payment field changed before fill")
			}
			if steps, isSelect := selectSteps[field]; isSelect {
				// Native keys generate trusted input/change events. No JS setter,
				// submit, or synthesized verification result is used.
				if err = cardKey(executor, "Home", 36); err != nil {
					return err
				}
				for range steps {
					if err = cardKey(executor, "ArrowDown", 40); err != nil {
						return err
					}
				}
			} else {
				// Also replaces prefilled number-type expiry controls, for which
				// HTMLInputElement.select() is not consistently supported.
				if err = input.DispatchKeyEvent(input.KeyDown).WithKey("a").WithCode("KeyA").WithWindowsVirtualKeyCode(65).WithModifiers(2).Do(executor); err != nil {
					return err
				}
				if err = input.DispatchKeyEvent(input.KeyUp).WithKey("a").WithCode("KeyA").WithWindowsVirtualKeyCode(65).WithModifiers(2).Do(executor); err != nil {
					return err
				}
				if err = input.InsertText(values[field]).Do(executor); err != nil {
					return err
				}
			}
			var accepted bool
			err = evaluate(cardVerifyJS, []any{frame.origin, cardSelectors[field], values[field]}, &accepted).Do(executor)
			if err != nil || !accepted {
				return errors.New("payment field did not accept input")
			}
			if field == "year" {
				result.Filled = append(result.Filled, "expiry")
			} else if field != "month" {
				result.Filled = append(result.Filled, field)
			}
		}
		b.cardFilled = result.CompleteCard()
		return nil
	}))
	card = checkout.Card{}
	return result, err
}

func cardKey(ctx context.Context, key string, code int64) error {
	if err := input.DispatchKeyEvent(input.KeyDown).WithKey(key).WithWindowsVirtualKeyCode(code).Do(ctx); err != nil {
		return err
	}
	return input.DispatchKeyEvent(input.KeyUp).WithKey(key).WithWindowsVirtualKeyCode(code).Do(ctx)
}

const expiryControlJS = `function(origin,selector){
	if(location.origin!==origin)return {};
	const nodes=[...document.querySelectorAll(selector)].filter(el=>!el.disabled&&!el.readOnly&&el.type!=='hidden'&&el.getClientRects().length&&getComputedStyle(el).visibility!=='hidden');
	if(nodes.length!==1)return {};
	const el=nodes[0];
	if(el instanceof HTMLInputElement)return {kind:'input',max_length:el.maxLength};
	if(el instanceof HTMLSelectElement&&!el.multiple&&el.options.length<=256)return {kind:'select',options:[...el.options].filter(o=>!o.disabled&&!(o.parentElement instanceof HTMLOptGroupElement&&o.parentElement.disabled)).map(o=>/^\d{1,4}$/.test(o.value)?o.value:'')};
	return {};
}`

const cardProbeJS = `function(origin,selectors){
	if(location.origin!==origin)return {};
	const result={};for(const [key,selector] of Object.entries(selectors)){
		result[key]=[...document.querySelectorAll(selector)].filter(el=>!el.disabled&&!el.readOnly&&el.type!=='hidden'&&el.getClientRects().length&&getComputedStyle(el).visibility!=='hidden').length;
	}return result;
}`
const cardFocusJS = `function(origin,selector){
	if(location.origin!==origin)return false;
	const nodes=[...document.querySelectorAll(selector)].filter(el=>!el.disabled&&!el.readOnly&&el.type!=='hidden'&&el.getClientRects().length&&getComputedStyle(el).visibility!=='hidden');
	if(nodes.length!==1)return false;
	nodes[0].focus();if(nodes[0] instanceof HTMLInputElement){try{nodes[0].select()}catch{}}return document.activeElement===nodes[0];
}`
const cardVerifyJS = `function(origin,selector,value){
	if(location.origin!==origin)return false;
	const nodes=[...document.querySelectorAll(selector)].filter(el=>!el.disabled&&!el.readOnly&&el.type!=='hidden'&&el.getClientRects().length&&getComputedStyle(el).visibility!=='hidden');
	if(nodes.length!==1)return false;
	const accepted=nodes[0].value.replace(/\D/g,'')===value.replace(/\D/g,'');nodes[0].blur();return accepted;
}`

// Do not classify a missing field as a rejected card or a failed charge.
func (r FillResult) CompleteCard() bool {
	return !r.WrongPage && len(r.Missing) == 0 && strings.Join(r.Filled, ",") == "number,expiry,cvc"
}
