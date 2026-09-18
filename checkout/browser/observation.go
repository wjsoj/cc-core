package browser

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/wjsoj/cc-core/checkout"
)

const observationBodyLimit = 256 * 1024

func observationNetworkEnable() *network.EnableParams {
	return network.Enable().WithMaxTotalBufferSize(2 * 1024 * 1024).WithMaxResourceBufferSize(observationBodyLimit).WithMaxPostDataSize(16 * 1024)
}

var intentIDPattern = regexp.MustCompile(`^pi_[A-Za-z0-9]+$`)
var intentSecretPattern = regexp.MustCompile(`^(pi_[A-Za-z0-9]+)_secret_[A-Za-z0-9]+$`)

// Observation is a non-authoritative progress hint from this order's browser.
// Even a Stripe succeeded response remains processing until checkout reconciles.
// No response body, URL, client secret or payment identifier is exposed.
type Observation struct {
	checkout.PaymentResult
	Observed bool `json:"observed"`
}

type observedRequest struct {
	kind, url, intent string
	sequence          uint64
	status            int64
	json              bool
}
type observedResponse struct {
	request observedRequest
	ctx     context.Context
	id      network.RequestID
}
type paymentObserver struct {
	mu               sync.Mutex
	armed            bool
	session          checkout.Session
	amount           int64
	currency         string
	intent           string
	sequence, latest uint64
	result           Observation
	queue            chan observedResponse
}

func newPaymentObserver(ctx context.Context) *paymentObserver {
	o := &paymentObserver{queue: make(chan observedResponse, 32)}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case response := <-o.queue:
				read, cancel := context.WithTimeout(response.ctx, 5*time.Second)
				body, err := network.GetResponseBody(response.id).Do(read)
				cancel()
				if err == nil && len(body) <= observationBodyLimit {
					o.accept(response.request, body)
				}
				clear(body)
			}
		}
	}()
	return o
}

// arm is called only after the durable guard, immediately before native input.
func (o *paymentObserver) arm(q checkout.Quote) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.armed {
		return
	}
	o.armed = true
	o.session = q.Session
	o.amount = q.Amount
	o.currency = strings.ToLower(q.Selection.Currency)
}

func (o *paymentObserver) track(e *network.EventRequestWillBeSent) (observedRequest, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.armed || e.Request == nil || len(e.Request.URL) > 2048 || e.Request.Method != "POST" || e.RedirectResponse != nil {
		return observedRequest{}, false
	}
	u, err := url.Parse(e.Request.URL)
	if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" {
		return observedRequest{}, false
	}
	r := observedRequest{url: e.Request.URL}
	switch {
	case u.Host == "chatgpt.com" && u.Path == "/backend-api/payments/checkout/confirm":
		// Only decode the order reference; ignore credentials and billing fields.
		var body []byte
		for _, entry := range e.Request.PostDataEntries {
			if len(entry.Bytes) > observationBodyLimit*2 {
				return observedRequest{}, false
			}
			part, err := base64.StdEncoding.DecodeString(entry.Bytes)
			if err != nil || len(body)+len(part) > observationBodyLimit {
				return observedRequest{}, false
			}
			body = append(body, part...)
			clear(part)
		}
		var bound struct {
			ID     string `json:"checkout_session_id"`
			Entity string `json:"processor_entity"`
		}
		err = json.Unmarshal(body, &bound)
		clear(body)
		if err != nil || bound.ID != o.session.ID || (bound.Entity != "" && bound.Entity != o.session.Entity) {
			return observedRequest{}, false
		}
		r.kind = "checkout_confirm"
	case u.Host == "api.stripe.com" && u.Path == "/v1/payment_pages/"+o.session.ID+"/confirm":
		r.kind = "page_confirm"
	case u.Host == "api.stripe.com" && strings.HasPrefix(u.Path, "/v1/payment_intents/"):
		parts := strings.Split(strings.TrimPrefix(u.Path, "/v1/payment_intents/"), "/")
		if len(parts) != 2 || !intentIDPattern.MatchString(parts[0]) || (parts[1] != "confirm" && parts[1] != "verify_challenge") {
			return observedRequest{}, false
		}
		r.kind = "intent"
		r.intent = parts[0]
	default:
		return observedRequest{}, false
	}
	o.sequence++
	r.sequence = o.sequence
	return r, true
}

// attach observes only an already validated target belonging to this browser.
// The event callback does no blocking CDP calls and retains no request bodies.
func (o *paymentObserver) attach(ctx context.Context) {
	var mu sync.Mutex
	pending := make(map[network.RequestID]observedRequest)
	chromedp.ListenTarget(ctx, func(event any) {
		mu.Lock()
		defer mu.Unlock()
		switch e := event.(type) {
		case *network.EventRequestWillBeSent:
			delete(pending, e.RequestID)
			if len(pending) >= 32 {
				return
			}
			if request, ok := o.track(e); ok {
				pending[e.RequestID] = request
			}
		case *network.EventResponseReceived:
			request, ok := pending[e.RequestID]
			if !ok || e.Response == nil {
				return
			}
			if e.Response.URL != request.url {
				delete(pending, e.RequestID)
				return
			}
			request.status = e.Response.Status
			request.json = strings.EqualFold(strings.Split(e.Response.MimeType, ";")[0], "application/json")
			pending[e.RequestID] = request
		case *network.EventLoadingFailed:
			delete(pending, e.RequestID)
		case *network.EventLoadingFinished:
			request, ok := pending[e.RequestID]
			delete(pending, e.RequestID)
			if !ok || !request.json || request.status < 200 || request.status >= 500 || request.status >= 300 && request.status < 400 || e.EncodedDataLength > observationBodyLimit {
				return
			}
			executor := cdp.WithExecutor(ctx, chromedp.FromContext(ctx).Target)
			select {
			case o.queue <- observedResponse{request: request, ctx: executor, id: e.RequestID}:
			default:
			}
		}
	})
}

type observedIntent struct {
	checkout.PaymentIntent
	ID       string `json:"id"`
	Amount   int64  `json:"amount"`
	Currency string `json:"currency"`
}

func (o *paymentObserver) accept(request observedRequest, body []byte) {
	if len(body) > observationBodyLimit || request.status < 200 || request.status >= 500 || request.status >= 300 && request.status < 400 {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.armed {
		return
	}
	var intent observedIntent
	switch request.kind {
	case "checkout_confirm":
		if request.status != 200 {
			return
		}
		var reply struct {
			Type   string `json:"type"`
			Status string `json:"status"`
			Secret string `json:"client_secret"`
		}
		if json.Unmarshal(body, &reply) != nil || reply.Type != "payment_intent" || reply.Status != "success" {
			return
		}
		matches := intentSecretPattern.FindStringSubmatch(reply.Secret)
		if len(matches) != 2 {
			return
		}
		if o.intent != "" && o.intent != matches[1] {
			return
		}
		o.intent = strings.Clone(matches[1]) // do not retain the secret's backing string
		return
	case "page_confirm":
		if request.status != 200 {
			return
		}
		// Only accept an explicit order ID plus an expanded PaymentIntent. The
		// captured Payment Page body was unavailable; unknown shapes stay unknown.
		var reply struct {
			ID     string         `json:"id"`
			Intent observedIntent `json:"payment_intent"`
		}
		if json.Unmarshal(body, &reply) != nil || reply.ID != o.session.ID || !intentIDPattern.MatchString(reply.Intent.ID) {
			return
		}
		intent = reply.Intent
		if intent.Amount != o.amount || intent.Currency != o.currency || o.intent != "" && o.intent != intent.ID {
			return
		}
		o.intent = intent.ID
	case "intent":
		if o.intent == "" || request.intent != o.intent {
			return
		}
		if json.Unmarshal(body, &intent) != nil {
			return
		}
		if intent.ID == "" {
			var envelope struct {
				Error struct {
					Intent observedIntent `json:"payment_intent"`
				} `json:"error"`
			}
			if json.Unmarshal(body, &envelope) != nil {
				return
			}
			intent = envelope.Error.Intent
		}
	default:
		return
	}
	if intent.ID != o.intent || intent.Amount != o.amount || intent.Currency != o.currency || request.sequence < o.latest {
		return
	}
	result := intent.Result()
	if result.State == "unknown" {
		return
	}
	o.latest = request.sequence
	o.result = Observation{PaymentResult: result, Observed: true}
}

// Observe reads only cached, sanitized results; it issues no payment request.
func (b *Browser) Observe(ctx context.Context, auth checkout.Auth, session checkout.Session) (Observation, error) {
	out := Observation{PaymentResult: checkout.PaymentResult{State: "unknown"}}
	err := b.run(ctx, chromedp.ActionFunc(func(context.Context) error {
		if b.owner == "" || b.owner != checkout.Owner(auth) || b.session != session {
			return errors.New("order ownership mismatch")
		}
		if b.observer != nil {
			b.observer.mu.Lock()
			if b.observer.result.Observed {
				out = b.observer.result
			}
			b.observer.mu.Unlock()
		}
		return nil
	}))
	return out, err
}
