package browser

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/chromedp/chromedp"
	"github.com/wjsoj/cc-core/checkout"
)

// QueryClient reuses cc-core's existing quote and status validation while
// executing those requests inside this order's Chromium session. Closing the
// returned client does not close the Browser. This adapter cannot execute Pay,
// subscription mutations, arbitrary URLs or another order's requests.
func (b *Browser) QueryClient() *checkout.Client {
	c, _ := checkout.NewClientWithTransport(&queryTransport{browser: b})
	return c
}

// lockedQueryClient is private: only an action already holding b.gate may use
// it. This keeps final quote revalidation and the click in one serialized action.
func (b *Browser) lockedQueryClient(ctx context.Context) *checkout.Client {
	c, _ := checkout.NewClientWithTransport(&queryTransport{browser: b, locked: ctx})
	return c
}

type queryTransport struct {
	browser *Browser
	locked  context.Context
}

type queryReply struct {
	Status    int    `json:"status"`
	Body      string `json:"body"`
	Challenge bool   `json:"challenge"`
}

func (t *queryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		defer req.Body.Close()
	}
	if req.URL == nil || req.URL.Scheme != "https" || req.URL.Host != "chatgpt.com" || req.URL.User != nil || req.URL.RawQuery != "" || req.URL.Fragment != "" || req.URL.RawPath != "" {
		return nil, errors.New("browser query destination denied")
	}
	authorization := req.Header.Get("Authorization")
	if !strings.HasPrefix(authorization, "Bearer ") {
		return nil, errors.New("browser query authentication required")
	}
	auth, err := checkout.ParseAuth(strings.TrimPrefix(authorization, "Bearer "))
	if err != nil {
		return nil, errors.New("invalid browser query authentication")
	}
	var body []byte
	if req.Body != nil {
		body, err = io.ReadAll(io.LimitReader(req.Body, 64*1024+1))
		if err != nil || len(body) > 64*1024 {
			return nil, errors.New("browser query body invalid")
		}
	}
	var reply queryReply
	b := t.browser
	run := b.run
	if t.locked != nil {
		run = func(_ context.Context, actions ...chromedp.Action) error { return chromedp.Run(t.locked, actions...) }
	}
	err = run(req.Context(), chromedp.ActionFunc(func(context.Context) error {
		if b.owner == "" || b.owner != checkout.Owner(auth) || b.session.Validate() != nil {
			return errors.New("browser order ownership mismatch")
		}
		return validateQuery(req.Method, req.URL.Path, body, b.session)
	}), evaluate(queryJS, []any{auth.Token, req.Method, req.URL.Path, string(body)}, &reply))
	if err != nil {
		return nil, err
	}
	if reply.Status < 100 || reply.Status > 599 || len(reply.Body) > 2*1024*1024 {
		return nil, errors.New("browser query failed or response too large")
	}
	headers := make(http.Header)
	headers.Set("Content-Type", "application/json")
	if reply.Challenge {
		headers.Set("Cf-Mitigated", "challenge")
	}
	return &http.Response{StatusCode: reply.Status, Header: headers, Body: io.NopCloser(strings.NewReader(reply.Body)), ContentLength: int64(len(reply.Body)), Request: req}, nil
}

func validateQuery(method, path string, body []byte, session checkout.Session) error {
	const base = "/backend-api/payments/checkout"
	if method == http.MethodGet && path == base+"/"+session.Entity+"/"+session.ID && len(body) == 0 {
		return nil
	}
	if method == http.MethodPost && path == base+"/taxes" {
		var payload struct {
			ID       string            `json:"checkout_session_id"`
			Entity   string            `json:"processor_entity"`
			Email    string            `json:"checkout_email"`
			Country  string            `json:"billing_country"`
			Name     string            `json:"billing_name"`
			Currency string            `json:"currency"`
			Address  map[string]string `json:"billing_address"`
		}
		decoder := json.NewDecoder(strings.NewReader(string(body)))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&payload) == nil && decoder.Decode(&struct{}{}) == io.EOF && payload.ID == session.ID && payload.Entity == session.Entity {
			return nil
		}
	}
	return errors.New("browser query operation denied")
}

// Explicit origin and redirect checks prevent authorization from following an
// unexpected navigation. The reader enforces a byte limit before transferring
// JSON through CDP; no upstream bodies are logged or treated as success here.
const queryJS = `async function(token, method, path, body) {
	if(location.origin !== 'https://chatgpt.com') return {status:0};
	try {
		const headers={Authorization:'Bearer '+token,Accept:'application/json'};
		if(method==='POST') headers['Content-Type']='application/json';
		const response=await fetch(path,{method,headers,body:method==='POST'?body:undefined,
			credentials:'same-origin',redirect:'error',signal:AbortSignal.timeout(25000)});
		const challenge=response.headers.get('cf-mitigated')==='challenge';
		// Error bodies can contain secrets or HTML; the shared client classifies
		// errors from HTTP status and explicit challenge metadata, not raw text.
		if(!response.ok || challenge) {if(response.body) await response.body.cancel(); return {status:response.status,challenge,body:''};}
		if(!response.body) return {status:0};
		const reader=response.body.getReader(), decoder=new TextDecoder();
		let total=0,text='';
		try {
			for(;;) {const {value,done}=await reader.read(); if(done) break;
				total+=value.byteLength; if(total>2097152) {await reader.cancel();return {status:0};}
				text+=decoder.decode(value,{stream:true});}
			text+=decoder.decode();
		} finally {reader.releaseLock();}
		return {status:response.status,body:text,challenge:false};
	} catch(_) {return {status:0};}
}`
