package browser

import (
	"context"
	"errors"
	"net"

	"github.com/chromedp/cdproto/browser"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/chromedp"
)

// RuntimeReport is deliberately credential-free. A successful offline check
// does not prove payment eligibility, proxy routing, or full OS sandbox policy.
type RuntimeReport struct {
	Product     string `json:"product"`
	JavaScript  bool   `json:"javascript"`
	WebAssembly bool   `json:"webassembly"`
	Locale      string `json:"locale"`
	Timezone    string `json:"timezone"`
	Offline     bool   `json:"offline"`
}

// CheckRuntime uses the SAME allocator/security flags and unprivileged-user
// requirement as order browsers, but its egress dialer denies every connection.
// It reads only about:blank, takes no credentials, and closes all resources.
// Run in the actual service unit's security/resource context before publishing;
// a successful shell invocation says nothing about a stricter systemd unit.
func CheckRuntime(ctx context.Context, config Config) (RuntimeReport, error) {
	var report RuntimeReport
	if config.Proxy != "" {
		return report, errors.New("offline runtime check does not accept proxy credentials")
	}
	b, err := start(ctx, config, func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("offline check denies network")
	})
	if err != nil {
		return report, err
	}
	defer b.Close()
	err = b.run(ctx, chromedp.ActionFunc(func(op context.Context) error {
		_, product, _, _, _, err := browser.GetVersion().Do(cdp.WithExecutor(op, chromedp.FromContext(op).Browser))
		if err != nil {
			return err
		}
		report.Product = product
		return nil
	}), evaluate(`function(){
		if(location.href!=='about:blank')throw new Error('unexpected diagnostic page');
		const opts=Intl.DateTimeFormat().resolvedOptions();
		const code=new Uint8Array([0,97,115,109,1,0,0,0,1,5,1,96,0,1,127,3,2,1,0,7,10,1,6,97,110,115,119,101,114,0,0,10,6,1,4,0,65,42,11]);
		return {javascript:[1,2,3].reduce((a,b)=>a+b,0)===6,webassembly:new WebAssembly.Instance(new WebAssembly.Module(code)).exports.answer()===42,locale:opts.locale,timezone:opts.timeZone};
	}`, []any{}, &report))
	if err != nil {
		return RuntimeReport{}, err
	}
	if !report.JavaScript || !report.WebAssembly {
		return RuntimeReport{}, errors.New("browser execution engine check failed")
	}
	report.Offline = true
	return report, nil
}
