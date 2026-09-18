package browser

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/chromedp"
	"github.com/wjsoj/cc-core/checkout"
)

// SubmitResult never infers paid from a click, navigation, or HTTP 200.
// Attempted means a durable guard exists (or is conservatively presumed), not
// that a charge succeeded. After Attempted, only observe/reconcile this order.
type SubmitResult struct {
	checkout.PaymentResult
	Attempted bool `json:"attempted"`
}

func billingDigest(billing checkout.Billing) string {
	data, _ := json.Marshal(billing)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Submit performs one native browser click on this order's Subscribe control.
// The application must obtain explicit user confirmation of q before calling.
// No CAPTCHA response, payment token, arbitrary script or URL is accepted.
// The upstream quote, page binding, form readiness, and durable shared ledger
// are checked before dispatch. Errors after reservation never authorize retry.
func (b *Browser) Submit(ctx context.Context, auth checkout.Auth, q checkout.Quote, ledger *checkout.Ledger) (SubmitResult, error) {
	out := SubmitResult{PaymentResult: checkout.PaymentResult{State: "unknown", Message: "尚未提交付款"}}
	if ledger == nil || q.Session.Validate() != nil || !time.Now().Before(q.Expires) {
		return out, errors.New("missing ledger or valid quote")
	}
	err := b.run(ctx, chromedp.ActionFunc(func(op context.Context) error {
		if err := b.checkOrderPage(op, auth, q.Session); err != nil {
			return err
		}
		if b.submitAttempted || ledger.Owns(auth, q.Session) {
			out.Attempted = true
			out.Message = "已有付款确认记录；仅查询本单结果"
			return errors.New("payment already attempted")
		}
		if !b.cardFilled || b.billingHash == "" || b.billingHash != billingDigest(q.Billing) {
			out.Message = "请先完整填写本单账单和卡片"
			return errors.New("payment fields not ready")
		}
		client := b.lockedQueryClient(op)
		defer client.Close()
		fresh, err := client.Quote(op, auth, q.Session, q.Selection, q.Billing)
		if err != nil {
			out.Message = "无法重新核验报价；未点击付款"
			return err
		}
		if fresh.Amount != q.Amount || fresh.Key != q.Key || fresh.UserID != q.UserID || fresh.AccountID != q.AccountID || !time.Now().Before(q.Expires) {
			out.Message = "报价或账号已变化；请重新核对"
			return errors.New("quote changed")
		}
		var point struct {
			Ready bool    `json:"ready"`
			X     float64 `json:"x"`
			Y     float64 `json:"y"`
		}
		if err = evaluate(subscribePointJS, []any{q.Session.URL()}, &point).Do(op); err != nil || !point.Ready {
			out.Message = "订阅按钮未就绪、被遮挡或不唯一；未点击付款"
			return errors.New("subscribe control not ready")
		}
		// The only financial action is below this fsynced, exclusive guard.
		if err = ledger.BeginAttempt(auth, q); err != nil {
			out.Attempted = true // a partial durable write is uncertain too
			b.submitAttempted = true
			out.Message = "付款记录已存在或无法可靠写入；未点击，仅查询"
			return err
		}
		out.Attempted = true
		b.submitAttempted = true
		if b.observer != nil {
			b.observer.arm(q)
		}
		out.Message = "付款提交结果待确认；请勿重新提交"
		// Re-resolve after the filesystem operation; never click stale coords.
		point.Ready = false
		if err = evaluate(subscribePointJS, []any{q.Session.URL()}, &point).Do(op); err != nil || !point.Ready {
			return errors.New("subscribe control changed after reservation")
		}
		if err = input.DispatchMouseEvent(input.MousePressed, point.X, point.Y).WithButton(input.Left).WithClickCount(1).Do(op); err != nil {
			return err
		}
		if err = input.DispatchMouseEvent(input.MouseReleased, point.X, point.Y).WithButton(input.Left).WithClickCount(1).Do(op); err != nil {
			return err
		}
		b.cardFilled = false
		out.State = "processing"
		out.Message = "已点击订阅，等待支付结果或用户验证；尚未确认扣款成功"
		return nil
	}))
	return out, err
}

// Exact labels are deliberate: a changed/ambiguous checkout UI is a manual
// handoff condition, not permission to click any submit button. Hit testing
// rejects challenge/other overlays; no checkboxes or challenges are answered.
const subscribePointJS = `function(url){
	if(location.origin+location.pathname!==url)return {ready:false};
	const nodes=[...document.querySelectorAll('button')].filter(el=>
		/^(Subscribe|订阅)$/.test((el.innerText||'').trim()) && !el.disabled && el.getAttribute('aria-disabled')!=='true' &&
		el.getClientRects().length && getComputedStyle(el).visibility!=='hidden');
	if(nodes.length!==1)return {ready:false};
	const el=nodes[0];el.scrollIntoView({block:'center',inline:'center',behavior:'instant'});
	const r=el.getBoundingClientRect(),x=r.left+r.width/2,y=r.top+r.height/2;
	if(x<0||y<0||x>=innerWidth||y>=innerHeight||!el.contains(document.elementFromPoint(x,y)))return {ready:false};
	if(el.form&&!el.form.checkValidity())return {ready:false};
	return {ready:true,x,y};
}`
