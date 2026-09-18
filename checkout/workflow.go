package checkout

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

func (c *Client) Create(ctx context.Context, a Auth, s Selection) (Session, error) {
	var session Session
	if err := s.Validate(); err != nil {
		return session, err
	}
	if !validToken(a.Token) {
		return session, errors.New("登录态无效")
	}
	err := c.oai(ctx, a.Token, "", map[string]any{"entry_point": "all_plans_pricing_modal", "plan_name": s.Plan, "billing_details": map[string]string{"country": s.Country, "currency": s.Currency}, "checkout_ui_mode": "custom"}, &session)
	if err != nil {
		return session, err
	}
	if session.Entity == "" {
		session.Entity = "openai_llc"
	}
	return session, session.Validate()
}
func (c *Client) Status(ctx context.Context, a Auth, s Session) (Snapshot, error) {
	var out Snapshot
	if err := s.Validate(); err != nil {
		return out, err
	}
	err := c.oai(ctx, a.Token, "/"+s.Entity+"/"+s.ID, nil, &out)
	return out, err
}
func (c *Client) Quote(ctx context.Context, a Auth, s Session, sel Selection, b Billing) (Quote, error) {
	q := Quote{Session: s, Selection: sel, Billing: b}
	if err := s.Validate(); err != nil {
		return q, err
	}
	if err := sel.Validate(); err != nil {
		return q, err
	}
	if err := b.Validate(sel.Country); err != nil {
		return q, err
	}
	snap, err := c.Status(ctx, a, s)
	if err != nil {
		return q, err
	}
	var taxed struct {
		Session Snapshot `json:"checkout_session"`
	}
	err = c.oai(ctx, a.Token, "/taxes", map[string]any{"checkout_session_id": s.ID, "checkout_email": b.Email, "billing_country": b.Country, "billing_name": b.Name, "currency": strings.ToLower(sel.Currency), "processor_entity": s.Entity, "billing_address": b.address()}, &taxed)
	if err != nil {
		return q, err
	}
	t := taxed.Session
	plan := snap.Plan
	if plan == "" {
		plan = t.Metadata["user_origin_tag"]
	}
	if snap.Status != "open" || t.Status != "open" || snap.PaymentStatus == "paid" || t.PaymentStatus == "paid" {
		return q, errors.New("会话不再可支付，请查询状态")
	}
	if plan != sel.Plan || t.Currency != strings.ToLower(sel.Currency) || t.Amount <= 0 || t.Amount > 999999999 {
		return q, errors.New("报价套餐、币种或金额不匹配")
	}
	if t.Expires != 0 && t.Expires <= time.Now().Unix() {
		return q, errors.New("结账已过期")
	}
	// Both identity and quote originate from authenticated upstream responses.
	// If JWT identity exists, it must also agree. User-supplied Session.user is ignored.
	q.UserID = t.Metadata["user_ref"]
	q.AccountID = t.Metadata["account_id"]
	if q.UserID == "" || a.UserID != "" && a.UserID != q.UserID || a.AccountID != "" && a.AccountID != q.AccountID {
		return q, errors.New("无法核验结账账号")
	}
	if !regexp.MustCompile(`^pk_live_[A-Za-z0-9]+$`).MatchString(snap.PublishableKey) {
		return q, errors.New("结账支付公钥无效")
	}
	q.Key = snap.PublishableKey
	q.Amount = t.Amount
	q.Expires = time.Now().Add(5 * time.Minute)
	if t.Expires > 0 && time.Unix(t.Expires, 0).Before(q.Expires) {
		q.Expires = time.Unix(t.Expires, 0)
	}
	return q, nil
}

// Ledger persists only a pre-confirm guard. An exclusive, fsynced file survives
// restarts and coordinates multiple processes. Ambiguous attempts never retry.
type Ledger struct {
	dir     string
	network *networkBinding
}

// Owns permits read-only recovery after a server/browser restart using the same
// access token. A refreshed token requires official account recovery instead.
func (l *Ledger) Owns(a Auth, s Session) bool {
	_, err := l.readAttempt(a, s)
	return err == nil
}

func NewLedger(dir string) (*Ledger, error) {
	if !filepath.IsAbs(dir) {
		return nil, errors.New("付款记录目录必须为绝对路径")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, errors.New("无法创建付款记录目录")
	}
	fi, err := os.Lstat(dir)
	if err != nil || !fi.IsDir() || fi.Mode().Perm()&0077 != 0 {
		return nil, errors.New("付款记录目录必须为私有目录 (0700)")
	}
	return &Ledger{dir: dir}, nil
}

// BeginAttempt durably reserves a single confirmation attempt before a browser
// or other executor performs a financial action. It shares the protocol Pay
// guard, including across processes and restarts. A failure never authorizes a
// click; an existing/partially written guard must not be deleted to retry.
// Callers must first revalidate the displayed quote with the authenticated
// upstream. This method validates structure and binding, not upstream truth.
func (l *Ledger) BeginAttempt(a Auth, q Quote) error {
	if l == nil || !validToken(a.Token) || q.Session.Validate() != nil || q.Selection.Validate() != nil ||
		q.Billing.Validate(q.Selection.Country) != nil || q.Amount <= 0 || q.Amount > 999999999 ||
		!time.Now().Before(q.Expires) || q.UserID == "" ||
		a.UserID != "" && a.UserID != q.UserID || a.AccountID != "" && a.AccountID != q.AccountID ||
		!regexp.MustCompile(`^pk_live_[A-Za-z0-9]+$`).MatchString(q.Key) {
		return errors.New("缺少有效报价、账号或持久化防重付记录")
	}
	return l.claim(a, q)
}

func (l *Ledger) claim(a Auth, q Quote) error {
	sum := sha256.Sum256([]byte(q.Session.Entity + ":" + q.Session.ID))
	name := filepath.Join(l.dir, hex.EncodeToString(sum[:])+".json")
	f, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return errors.New("已有付款确认记录或无法写入记录；只可查询状态，不可重复付款")
	}
	data := map[string]any{"session": q.Session, "owner": Owner(a), "amount_minor": q.Amount, "currency": q.Selection.Currency, "plan": q.Selection.Plan, "phase": "confirm_started", "user_id": q.UserID, "account_id": q.AccountID}
	if l.network != nil {
		data["network"] = l.network
	}
	err = json.NewEncoder(f).Encode(data)
	if err == nil {
		err = f.Sync()
	}
	ce := f.Close()
	if err == nil {
		err = ce
	}
	d, de := os.Open(l.dir)
	if de == nil {
		de = d.Sync()
		_ = d.Close()
	}
	if err != nil || de != nil {
		return errors.New("付款记录未可靠落盘，已停止付款")
	}
	return nil
}

type PaymentResult struct {
	State     string `json:"state"`
	Paid      bool   `json:"paid"`
	ErrorCode string `json:"error_code,omitempty"`
	Message   string `json:"message,omitempty"`
}

// Pay requires the exact, previously displayed quote. Never call it again after
// an ambiguous result. requires_action needs user-controlled bank verification;
// this library never sends the browser off-chain or bypasses authentication.
func (c *Client) Pay(ctx context.Context, a Auth, q Quote, card Card, ledger *Ledger) (PaymentResult, error) {
	out := PaymentResult{State: "unknown"}
	if ledger == nil {
		return out, errors.New("缺少持久化防重付记录")
	}
	if !time.Now().Before(q.Expires) {
		return out, errors.New("报价已过期，请重新获取")
	}
	if err := card.Validate(); err != nil {
		return out, err
	}
	refreshed, err := c.Quote(ctx, a, q.Session, q.Selection, q.Billing)
	if err != nil {
		return out, err
	}
	same := func(n Quote) bool {
		return n.Amount == q.Amount && n.Key == q.Key && n.UserID == q.UserID && n.AccountID == q.AccountID
	}
	if !same(refreshed) {
		return out, errors.New("报价或账号已变化，已停止付款")
	}
	form := url.Values{"payment_method_data[type]": {"card"}, "payment_method_data[card][number]": {card.Number}, "payment_method_data[card][cvc]": {card.CVC}, "payment_method_data[card][exp_month]": {card.Month}, "payment_method_data[card][exp_year]": {card.Year}, "payment_method_data[allow_redisplay]": {"limited"}, "payment_method_data[billing_details][name]": {q.Billing.Name}, "payment_method_data[billing_details][email]": {q.Billing.Email}, "key": {q.Key}, "_stripe_version": {"2025-03-31.basil"}}
	for k, v := range q.Billing.address() {
		form.Set("payment_method_data[billing_details][address]["+k+"]", v)
	}
	var token struct {
		ID string `json:"id"`
	}
	err = c.stripe(ctx, "confirmation_tokens", form, &token)
	clear(form)
	card = Card{}
	if err != nil {
		return out, err
	}
	if !regexp.MustCompile(`^ctoken_[A-Za-z0-9]+$`).MatchString(token.ID) {
		return out, errors.New("支付令牌无效")
	}
	refreshed, err = c.Quote(ctx, a, q.Session, q.Selection, q.Billing)
	if err != nil {
		return out, err
	}
	if !same(refreshed) {
		return out, errors.New("确认前报价变化，已停止付款")
	}
	if err = ledger.claim(a, q); err != nil {
		return out, err
	}
	var confirm struct {
		Type   string `json:"type"`
		Status string `json:"status"`
		Secret string `json:"client_secret"`
		Return string `json:"confirm_return_url"`
	}
	err = c.oai(ctx, a.Token, "/confirm", map[string]string{"checkout_session_id": q.Session.ID, "confirm_token": token.ID, "selected_payment_method_type": "card"}, &confirm)
	if err != nil {
		return out, err
	}
	if confirm.Type != "payment_intent" || confirm.Status != "success" || !regexp.MustCompile(`^pi_[A-Za-z0-9]+_secret_[A-Za-z0-9]+$`).MatchString(confirm.Secret) {
		return out, errors.New("付款确认结果未知；仅查询状态")
	}
	ret, err := url.Parse(confirm.Return)
	if err != nil || ret.Scheme != "https" || ret.Host != "chatgpt.com" || ret.Path != "/checkout/verify" || ret.User != nil || ret.Fragment != "" {
		return out, errors.New("付款回跳地址无效；仅查询状态")
	}
	var intent PaymentIntent
	err = c.stripe(ctx, "payment_intents/"+strings.Split(confirm.Secret, "_secret_")[0]+"/confirm", url.Values{"return_url": {confirm.Return}, "confirmation_token": {token.ID}, "key": {q.Key}, "client_secret": {confirm.Secret}, "_stripe_version": {"2025-03-31.basil"}}, &intent)
	if err != nil {
		return out, err
	}
	out = intent.Result()
	switch intent.Status {
	case "requires_action", "requires_payment_method", "canceled":
		return out, nil
	case "succeeded", "processing":
	default:
		return out, errors.New("支付结果未知；仅查询状态")
	}
	result, err := c.Reconcile(ctx, a, q.Session, ledger)
	if err != nil {
		return out, err
	}
	if result.Paid {
		return result, nil
	}
	return out, nil
}
