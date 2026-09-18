package checkout

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
)

// attemptRecord contains only the immutable identity/amount binding recorded
// before confirmation. It never contains Session credentials, card or address.
type attemptRecord struct {
	Session   Session         `json:"session"`
	Owner     string          `json:"owner"`
	Amount    int64           `json:"amount_minor"`
	Currency  string          `json:"currency"`
	Plan      string          `json:"plan"`
	Phase     string          `json:"phase"`
	UserID    string          `json:"user_id"`
	AccountID string          `json:"account_id"`
	Network   *networkBinding `json:"network,omitempty"`
}

// StatusReader is the read-only subset required by reconciliation. Both the
// direct client and the isolated browser adapter implement it. There is no
// create/quote/confirm method available to these routines.
type StatusReader interface {
	Status(context.Context, Auth, Session) (Snapshot, error)
}

// AttemptExists distinguishes verified absence from an unreadable/corrupt
// guard. Callers must not fall back to an in-memory quote if any record exists
// or the filesystem cannot establish absence. This does not authorize access
// to a record; Reconcile still checks ownership and all recorded bindings.
func (l *Ledger) AttemptExists(s Session) (bool, error) {
	failed := errors.New("无法核验本单付款记录，停止自动判定")
	if l == nil || s.Validate() != nil {
		return false, failed
	}
	root, err := os.OpenRoot(l.dir)
	if err != nil {
		return false, failed
	}
	defer root.Close()
	sum := sha256.Sum256([]byte(s.Entity + ":" + s.ID))
	_, err = root.Lstat(hex.EncodeToString(sum[:]) + ".json")
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, failed
	}
	return true, nil
}

func (l *Ledger) readAttempt(a Auth, s Session) (attemptRecord, error) {
	var record attemptRecord
	denied := errors.New("没有可核验的本单付款记录，请核对原登录态和结账编号")
	if l == nil || !validToken(a.Token) || s.Validate() != nil {
		return record, denied
	}
	root, err := os.OpenRoot(l.dir)
	if err != nil {
		return record, denied
	}
	defer root.Close()
	sum := sha256.Sum256([]byte(s.Entity + ":" + s.ID))
	name := hex.EncodeToString(sum[:]) + ".json"
	info, err := root.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 8192 || info.Mode().Perm()&0077 != 0 {
		return record, denied
	}
	f, err := root.Open(name)
	if err != nil {
		return record, denied
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 8192 || info.Mode().Perm()&0077 != 0 {
		return record, denied
	}
	data, err := io.ReadAll(io.LimitReader(f, 8193))
	if err != nil || len(data) > 8192 || json.Unmarshal(data, &record) != nil || record.Owner != Owner(a) || record.Session != s || record.Phase != "confirm_started" {
		return attemptRecord{}, denied
	}
	return record, nil
}

// Reconcile is read-only: exactly one authenticated GET for the bound order,
// using this client's existing egress. No taxes, confirm, resubmit or fallback.
// Legacy records without identity remain readable but cannot prove payment.
// A refreshed login token cannot take over another token's recorded attempt.
func (c *Client) Reconcile(ctx context.Context, a Auth, s Session, ledger *Ledger) (PaymentResult, error) {
	return Reconcile(ctx, c, a, s, ledger)
}

// Reconcile accepts only a trusted in-process StatusReader and a recorded order.
// It performs the same checks as Client.Reconcile without requiring a concrete
// transport, so HTTP services can reuse the checks with their backend adapter.
func Reconcile(ctx context.Context, reader StatusReader, a Auth, s Session, ledger *Ledger) (PaymentResult, error) {
	unknown := PaymentResult{State: "unknown", Message: "付款结果待核验；不要重复提交"}
	if reader == nil {
		return unknown, errors.New("缺少只读状态查询客户端")
	}
	record, err := ledger.readAttempt(a, s)
	if err != nil {
		return unknown, err
	}
	snap, err := reader.Status(ctx, a, s)
	if err != nil {
		return unknown, err
	}
	return reconcileSnapshot(a, record, snap)
}

// ReconcileQuote checks an in-memory, upstream-verified quote when the user
// completed this checkout outside the service's own submit action. Quote expiry
// does not invalidate read-only reconciliation of a late payment. Never pass a
// visitor-supplied Quote directly; authenticate and retain it when quoting.
func (c *Client) ReconcileQuote(ctx context.Context, a Auth, q Quote) (PaymentResult, error) {
	return ReconcileQuote(ctx, c, a, q)
}

// ReconcileQuote is the StatusReader form of Client.ReconcileQuote. The quote
// must come from server-side upstream verification, never from visitor input.
func ReconcileQuote(ctx context.Context, reader StatusReader, a Auth, q Quote) (PaymentResult, error) {
	unknown := PaymentResult{State: "unknown", Message: "付款结果待核验；不要重复提交"}
	if reader == nil || q.Session.Validate() != nil || q.Selection.Validate() != nil || !validToken(a.Token) {
		return unknown, errors.New("对账参数无效")
	}
	record := attemptRecord{Session: q.Session, Owner: Owner(a), Amount: q.Amount, Currency: q.Selection.Currency, Plan: q.Selection.Plan, UserID: q.UserID, AccountID: q.AccountID}
	snap, err := reader.Status(ctx, a, q.Session)
	if err != nil {
		return unknown, err
	}
	return reconcileSnapshot(a, record, snap)
}

func reconcileSnapshot(a Auth, record attemptRecord, snap Snapshot) (PaymentResult, error) {
	unknown := PaymentResult{State: "unknown", Message: "付款结果待核验；不要重复提交"}
	mismatch := errors.New("付款结果与本单账号、套餐、金额或币种不一致")
	// Missing fields are not invented from frontend input. Present conflicting
	// evidence must not be overridden by a convenient fallback field either.
	if record.Amount <= 0 || record.Amount > 999999999 || record.Currency == "" || record.Plan == "" ||
		a.UserID != "" && record.UserID != "" && a.UserID != record.UserID ||
		a.AccountID != "" && record.AccountID != "" && a.AccountID != record.AccountID ||
		snap.Amount != 0 && snap.Amount != record.Amount || snap.Currency != "" && snap.Currency != strings.ToLower(record.Currency) ||
		snap.Plan != "" && snap.Plan != record.Plan || snap.Metadata["user_origin_tag"] != "" && snap.Metadata["user_origin_tag"] != record.Plan ||
		snap.Metadata["user_ref"] != "" && record.UserID != "" && snap.Metadata["user_ref"] != record.UserID ||
		snap.Metadata["account_id"] != "" && record.AccountID != "" && snap.Metadata["account_id"] != record.AccountID {
		return unknown, mismatch
	}
	if snap.Paid() {
		plan := snap.Plan
		if plan == "" {
			plan = snap.Metadata["user_origin_tag"]
		}
		if snap.Amount != record.Amount || snap.Currency != strings.ToLower(record.Currency) || plan != record.Plan ||
			record.UserID == "" || record.AccountID == "" || snap.Metadata["user_ref"] != record.UserID || snap.Metadata["account_id"] != record.AccountID {
			return unknown, errors.New("上游标记已支付，但本单核验字段不完整；请人工对账，不要重新付款")
		}
		return PaymentResult{State: "paid", Paid: true, Message: "本单支付成功，账号、套餐、金额和币种已核验"}, nil
	}
	if snap.PaymentStatus == "unpaid" {
		switch snap.Status {
		case "open":
			return PaymentResult{State: "pending", Message: "本单尚未确认支付成功；只查询，不重新提交"}, nil
		case "expired":
			return PaymentResult{State: "expired", Message: "本单结账已过期；未确认支付成功"}, nil
		}
	}
	return unknown, nil
}
