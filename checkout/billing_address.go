package checkout

import (
	"context"
	"errors"
	"strings"
)

var ErrBillingAddressProviderNotConfigured = errors.New("账单地址数据源尚未配置")

// BillingAddressQuery describes address lookup/autocomplete input. It does not
// contain card data, session tokens, or an instruction to change tax residency.
// A future provider may resolve a saved user address or normalize typed input.
type BillingAddressQuery struct {
	// Empty Country and State allow a provider to select across its full pool.
	Country string `json:"country,omitempty"`
	State   string `json:"state,omitempty"`
	Input   string `json:"input,omitempty"`
}

// BillingAddress contains postal fields only. A physical location's existence
// does not establish that it is the cardholder's registered billing address.
type BillingAddress struct {
	Line1      string `json:"line1"`
	Line2      string `json:"line2,omitempty"`
	City       string `json:"city"`
	State      string `json:"state,omitempty"`
	PostalCode string `json:"postal_code"`
	Country    string `json:"country"`
}

type BillingAddressResult struct {
	Address BillingAddress `json:"address"`
	Source  string         `json:"source"`
	// Sample identifies generated/test data; it is not a real-payment address.
	Sample bool `json:"sample"`
	// Always true through ResolveBillingAddress. Suggestions never replace the
	// user's billing information or establish ownership automatically.
	RequiresConfirmation bool `json:"requires_confirmation"`
}

// BillingAddressProvider is an extension point, not a bundled address generator.
// Providers must document data provenance and distinguish samples from user
// addresses. No MockAddress code/data is vendored, and no network call is made
// unless the application explicitly supplies a provider implementation.
type BillingAddressProvider interface {
	Resolve(context.Context, BillingAddressQuery) (BillingAddressResult, error)
}

type BillingAddressProviderFunc func(context.Context, BillingAddressQuery) (BillingAddressResult, error)

func (f BillingAddressProviderFunc) Resolve(ctx context.Context, q BillingAddressQuery) (BillingAddressResult, error) {
	if f == nil {
		return BillingAddressResult{}, ErrBillingAddressProviderNotConfigured
	}
	return f(ctx, q)
}

// ResolveBillingAddress invokes the configured provider and returns a candidate
// for human review. It never modifies Billing or calls Quote, Pay, or Create.
// There is deliberately no automatic random-address fallback.
func ResolveBillingAddress(ctx context.Context, p BillingAddressProvider, q BillingAddressQuery) (BillingAddressResult, error) {
	var empty BillingAddressResult
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	q.Country = strings.ToUpper(strings.TrimSpace(q.Country))
	q.State = strings.ToUpper(strings.TrimSpace(q.State))
	if q.Country != "" && (len(q.Country) != 2 || !strings.Contains(countries, " "+q.Country+" ")) {
		return empty, errors.New("地址国家无效")
	}
	for _, v := range []string{q.State, q.Input} {
		if len(v) > 512 || strings.ContainsFunc(v, func(r rune) bool { return r < 32 || r == 127 }) {
			return empty, errors.New("地址查询参数无效")
		}
	}
	if p == nil {
		return empty, ErrBillingAddressProviderNotConfigured
	}
	result, err := p.Resolve(ctx, q)
	if err != nil {
		return empty, err
	}
	if err = ctx.Err(); err != nil {
		return empty, err
	}
	if result.Source == "" || len(result.Source) > 128 || q.Country != "" && result.Address.Country != q.Country || q.State != "" && result.Address.State != q.State {
		return empty, errors.New("地址数据源或地区不匹配")
	}
	a := result.Address
	if len(a.Country) != 2 || !strings.Contains(countries, " "+a.Country+" ") {
		return empty, errors.New("地址数据源返回无效国家")
	}
	for _, v := range []string{a.Line1, a.City, a.PostalCode} {
		if strings.TrimSpace(v) == "" {
			return empty, errors.New("地址数据源未返回完整地址")
		}
	}
	for _, v := range []string{a.Line1, a.Line2, a.City, a.State, a.PostalCode, result.Source} {
		if len(v) > 254 || strings.ContainsFunc(v, func(r rune) bool { return r < 32 || r == 127 }) {
			return empty, errors.New("地址数据源返回无效字段")
		}
	}
	result.RequiresConfirmation = true
	return result, nil
}
