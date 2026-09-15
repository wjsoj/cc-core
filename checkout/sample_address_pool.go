package checkout

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"strings"
)

var (
	ErrEmptyAddressPool  = errors.New("样例地址库为空")
	ErrNoMatchingAddress = errors.New("地址库中没有匹配的地区")
)

const MaxSampleAddressPoolBytes = 16 * 1024 * 1024
const MaxSampleAddressPoolRows = 50000

// SampleAddressPool samples whole records from caller-supplied, authorized test
// data. It never generates a street/ZIP combination, fetches third-party data,
// or claims that a sampled location belongs to a cardholder. Every result is
// marked Sample=true and remains independent of the payment workflow.
// The immutable pool is safe for concurrent Resolve calls.
type SampleAddressPool struct {
	source string
	rows   []BillingAddress
	choose func(int) (int, error)
}

// NewSampleAddressPool copies and validates the input; later caller mutations
// cannot change the pool. Empty filters sample uniformly over ALL records,
// rather than first choosing a state and biasing small states.
func NewSampleAddressPool(source string, rows []BillingAddress) (*SampleAddressPool, error) {
	if len(rows) == 0 {
		return nil, ErrEmptyAddressPool
	}
	if len(rows) > MaxSampleAddressPoolRows {
		return nil, errors.New("地址库记录过多")
	}
	source = strings.TrimSpace(source)
	p := &SampleAddressPool{source: source, rows: make([]BillingAddress, len(rows)), choose: func(n int) (int, error) {
		v, e := rand.Int(rand.Reader, big.NewInt(int64(n)))
		if e != nil {
			return 0, errors.New("随机地址选择失败")
		}
		return int(v.Int64()), nil
	}}
	for i, a := range rows {
		a.Line1 = strings.TrimSpace(a.Line1)
		a.Line2 = strings.TrimSpace(a.Line2)
		a.City = strings.TrimSpace(a.City)
		a.PostalCode = strings.TrimSpace(a.PostalCode)
		a.Country = strings.ToUpper(strings.TrimSpace(a.Country))
		a.State = strings.ToUpper(strings.TrimSpace(a.State))
		candidate := BillingAddressResult{Address: a, Source: source, Sample: true}
		check := BillingAddressProviderFunc(func(context.Context, BillingAddressQuery) (BillingAddressResult, error) { return candidate, nil })
		if _, err := ResolveBillingAddress(context.Background(), check, BillingAddressQuery{}); err != nil {
			return nil, err
		}
		p.rows[i] = a
	}
	return p, nil
}

// LoadSampleAddressPool accepts a bounded JSON array of BillingAddress records.
// Unknown fields, trailing JSON, incomplete records and empty pools are rejected.
// It does not infer a file path or make network requests.
func LoadSampleAddressPool(source string, input io.Reader) (*SampleAddressPool, error) {
	if input == nil {
		return nil, ErrEmptyAddressPool
	}
	raw, err := io.ReadAll(io.LimitReader(input, MaxSampleAddressPoolBytes+1))
	if err != nil || len(raw) > MaxSampleAddressPoolBytes {
		return nil, errors.New("无法读取地址库或文件过大")
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	var rows []BillingAddress
	if decoder.Decode(&rows) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return nil, errors.New("地址库必须为有效 JSON 地址数组")
	}
	return NewSampleAddressPool(source, rows)
}

func (p *SampleAddressPool) Len() int {
	if p == nil {
		return 0
	}
	return len(p.rows)
}
func (p *SampleAddressPool) Resolve(ctx context.Context, q BillingAddressQuery) (BillingAddressResult, error) {
	var empty BillingAddressResult
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if p == nil || len(p.rows) == 0 {
		return empty, ErrEmptyAddressPool
	}
	q.Country = strings.ToUpper(strings.TrimSpace(q.Country))
	q.State = strings.ToUpper(strings.TrimSpace(q.State))
	if q.Input != "" {
		return empty, errors.New("随机样例地址池不支持文本地址检索")
	}
	// Reuse public query/output validation without recursion through this pool.
	provider := BillingAddressProviderFunc(func(ctx context.Context, filter BillingAddressQuery) (BillingAddressResult, error) {
		matches := func(a BillingAddress) bool {
			return (filter.Country == "" || a.Country == filter.Country) && (filter.State == "" || a.State == filter.State)
		}
		count := 0
		for i, a := range p.rows {
			if i%256 == 0 && ctx.Err() != nil {
				return empty, ctx.Err()
			}
			if matches(a) {
				count++
			}
		}
		if count == 0 {
			return empty, ErrNoMatchingAddress
		}
		index, err := p.choose(count)
		if err != nil {
			return empty, err
		}
		if index < 0 || index >= count {
			return empty, errors.New("随机地址选择失败")
		}
		for i, a := range p.rows {
			if i%256 == 0 && ctx.Err() != nil {
				return empty, ctx.Err()
			}
			if matches(a) {
				if index == 0 {
					return BillingAddressResult{Address: a, Source: p.source, Sample: true, RequiresConfirmation: true}, nil
				}
				index--
			}
		}
		return empty, ErrNoMatchingAddress
	})
	return ResolveBillingAddress(ctx, provider, q)
}

var _ BillingAddressProvider = (*SampleAddressPool)(nil)
