package checkout

import (
	"context"
	"errors"
	"testing"
)

func TestBillingAddressProviderUnconfigured(t *testing.T) {
	_, err := ResolveBillingAddress(context.Background(), nil, BillingAddressQuery{Country: "US"})
	if !errors.Is(err, ErrBillingAddressProviderNotConfigured) {
		t.Fatal(err)
	}
	var nilFunc BillingAddressProviderFunc
	_, err = ResolveBillingAddress(context.Background(), nilFunc, BillingAddressQuery{Country: "US"})
	if !errors.Is(err, ErrBillingAddressProviderNotConfigured) {
		t.Fatal(err)
	}
}
func TestBillingAddressProviderContract(t *testing.T) {
	fixture := BillingAddressResult{Address: BillingAddress{Line1: "TEST ONLY", City: "TEST", State: "OR", PostalCode: "00000", Country: "US"}, Source: "unit-test", Sample: true}
	provider := BillingAddressProviderFunc(func(context.Context, BillingAddressQuery) (BillingAddressResult, error) { return fixture, nil })
	r, err := ResolveBillingAddress(context.Background(), provider, BillingAddressQuery{Country: "US", State: "OR"})
	if err != nil || !r.Sample || !r.RequiresConfirmation {
		t.Fatalf("%+v %v", r, err)
	}
	for _, q := range []BillingAddressQuery{{Country: "US", State: "DE"}, {Country: "XX"}, {Country: "US", Input: "invalid\ninput"}} {
		if _, err = ResolveBillingAddress(context.Background(), provider, q); err == nil {
			t.Fatal("invalid query/region accepted")
		}
	}
	fixture.Address.Line1 = ""
	if _, err = ResolveBillingAddress(context.Background(), provider, BillingAddressQuery{Country: "US"}); err == nil {
		t.Fatal("incomplete candidate accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = ResolveBillingAddress(ctx, provider, BillingAddressQuery{Country: "US"}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
