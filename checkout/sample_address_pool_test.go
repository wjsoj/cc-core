package checkout

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
)

func sampleRows() []BillingAddress {
	return []BillingAddress{
		{Line1: "TEST RECORD A", City: "TEST", State: "CA", PostalCode: "00000", Country: "US"},
		{Line1: "TEST RECORD B", City: "TEST", State: "CA", PostalCode: "00000", Country: "US"},
		{Line1: "TEST RECORD C", City: "TEST", State: "OR", PostalCode: "00000", Country: "US"},
		{Line1: "TEST RECORD D", City: "TEST", State: "BC", PostalCode: "TEST", Country: "CA"},
	}
}
func TestSamplePoolAllRecordsAndFilters(t *testing.T) {
	rows := sampleRows()
	p, err := NewSampleAddressPool("owned-test-fixtures", rows)
	if err != nil {
		t.Fatal(err)
	}
	rows[0].Line1 = "MUTATED"
	for want := range 4 {
		p.choose = func(n int) (int, error) {
			if n != 4 {
				t.Fatal("full pool must weight records, not states")
			}
			return want, nil
		}
		r, e := p.Resolve(context.Background(), BillingAddressQuery{})
		if e != nil || r.Address != sampleRows()[want] || !r.Sample || !r.RequiresConfirmation {
			t.Fatalf("%+v %v", r, e)
		}
	}
	for _, tc := range []struct {
		q    BillingAddressQuery
		n    int
		line string
	}{
		{BillingAddressQuery{Country: "US"}, 3, "TEST RECORD C"},
		{BillingAddressQuery{Country: "us", State: "ca"}, 2, "TEST RECORD B"},
		{BillingAddressQuery{State: "BC"}, 1, "TEST RECORD D"},
	} {
		p.choose = func(n int) (int, error) {
			if n != tc.n {
				t.Fatal("filter count mismatch")
			}
			return n - 1, nil
		}
		r, e := p.Resolve(context.Background(), tc.q)
		if e != nil || r.Address.Line1 != tc.line {
			t.Fatalf("%+v %v", r, e)
		}
	}
	if _, err = p.Resolve(context.Background(), BillingAddressQuery{Country: "US", State: "NY"}); !errors.Is(err, ErrNoMatchingAddress) {
		t.Fatal(err)
	}
	if _, err = p.Resolve(context.Background(), BillingAddressQuery{Country: "XX"}); err == nil {
		t.Fatal("invalid country accepted")
	}
	if _, err = p.Resolve(context.Background(), BillingAddressQuery{Input: "search"}); err == nil {
		t.Fatal("unsupported search silently ignored")
	}
}
func TestSamplePoolJSONAndValidation(t *testing.T) {
	b, _ := json.Marshal(sampleRows())
	p, err := LoadSampleAddressPool("fixtures", strings.NewReader(string(b)))
	if err != nil || p.Len() != 4 {
		t.Fatal(err)
	}
	for _, s := range []string{"[]", "null", "{}", "[{}]", "[", string(b) + "{}", `[{"unexpected":true}]`} {
		if _, err = LoadSampleAddressPool("fixtures", strings.NewReader(s)); err == nil {
			t.Fatal("invalid data accepted")
		}
	}
	bad := sampleRows()
	bad[0].PostalCode = ""
	if _, err = NewSampleAddressPool("fixtures", bad); err == nil {
		t.Fatal("incomplete record accepted")
	}
	if _, err = NewSampleAddressPool("", sampleRows()); err == nil {
		t.Fatal("missing provenance accepted")
	}
	if _, err = LoadSampleAddressPool("fixtures", strings.NewReader(strings.Repeat(" ", MaxSampleAddressPoolBytes+1))); err == nil {
		t.Fatal("oversized pool accepted")
	}
}
func TestSamplePoolConcurrentCancellation(t *testing.T) {
	p, _ := NewSampleAddressPool("fixtures", sampleRows())
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				r, err := p.Resolve(context.Background(), BillingAddressQuery{})
				if err != nil || !r.Sample {
					t.Error("invalid concurrent result")
				}
			}
		}()
	}
	wg.Wait()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.Resolve(ctx, BillingAddressQuery{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	var empty *SampleAddressPool
	if empty.Len() != 0 {
		t.Fatal("nil len")
	}
	if _, err := empty.Resolve(context.Background(), BillingAddressQuery{}); !errors.Is(err, ErrEmptyAddressPool) {
		t.Fatal(err)
	}
}
