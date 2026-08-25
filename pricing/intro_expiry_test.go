package pricing

import (
	"testing"
	"time"
)

// introductoryRates are catalog cards that are knowingly below list price for a
// limited window. A promo that outlives its window silently under-bills every
// request that hits it — there is no error, no log line, just less money — so
// each one gets a deadline here and this test turns that deadline into a build
// failure the day it lapses.
//
// When a test below starts failing: replace the card's four values with the
// listed rates, delete the ⚠️ notice next to the card, and drop the entry here.
var introductoryRates = []struct {
	provider string
	model    string
	// expires is the first day the promotional rate no longer applies.
	expires time.Time
	// list is what the card must become on that day.
	list ModelPrice
}{
	{
		provider: ProviderAnthropic,
		model:    "claude-sonnet-5",
		expires:  time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
		list: ModelPrice{
			InputPer1M:       3.00,
			OutputPer1M:      15.00,
			CacheReadPer1M:   0.30,
			CacheCreatePer1M: 3.75,
		},
	},
}

func TestIntroductoryRatesHaveNotLapsed(t *testing.T) {
	cat := NewCatalog(Config{})
	for _, ir := range introductoryRates {
		if time.Now().UTC().Before(ir.expires) {
			continue
		}
		got := cat.Lookup(ir.provider, ir.model)
		if got != ir.list {
			t.Errorf("%s/%s: the introductory rate expired on %s but the catalog still bills %+v; "+
				"update the card to the list price %+v and remove it from introductoryRates",
				ir.provider, ir.model, ir.expires.Format("2006-01-02"), got, ir.list)
		}
	}
}

// The promo card must never sit *above* list price either: that would overcharge
// while the promotion is supposedly running.
func TestIntroductoryRatesAreBelowList(t *testing.T) {
	cat := NewCatalog(Config{})
	for _, ir := range introductoryRates {
		if !time.Now().UTC().Before(ir.expires) {
			continue
		}
		got := cat.Lookup(ir.provider, ir.model)
		if got.InputPer1M > ir.list.InputPer1M || got.OutputPer1M > ir.list.OutputPer1M ||
			got.CacheReadPer1M > ir.list.CacheReadPer1M || got.CacheCreatePer1M > ir.list.CacheCreatePer1M {
			t.Errorf("%s/%s: %+v is not below the list price %+v", ir.provider, ir.model, got, ir.list)
		}
	}
}
