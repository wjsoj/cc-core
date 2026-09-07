package requestlog

import (
	"testing"
	"time"
)

func TestShedBucketRate(t *testing.T) {
	for _, tc := range []struct {
		b    ShedBucket
		want float64
	}{
		{ShedBucket{}, 0},                        // empty must not divide by zero
		{ShedBucket{Requests: 10, Shed: 0}, 0},   // traffic, all clean
		{ShedBucket{Requests: 10, Shed: 3}, 0.3}, //
		{ShedBucket{Requests: 4, Shed: 4}, 1},    //
	} {
		if got := tc.b.Rate(); got != tc.want {
			t.Errorf("%+v Rate() = %v, want %v", tc.b, got, tc.want)
		}
	}
}

func TestModelReliabilityRates(t *testing.T) {
	m := ModelReliability{Requests: 100, Shed: 25, Failed: 4, Canceled: 20}
	if got := m.ShedRate(); got != 0.25 {
		t.Errorf("ShedRate = %v, want 0.25", got)
	}
	// Cancellations leave BOTH sides of the failure rate: 4 failures out of the
	// 80 requests that were actually served, not out of 100. Counting them in
	// the denominator would quietly deflate the rate exactly when users give up
	// most, which is when the service is worst.
	if got := m.FailureRate(); got != 0.05 {
		t.Errorf("FailureRate = %v, want 0.05 (4/80, cancellations excluded)", got)
	}
	empty := ModelReliability{}
	if empty.ShedRate() != 0 || empty.FailureRate() != 0 {
		t.Error("an empty summary must report zero rather than divide by zero")
	}
	allCanceled := ModelReliability{Requests: 5, Canceled: 5}
	if got := allCanceled.FailureRate(); got != 0 {
		t.Errorf("FailureRate = %v with nothing served, want 0", got)
	}
}

func TestShedBucketsRejectsBadInput(t *testing.T) {
	var s *Store
	if _, err := s.ShedBucketsSince("openai", time.Now(), time.Minute); err == nil {
		t.Error("a nil store must report an error rather than panic")
	}
	if _, err := (&Store{}).ShedBucketsSince("openai", time.Now(), 0); err == nil {
		t.Error("a non-positive bucket width must be rejected")
	}
}
