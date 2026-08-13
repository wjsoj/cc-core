package auth

import "testing"

// A disabled credential must never be reported as a pool's worst state while a
// real fault is present. Severity answers "what is the worst thing happening
// here", and an operator switching a channel off is not a thing going wrong.
//
// This shipped inverted: disabled ranked above hard_failed, so a production
// pool of {3 healthy, 3 hard_failed, 2 disabled} published worst_state
// "disabled" and the three retired credentials never reached the headline.
// The string surfaces in the 503 body of an exhausted pool and in the
// monitor's per-provider error line, so the wrong answer lands exactly where
// an operator is trying to find out what broke.
func TestPoolWorstPrefersFaultOverDisabled(t *testing.T) {
	cases := []struct {
		name    string
		reports []HealthReport
		want    HealthState
	}{
		{
			name: "hard_failed outranks disabled",
			reports: []HealthReport{
				{State: HealthHealthy, Serving: true},
				{State: HealthHealthy, Serving: true},
				{State: HealthHealthy, Serving: true},
				{State: HealthHardFailed},
				{State: HealthHardFailed},
				{State: HealthHardFailed},
				{State: HealthDisabled},
				{State: HealthDisabled},
			},
			want: HealthHardFailed,
		},
		{
			// Every fault state, not just the sticky one, has to win.
			name: "half_open outranks disabled",
			reports: []HealthReport{
				{State: HealthDisabled},
				{State: HealthHalfOpen, Serving: true},
			},
			want: HealthHalfOpen,
		},
		{
			name: "degraded outranks disabled",
			reports: []HealthReport{
				{State: HealthDisabled},
				{State: HealthDegraded, Serving: true},
			},
			want: HealthDegraded,
		},
		{
			name: "quota outranks disabled",
			reports: []HealthReport{
				{State: HealthDisabled},
				{State: HealthQuota},
			},
			want: HealthQuota,
		},
		{
			name: "cooling outranks disabled",
			reports: []HealthReport{
				{State: HealthDisabled},
				{State: HealthCooling},
			},
			want: HealthCooling,
		},
		{
			// But disabled still has to beat healthy: a pool with one channel
			// switched off is not reported as problem-free.
			name: "disabled outranks healthy",
			reports: []HealthReport{
				{State: HealthHealthy, Serving: true},
				{State: HealthDisabled},
			},
			want: HealthDisabled,
		},
		{
			name:    "empty pool is healthy",
			reports: nil,
			want:    HealthHealthy,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := NewPoolHealth("anthropic", tc.reports)
			if got.Worst != tc.want {
				t.Errorf("Worst = %q, want %q (by_state=%v)", got.Worst, tc.want, got.ByState)
			}
		})
	}
}

// The ladder must stay a strict order with healthy at the bottom, or `Worst`
// silently picks whichever state happened to be scanned first among ties.
func TestSeverityIsStrictlyOrdered(t *testing.T) {
	ascending := []HealthState{
		HealthHealthy,
		HealthDisabled,
		HealthHalfOpen,
		HealthDegraded,
		HealthQuota,
		HealthCooling,
		HealthHardFailed,
	}
	for i := 1; i < len(ascending); i++ {
		prev, cur := ascending[i-1], ascending[i]
		if cur.Severity() <= prev.Severity() {
			t.Errorf("Severity(%s)=%d must exceed Severity(%s)=%d",
				cur, cur.Severity(), prev, prev.Severity())
		}
	}
	if HealthHealthy.Severity() != 0 {
		t.Errorf("Severity(healthy) = %d, want 0", HealthHealthy.Severity())
	}
	// An unknown state falls through to 0, which must not outrank a real fault.
	if HealthState("nonsense").Severity() != 0 {
		t.Errorf("Severity(unknown) = %d, want 0", HealthState("nonsense").Severity())
	}
}
