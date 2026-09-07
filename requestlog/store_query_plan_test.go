package requestlog

import (
	"strings"
	"testing"
	"time"
)

// A bounded AggregateByAuth must seek the timestamp range, not walk the table.
//
// Left to itself the planner reaches for idx_req_auth — it is (auth_id, ts) and
// so answers the GROUP BY without a sort — but it cannot seek the ts range
// inside each group, so it reads every row. On production that was 1.76s cold
// for a 24h window over a 90-day table, paid by whoever opened the admin
// credentials page after the aggregate's cache had gone stale.
//
// The query pins idx_req_ts with INDEXED BY, which makes this test a schema
// guard as much as a plan guard: drop or rename that index and the statement
// stops preparing at all.
func TestAggregateByAuthSeeksTheTimeRange(t *testing.T) {
	st, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer st.Close()

	where, args := timeWhere(time.Now().Add(-24*time.Hour), time.Time{})
	plan := explainPlan(t, st, `SELECT auth_id, `+aggSelect+`
		FROM req INDEXED BY idx_req_ts
		WHERE attempt_only = 0 AND auth_id != ''`+where+`
		GROUP BY auth_id`, args...)

	if !strings.Contains(plan, "idx_req_ts") {
		t.Errorf("bounded aggregate did not use idx_req_ts:\n%s", plan)
	}
	if strings.Contains(plan, "SCAN req") {
		t.Errorf("bounded aggregate still scans the whole table:\n%s", plan)
	}
}
