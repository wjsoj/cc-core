package requestlog

import (
	"strings"
	"testing"
	"time"
)

// shedTelemetryRecords is one model's traffic over a window: three completed
// customer requests, one of which the customer saw shed, plus five withheld
// pre-output shed attempts behind them. The 5-against-1 shape is the point —
// production's withheld sheds outnumbered the visible ones by two orders of
// magnitude, and an aggregate that reports only the visible ones calls that
// window healthy.
func shedTelemetryRecords(base time.Time) []Record {
	rec := func(off time.Duration, ttfb int64, errStr string, attemptOnly bool) Record {
		return Record{
			TS: base.Add(off), Provider: "openai", Model: "gpt-5.6-sol",
			ClientToken: "tok", AuthID: "cred-a", AuthKind: "oauth",
			Status: 200, DurationMs: 30000, TTFBMs: ttfb,
			Error: errStr, AttemptOnly: attemptOnly,
		}
	}
	out := []Record{
		rec(1*time.Second, 9000, "", false),
		rec(2*time.Second, 11000, "", false),
		rec(3*time.Second, 0, ShedCapacityLabel, false),
	}
	for i := 0; i < 5; i++ {
		out = append(out, rec(time.Duration(10+i)*time.Second, 0, ShedPreOutputLabel, true))
	}
	return out
}

func TestModelReliabilityCountsWithheldSheds(t *testing.T) {
	withShanghaiBuckets(t)
	dir := t.TempDir()
	base := time.Now().Add(-time.Hour).UTC()
	writeLog(t, dir, shedTelemetryRecords(base))

	st := openReadyStore(t, dir)
	got, err := st.ModelReliabilitySince(base.Add(-time.Minute), 0)
	if err != nil {
		t.Fatalf("ModelReliabilitySince: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d rows, want 1: %+v", len(got), got)
	}
	m := got[0]
	// Attempt rows must not become requests: the customer asked three times.
	if m.Requests != 3 {
		t.Errorf("Requests = %d, want 3 (attempt rows must not inflate the count)", m.Requests)
	}
	if m.Shed != 1 {
		t.Errorf("Shed = %d, want 1 (only the shed the customer saw)", m.Shed)
	}
	if m.ShedAttempts != 5 {
		t.Errorf("ShedAttempts = %d, want 5; the withheld sheds are invisible again", m.ShedAttempts)
	}
	// Average over the rows that reported one — the shed row carries no
	// measurement and must not drag the mean toward zero.
	if m.AvgTTFBMs != 10000 {
		t.Errorf("AvgTTFBMs = %d, want 10000 (mean of 9000 and 11000, unmeasured rows excluded)", m.AvgTTFBMs)
	}
}

// TestShedAttemptQueryUsesItsIndex is the guard the wallet_tx incident earned:
// a predicate that misses a partial index turns a bounded seek into a scan of
// the whole archive, and nothing in a functional test notices. Assert the plan,
// not just the answer.
func TestShedAttemptQueryUsesItsIndex(t *testing.T) {
	withShanghaiBuckets(t)
	dir := t.TempDir()
	base := time.Now().Add(-time.Hour).UTC()
	writeLog(t, dir, shedTelemetryRecords(base))
	st := openReadyStore(t, dir)

	rows, err := st.db.Query(`EXPLAIN QUERY PLAN
SELECT provider, model, COUNT(*)
FROM req
WHERE attempt_only = 1 AND ts >= ? AND error = ?
GROUP BY provider, model`, base.UnixNano(), ShedPreOutputLabel)
	if err != nil {
		t.Fatalf("explain: %v", err)
	}
	defer rows.Close()
	var plan strings.Builder
	for rows.Next() {
		var id, parent, notused int
		var detail string
		if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
			t.Fatalf("scan plan: %v", err)
		}
		plan.WriteString(detail)
		plan.WriteString("\n")
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("plan rows: %v", err)
	}
	if !strings.Contains(plan.String(), "idx_req_attempt_ts") {
		t.Fatalf("shed-attempt query does not use idx_req_attempt_ts; it would scan the whole archive.\nplan:\n%s", plan.String())
	}
}

// TestTTFBSurvivesTheArchive: the field has to make it through JSONL, the
// ingest insert and the read-back, or the column is decoration.
func TestTTFBSurvivesTheArchive(t *testing.T) {
	withShanghaiBuckets(t)
	dir := t.TempDir()
	base := time.Now().Add(-time.Hour).UTC()
	writeLog(t, dir, []Record{{
		TS: base, Provider: "openai", Model: "gpt-5.6-sol", ClientToken: "tok",
		AuthID: "cred-a", AuthKind: "oauth", Status: 200,
		DurationMs: 31000, TTFBMs: 10500,
	}})
	st := openReadyStore(t, dir)
	res, err := st.storeQuery(Filter{Dir: dir, Limit: 10})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(res.Entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(res.Entries))
	}
	if res.Entries[0].TTFBMs != 10500 {
		t.Errorf("TTFBMs = %d, want 10500", res.Entries[0].TTFBMs)
	}
}

// TestShedBucketsCountWithheldSheds is the status-strip half of the same gap:
// the amber overlay reads these buckets, and while Shed could only see sheds
// that survived to the customer, a window where a quarter of all turns were
// being retried rendered entirely green.
func TestShedBucketsCountWithheldSheds(t *testing.T) {
	withShanghaiBuckets(t)
	dir := t.TempDir()
	base := time.Now().Add(-time.Hour).UTC().Truncate(time.Minute)
	writeLog(t, dir, shedTelemetryRecords(base))

	st := openReadyStore(t, dir)
	got, err := st.ShedBucketsSince("openai", base.Add(-time.Minute), time.Hour)
	if err != nil {
		t.Fatalf("ShedBucketsSince: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d buckets, want 1: %+v", len(got), got)
	}
	b := got[0]
	if b.Requests != 3 {
		t.Errorf("Requests = %d, want 3", b.Requests)
	}
	if b.Shed != 1 {
		t.Errorf("Shed = %d, want 1", b.Shed)
	}
	if b.ShedAttempts != 5 {
		t.Errorf("ShedAttempts = %d, want 5; the strip is blind again", b.ShedAttempts)
	}
	// Severity counts attempts, so it is allowed past 1 — a slot that had to
	// retry every request twice is worse than one that retried each once, and
	// clamping here would flatten the two together.
	if want := 2.0; b.Severity() != want {
		t.Errorf("Severity = %v, want %v", b.Severity(), want)
	}
	if b.Rate() != 1.0/3.0 {
		t.Errorf("Rate = %v, want 1/3 (unchanged: what the customer saw)", b.Rate())
	}
}

// A bucket that holds nothing but attempt rows has no denominator. Reporting it
// would divide by zero and, worse, draw an incident on a slot where the strip's
// contract says no traffic means no verdict.
func TestShedBucketsIgnoreAttemptOnlyBuckets(t *testing.T) {
	withShanghaiBuckets(t)
	dir := t.TempDir()
	base := time.Now().Add(-time.Hour).UTC().Truncate(time.Minute)
	recs := []Record{{
		TS: base, Provider: "openai", Model: "gpt-5.6-sol", ClientToken: "tok",
		AuthID: "cred-a", AuthKind: "oauth", Status: 200, DurationMs: 1000,
		Error: ShedPreOutputLabel, AttemptOnly: true,
	}}
	writeLog(t, dir, recs)
	st := openReadyStore(t, dir)
	got, err := st.ShedBucketsSince("openai", base.Add(-time.Minute), time.Hour)
	if err != nil {
		t.Fatalf("ShedBucketsSince: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d buckets from attempt rows alone, want 0: %+v", len(got), got)
	}
}
