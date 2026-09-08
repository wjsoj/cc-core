package requestlog

import (
	"database/sql"
	"fmt"
	"sort"
	"time"
)

// Real-traffic reliability, for a status page that tells the truth.
//
// The existing health surface is a PROBE: it sends a synthetic request per
// (credential, model) and reports whether that came back. It cannot see what
// this measures, for two reasons. It probes one model per provider, so a model
// the probe does not exercise is invisible however badly it is behaving; and a
// capacity shed lands on a real turn under real load, which a single small
// probe rarely reproduces. Production had gpt-6-astra shedding 30.7% of turns
// while the probe reported the provider green, because the probe was aimed at
// gpt-5.6-sol, which was shedding 5.6%.
//
// So this reads the request log instead — what actually happened to customer
// traffic — and reports it per model.

// Shed labels. A turn upstream refused for capacity or quota arrives inside an
// otherwise-200 stream, so it is recorded as an error STRING rather than a
// status code. These constants are exported because the proxy writes them and
// this file matches on them: leaving the producer and the consumer to agree on
// a quoted string is how the two drift apart and the aggregate silently starts
// reporting zero sheds.
const (
	ShedCapacityLabel = "upstream shed the turn (capacity)"
	ShedQuotaLabel    = "upstream shed the turn (quota/rate)"
	// ShedPreOutputLabel tags a shed that arrived before any output and was
	// withheld from the client, so the turn could be re-run on another
	// credential. It is recorded on an attempt_only row — there is no
	// downstream request to attach it to, the customer's request went on to
	// succeed elsewhere — which is why it needs its own counter below rather
	// than joining the two labels above.
	ShedPreOutputLabel = "upstream shed the turn before any output"
)

// ModelReliability is what real traffic did for one (provider, model) over a
// window. Counts are of downstream REQUESTS — one per thing a customer asked
// for — not of upstream attempts, so a turn that was shed and then succeeded on
// another credential counts once, as a success, with Shed incremented. That
// split is the point: Shed measures what upstream is doing to us, Failed
// measures what the customer actually suffered, and the gap between them is the
// failover doing its job.
type ModelReliability struct {
	Provider string
	Model    string

	Requests int64
	// Shed: upstream refused the turn for capacity or quota at least once.
	// Includes turns that were then served successfully elsewhere.
	Shed int64
	// ShedAttempts counts withheld pre-output sheds — upstream attempts that
	// were refused and silently re-run on another credential. It is a count of
	// ATTEMPTS, not requests: one request shed three times contributes three,
	// which is why it is not folded into Shed.
	//
	// This is the number the failover hides. In a 16-hour production window it
	// was 3315 while Shed, which can only see sheds that survived to the
	// customer, was two orders of magnitude lower — the whole cost of the
	// condition was showing up as latency and nowhere else.
	ShedAttempts int64
	// Failed: the customer received an error. A shed that could not be
	// retried — because output had already started — lands here too.
	Failed int64
	// Canceled: the client hung up (499). Not a fault of the service, and
	// counted separately so it cannot flatter or damn the failure rate.
	Canceled int64

	AvgMs int64
	// AvgTTFBMs is how long upstream took to start producing, averaged over the
	// requests that reported it. AvgMs cannot stand in for it: a turn's total is
	// dominated by how many tokens it generated, so a model that answers at half
	// speed and a model that sits in a queue for ten seconds look the same in it.
	// Zero when no request in the window carried a measurement.
	AvgTTFBMs int64
	// SlowRequests: completed, but took longer than SlowThreshold. Retries
	// after a shed are the usual cause, and they are invisible in a failure
	// rate that only counts outright errors.
	SlowRequests int64
}

// SlowThreshold is what counts as slow for ModelReliability.SlowRequests.
// A Codex turn routinely runs 20-30s, so this is set well above ordinary and
// picks out the ones a user would describe as hung.
const SlowThreshold = 60 * time.Second

// ShedRate returns the fraction of requests upstream shed at least once, in
// [0,1]. Zero requests reports 0 rather than dividing by zero.
func (m ModelReliability) ShedRate() float64 {
	if m.Requests == 0 {
		return 0
	}
	return float64(m.Shed) / float64(m.Requests)
}

// FailureRate returns the fraction of requests the customer saw fail, in [0,1].
// Client cancellations are excluded from BOTH sides: a user pressing Ctrl-C is
// not a failure, and leaving them in the denominator would quietly deflate the
// rate whenever people give up more often — which is exactly when the service
// is worst.
func (m ModelReliability) FailureRate() float64 {
	served := m.Requests - m.Canceled
	if served <= 0 {
		return 0
	}
	return float64(m.Failed) / float64(served)
}

// ModelReliabilitySince summarises traffic recorded at or after `since`.
//
// It reads the SQLite index directly. The JSONL scanner is deliberately not a
// fallback here: this runs behind a public page that anyone can refresh, and
// re-parsing the archive per view is what made the usage pages slow enough to
// be a documented incident. A deployment with no index gets no reliability
// section rather than a scan.
func ModelReliabilitySince(dir string, since time.Time, minRequests int64) ([]ModelReliability, error) {
	store, err := OpenStoreForRead(dir)
	if err != nil {
		return nil, err
	}
	defer store.Close()
	return store.ModelReliabilitySince(since, minRequests)
}

// ModelReliabilitySince is the Store-bound form, for callers that already hold
// the index open and should not pay to reopen it per request.
func (s *Store) ModelReliabilitySince(since time.Time, minRequests int64) ([]ModelReliability, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("requestlog: no index open")
	}
	if minRequests < 0 {
		minRequests = 0
	}

	// attempt_only rows are per-credential attempts behind one downstream
	// request; counting them as requests would report the retry storm rather
	// than what the customer asked for. They are read separately below, into
	// their own counter. idx_req_ts covers (ts DESC) for exactly these rows —
	// it is PARTIAL on attempt_only = 0, so this predicate is load-bearing and
	// must not be relaxed to pull both kinds of row in one pass.
	const q = `
SELECT provider,
       model,
       COUNT(*)                                                   AS requests,
       SUM(CASE WHEN error IN (?, ?) THEN 1 ELSE 0 END)           AS shed,
       SUM(CASE WHEN status >= 400 AND status <> 499 THEN 1 ELSE 0 END) AS failed,
       SUM(CASE WHEN status = 499 THEN 1 ELSE 0 END)              AS canceled,
       CAST(COALESCE(AVG(duration_ms), 0) AS INTEGER)             AS avg_ms,
       CAST(COALESCE(AVG(NULLIF(ttfb_ms, 0)), 0) AS INTEGER)      AS avg_ttfb_ms,
       SUM(CASE WHEN duration_ms > ? THEN 1 ELSE 0 END)           AS slow
FROM req
WHERE attempt_only = 0 AND ts >= ?
GROUP BY provider, model
HAVING requests >= ?
ORDER BY requests DESC`

	rows, err := s.db.Query(q,
		ShedCapacityLabel, ShedQuotaLabel,
		SlowThreshold.Milliseconds(),
		since.UnixNano(),
		minRequests,
	)
	if err != nil {
		return nil, fmt.Errorf("requestlog: model reliability: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]ModelReliability, 0, 16)
	for rows.Next() {
		var m ModelReliability
		var provider, model sql.NullString
		if err := rows.Scan(&provider, &model, &m.Requests, &m.Shed, &m.Failed,
			&m.Canceled, &m.AvgMs, &m.AvgTTFBMs, &m.SlowRequests); err != nil {
			return nil, err
		}
		m.Provider, m.Model = provider.String, model.String
		if m.Model == "" {
			// A row with no model name tells a reader nothing and would render
			// as a blank line on the page.
			continue
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if err := s.foldShedAttempts(out, since); err != nil {
		return nil, err
	}

	// Worst first: a status page is read to find out what is wrong, and burying
	// the 30%-shed model under six healthy ones defeats the purpose. Ties break
	// on volume so the model more people are hitting leads.
	sort.SliceStable(out, func(i, j int) bool {
		si, sj := out[i].ShedRate(), out[j].ShedRate()
		if si != sj {
			return si > sj
		}
		fi, fj := out[i].FailureRate(), out[j].FailureRate()
		if fi != fj {
			return fi > fj
		}
		return out[i].Requests > out[j].Requests
	})
	return out, nil
}

// ShedBucket is the real-traffic quality of one time slot, for a status page
// that wants to say "requests were unstable around then".
//
// This is deliberately separate from ModelReliability: that answers "which
// model is bad", this answers "when was it bad", and a status strip needs the
// second. It is also separate from the health PROBE the strip is otherwise
// built from — a probe says whether a synthetic request succeeded, which stays
// green through a capacity shed that made every real turn retry.
type ShedBucket struct {
	// Start is the bucket's opening instant, aligned to the bucket width.
	Start time.Time
	// Requests counts downstream requests, excluding client cancellations:
	// a user pressing Ctrl-C is not instability, and leaving them in would
	// dilute the rate exactly when people are giving up most.
	Requests int64
	// Shed counts requests upstream refused at least once for capacity or
	// quota, including those a retry then served successfully. That is the
	// point — the customer waited through the retry either way.
	//
	// It can only see sheds that reached the terminal row, i.e. ones that
	// arrived after output had started. The far more common kind is withheld
	// before the client sees anything and re-run elsewhere, and that lands in
	// ShedAttempts.
	Shed int64
	// ShedAttempts counts withheld pre-output sheds in the bucket — upstream
	// attempts refused and silently retried on another credential.
	//
	// ATTEMPTS, not requests: one request shed three times contributes three,
	// so this can exceed Requests. It is not folded into Shed for exactly that
	// reason. Without it the strip was blind to the condition it exists to
	// show — a production window with 3315 withheld sheds carried a Shed count
	// two orders of magnitude smaller, so every slot rendered healthy.
	ShedAttempts int64
}

// Rate returns Shed/Requests in [0,1]; an empty bucket reports 0.
//
// This is the rate of sheds the CUSTOMER SAW. For how much upstream refusal the
// slot actually absorbed, see Severity.
func (b ShedBucket) Rate() float64 {
	if b.Requests == 0 {
		return 0
	}
	return float64(b.Shed) / float64(b.Requests)
}

// Severity is shed activity per request, counting the withheld retries the
// failover hides: (Shed + ShedAttempts) / Requests.
//
// It is an index, not a probability, and deliberately NOT clamped to 1 — a slot
// where every request had to be retried twice should read as worse than one
// where every request was retried once, and clamping would erase exactly that
// difference at the moment it matters. Callers rendering it as a percentage are
// the ones that should clamp.
func (b ShedBucket) Severity() float64 {
	if b.Requests == 0 {
		return 0
	}
	return float64(b.Shed+b.ShedAttempts) / float64(b.Requests)
}

// ShedBucketsSince buckets shed activity for one provider from `since` to now.
//
// Empty buckets are omitted rather than returned as zeros: the caller is
// overlaying this onto a strip it already built, and "no traffic" must stay
// distinguishable from "traffic, none shed" — the first should leave the strip
// alone, the second should mark it healthy.
func (s *Store) ShedBucketsSince(provider string, since time.Time, bucket time.Duration) ([]ShedBucket, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("requestlog: no index open")
	}
	if bucket <= 0 {
		return nil, fmt.Errorf("requestlog: bucket must be positive")
	}
	width := bucket.Nanoseconds()

	const q = `
SELECT (ts / ?) * ?                                              AS bucket_ns,
       COUNT(*)                                                  AS requests,
       SUM(CASE WHEN error IN (?, ?) THEN 1 ELSE 0 END)          AS shed
FROM req
WHERE attempt_only = 0 AND ts >= ? AND provider = ? AND status <> 499
GROUP BY bucket_ns
ORDER BY bucket_ns`

	rows, err := s.db.Query(q, width, width, ShedCapacityLabel, ShedQuotaLabel,
		since.UnixNano(), provider)
	if err != nil {
		return nil, fmt.Errorf("requestlog: shed buckets: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]ShedBucket, 0, 160)
	byStart := make(map[int64]int, 160)
	for rows.Next() {
		var startNS int64
		var b ShedBucket
		if err := rows.Scan(&startNS, &b.Requests, &b.Shed); err != nil {
			return nil, err
		}
		b.Start = time.Unix(0, startNS)
		byStart[startNS] = len(out)
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := s.foldShedAttemptBuckets(out, byStart, provider, since, width); err != nil {
		return nil, err
	}
	return out, nil
}

// foldShedAttemptBuckets adds the withheld pre-output sheds to buckets the
// customer-facing pass already created.
//
// A second query for the same reason as foldShedAttempts: the ts indexes on req
// are partial on attempt_only = 0, so one pass over both kinds of row would
// match no index at all.
//
// Attempt rows land only in buckets that already exist. A bucket built purely
// from attempts has no request count, so its severity would divide by zero, and
// the strip's contract is that a slot with no traffic stays untouched rather
// than being drawn as an incident.
func (s *Store) foldShedAttemptBuckets(out []ShedBucket, byStart map[int64]int, provider string, since time.Time, width int64) error {
	if len(out) == 0 {
		return nil
	}
	const q = `
SELECT (ts / ?) * ? AS bucket_ns, COUNT(*)
FROM req
WHERE attempt_only = 1 AND ts >= ? AND provider = ? AND error = ?
GROUP BY bucket_ns`

	rows, err := s.db.Query(q, width, width, since.UnixNano(), provider, ShedPreOutputLabel)
	if err != nil {
		return fmt.Errorf("requestlog: shed attempt buckets: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var startNS, n int64
		if err := rows.Scan(&startNS, &n); err != nil {
			return err
		}
		if i, ok := byStart[startNS]; ok {
			out[i].ShedAttempts = n
		}
	}
	return rows.Err()
}

// foldShedAttempts adds the withheld pre-output sheds onto the rows already
// built from customer requests.
//
// It is a second query rather than a wider first one because every ts index on
// req is PARTIAL on attempt_only = 0. A single pass over both kinds of row
// would match none of them and scan an archive measured in hundreds of
// megabytes; idx_req_attempt_ts is the mirror index that makes this half a
// range seek of its own.
//
// Models that only appear as shed attempts are dropped rather than added: a
// (provider, model) with no completed request in the window has no denominator,
// and a status page listing a model nobody successfully used says nothing a
// reader can act on.
func (s *Store) foldShedAttempts(out []ModelReliability, since time.Time) error {
	if len(out) == 0 {
		return nil
	}
	const q = `
SELECT provider, model, COUNT(*)
FROM req
WHERE attempt_only = 1 AND ts >= ? AND error = ?
GROUP BY provider, model`

	rows, err := s.db.Query(q, since.UnixNano(), ShedPreOutputLabel)
	if err != nil {
		return fmt.Errorf("requestlog: shed attempts: %w", err)
	}
	defer func() { _ = rows.Close() }()

	counts := make(map[string]int64, len(out))
	for rows.Next() {
		var provider, model sql.NullString
		var n int64
		if err := rows.Scan(&provider, &model, &n); err != nil {
			return err
		}
		counts[provider.String+"\x00"+model.String] = n
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for i := range out {
		out[i].ShedAttempts = counts[out[i].Provider+"\x00"+out[i].Model]
	}
	return nil
}
