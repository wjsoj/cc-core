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
	// Failed: the customer received an error. A shed that could not be
	// retried — because output had already started — lands here too.
	Failed int64
	// Canceled: the client hung up (499). Not a fault of the service, and
	// counted separately so it cannot flatter or damn the failure rate.
	Canceled int64

	AvgMs int64
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
	// request; counting them would report the retry storm rather than what the
	// customer asked for. idx_req_ts covers (ts DESC) for exactly these rows.
	const q = `
SELECT provider,
       model,
       COUNT(*)                                                   AS requests,
       SUM(CASE WHEN error IN (?, ?) THEN 1 ELSE 0 END)           AS shed,
       SUM(CASE WHEN status >= 400 AND status <> 499 THEN 1 ELSE 0 END) AS failed,
       SUM(CASE WHEN status = 499 THEN 1 ELSE 0 END)              AS canceled,
       CAST(COALESCE(AVG(duration_ms), 0) AS INTEGER)             AS avg_ms,
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
			&m.Canceled, &m.AvgMs, &m.SlowRequests); err != nil {
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
