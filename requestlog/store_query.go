package requestlog

// SQL implementations of the three query entry points.
//
// Every function here must return exactly what the equivalent JSONL scan in
// query.go returns — store_test.go asserts that field by field. Two rules
// carry most of that weight:
//
//   - attempt_only rows are invisible everywhere (matches() rejects them
//     first, and both aggregate helpers skip them), so every WHERE below
//     starts from attempt_only = 0.
//   - the day column holds the *source file's* day, which is what the
//     scanning path prunes on before applying exact timestamp bounds. Range
//     predicates therefore constrain both, mirroring that two-step filter.

import (
	"database/sql"
	"encoding/json"
	"strings"
	"time"
)

// storeAggregateByAuth serves AggregateByAuth. The unbounded case — the
// lifetime totals the admin summary polls — reads the pre-summed agg_cube,
// turning what was a full-archive parse into a scan of a few thousand rows.
// Bounded windows go to req, where idx_req_ts keeps a 24h slice cheap.
func (s *Store) storeAggregateByAuth(from, to time.Time) (map[string]Aggregate, error) {
	s.maybeCatchUp()
	out := make(map[string]Aggregate)

	var rows *sql.Rows
	var err error
	if from.IsZero() && to.IsZero() {
		rows, err = s.db.Query(`SELECT auth_id, ` + rollupSelect + `
			FROM agg_cube WHERE auth_id != '' GROUP BY auth_id`)
	} else {
		where, args := timeWhere(from, to)
		rows, err = s.db.Query(`SELECT auth_id, `+aggSelect+`
			FROM req WHERE attempt_only = 0 AND auth_id != ''`+where+`
			GROUP BY auth_id`, args...)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var key string
		var a Aggregate
		if err := scanAggregate(rows, &key, &a); err != nil {
			return nil, err
		}
		out[key] = a
	}
	return out, rows.Err()
}

// storeAggregateHourly serves AggregateHourly. Note it sums cost_usd rather
// than the billed fallback and omits the 1h-cache and duration axes — the
// scanning version does the same, and the chart only reads these fields.
func (s *Store) storeAggregateHourly(hours int) ([]HourBucket, error) {
	s.maybeCatchUp()

	now := time.Now().UTC().Truncate(time.Hour)
	start := now.Add(-time.Duration(hours-1) * time.Hour)
	buckets := make([]HourBucket, hours)
	for i := range buckets {
		buckets[i].Hour = start.Add(time.Duration(i) * time.Hour).In(bucketLoc)
	}

	// Integer division on the nanosecond timestamp yields the bucket index
	// directly; ts >= start keeps it non-negative.
	const hourNS = int64(time.Hour)
	rows, err := s.db.Query(`SELECT (ts / ?) - ?,
			COUNT(*), COALESCE(SUM(input),0), COALESCE(SUM(output),0),
			COALESCE(SUM(cache_read),0), COALESCE(SUM(cache_create),0),
			COALESCE(SUM(cost_usd),0),
			COALESCE(SUM(CASE WHEN status >= 400 OR error != '' THEN 1 ELSE 0 END),0)
		FROM req
		WHERE attempt_only = 0
		  AND day >= ? AND day <= ?
		  AND ts >= ? AND ts <= ?
		GROUP BY 1`,
		hourNS, start.UnixNano()/hourNS,
		start.Format("2006-01-02"), now.Format("2006-01-02"),
		start.UnixNano(), now.Add(time.Hour).UnixNano())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var idx int
		var b HourBucket
		if err := rows.Scan(&idx, &b.Count, &b.InputTokens, &b.OutputTokens,
			&b.CacheReadTokens, &b.CacheCreateTokens, &b.CostUSD, &b.Errors); err != nil {
			return nil, err
		}
		if idx < 0 || idx >= hours {
			continue
		}
		hour := buckets[idx].Hour
		b.Hour = hour
		buckets[idx] = b
	}
	return buckets, rows.Err()
}

// storeQuery serves Query.
func (s *Store) storeQuery(f Filter) (*Result, error) {
	s.maybeCatchUp()
	f = f.resolveDays()

	res := &Result{
		ByClient: make(map[string]Aggregate),
		ByModel:  make(map[string]Aggregate),
		ByDay:    make(map[string]Aggregate),
	}
	where, args := filterWhere(f)

	// Entries: newest-first page. id breaks ties so paging is stable across
	// records sharing a timestamp.
	entArgs := append(append([]any{}, args...), f.Limit, f.Offset)
	rows, err := s.db.Query(`SELECT ts, client, client_token, provider, auth_id, auth_label,
			auth_kind, model, input, output, cache_read, cache_create, cache_create_1h,
			cost_usd, billed_usd, multiplier, status, duration_ms, stream, path,
			attempts, error, user_id, audit
		FROM req WHERE `+where+`
		ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?`, entArgs...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		r, err := scanRecord(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		res.Entries = append(res.Entries, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if f.PageOnly {
		return res, nil
	}

	if cubeEligible(f) {
		if err := s.aggregatesFromCube(res, f); err != nil {
			return nil, err
		}
	} else {
		if err := s.aggregatesFromReq(res, where, args); err != nil {
			return nil, err
		}
	}
	res.Scanned = res.Summary.Count
	return res, nil
}

// cubeEligible reports whether the cube can answer this filter exactly.
//
// Every dimension the panel filters on is a cube column, so the only thing
// that can disqualify a query is a time bound: Filter compares exact
// timestamps while the cube's finest grain is a day. An unbounded query is
// therefore eligible, and so is one whose bounds are whole days — but only
// when the caller said so in days (FromDay/ToDay, which set dayBounds).
//
// We do not try to *infer* day alignment from a timestamp pair. Whether
// 2026-08-02T00:00:00+08:00 is a day boundary depends on the bucketing zone,
// so the inference would silently start answering from the wrong grain the
// day an operator changes it. Making the caller state the grain costs one
// field and cannot drift.
func cubeEligible(f Filter) bool {
	if f.dayBounds {
		return true
	}
	return f.From.IsZero() && f.To.IsZero()
}

// aggregatesFromCube answers Summary/ByClient/ByModel/ByDay from the pre-summed
// cube. The cube is small enough (~10k rows for a 90-day, 1M-record archive)
// that four groupings over it are microseconds, so unlike the req path there is
// nothing to gain from materializing it first.
func (s *Store) aggregatesFromCube(res *Result, f Filter) error {
	where, args := cubeWhere(f)
	for _, spec := range []struct {
		dim string
		dst map[string]Aggregate
	}{
		{`''`, nil},
		{`CASE WHEN client_token != '' THEN client_token ELSE client END`, res.ByClient},
		{`model`, res.ByModel},
		{`bday`, res.ByDay},
	} {
		rows, err := s.db.Query(`SELECT `+spec.dim+`, `+rollupSelect+`
			FROM agg_cube WHERE `+where+` GROUP BY `+spec.dim, args...)
		if err != nil {
			return err
		}
		for rows.Next() {
			var key string
			var a Aggregate
			if err := scanAggregate(rows, &key, &a); err != nil {
				rows.Close()
				return err
			}
			if spec.dst == nil {
				res.Summary = a
			} else {
				spec.dst[key] = a
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
	}
	return nil
}

// cubeWhere renders the non-time predicates of a Filter against cube columns.
// It mirrors filterWhere clause for clause — the same collations, the same
// legacy-provider fallback — minus attempt_only, which the cube excluded when
// it was built.
func cubeWhere(f Filter) (string, []any) {
	var sb strings.Builder
	var args []any
	sb.WriteString(`1 = 1`)

	if f.UserID != 0 {
		sb.WriteString(` AND user_id = ?`)
		args = append(args, f.UserID)
	}
	if f.ClientToken != "" {
		sb.WriteString(` AND client_token = ?`)
		args = append(args, f.ClientToken)
	} else if f.Client != "" {
		sb.WriteString(` AND client = ? COLLATE NOCASE`)
		args = append(args, f.Client)
	}
	if f.Model != "" {
		sb.WriteString(` AND model = ? COLLATE NOCASE`)
		args = append(args, f.Model)
	}
	if f.Provider != "" {
		sb.WriteString(` AND (CASE WHEN provider = '' THEN 'anthropic' ELSE provider END) = ? COLLATE NOCASE`)
		args = append(args, f.Provider)
	}
	if f.Status != 0 {
		sb.WriteString(` AND status = ?`)
		args = append(args, f.Status)
	}
	if f.AuthID != "" {
		sb.WriteString(` AND auth_id = ?`)
		args = append(args, f.AuthID)
	}
	// bday carries the same display-zone day label the caller named, so these
	// are an exact translation of the window rather than an approximation.
	// cubeEligible guarantees any window present here arrived as day labels.
	if f.FromDay != "" {
		sb.WriteString(` AND bday >= ?`)
		args = append(args, f.FromDay)
	}
	if f.ToDay != "" {
		sb.WriteString(` AND bday <= ?`)
		args = append(args, f.ToDay)
	}
	return sb.String(), args
}

// aggregatesFromReq computes the summary and all three groupings in a single
// pass over the filtered rows.
//
// The obvious shape — one grouped query per dimension — costs four passes,
// and a pass here is not cheap: the filter indexes cover the predicate but
// not the eleven counter columns, so every matching row is a separate lookup
// into the table. On production data a filter matching 116k rows took 0.54s
// per dimension, so the panel's model filter spent ~3.9s doing four times the
// same work. Materializing the filtered slice once and grouping it four ways
// costs 0.57s total.
//
// MATERIALIZED is explicit rather than left to the planner: SQLite may inline
// a CTE referenced more than once, which would silently restore the four
// passes this exists to avoid.
func (s *Store) aggregatesFromReq(res *Result, where string, args []any) error {
	q := `WITH m AS MATERIALIZED (
			SELECT client, client_token, model, bday, input, output,
			       cache_read, cache_create, cache_create_1h,
			       cost_usd, billed_usd, status, error, duration_ms
			FROM req WHERE ` + where + `
		)
		SELECT 'total' AS kind, '' AS dim, ` + aggSelect + ` FROM m
		UNION ALL
		SELECT 'client', CASE WHEN client_token != '' THEN client_token ELSE client END,
			` + aggSelect + ` FROM m GROUP BY 2
		UNION ALL
		SELECT 'model', model, ` + aggSelect + ` FROM m GROUP BY 2
		UNION ALL
		SELECT 'day', bday, ` + aggSelect + ` FROM m GROUP BY 2`

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var kind, key string
		var a Aggregate
		if err := rows.Scan(&kind, &key, &a.Count, &a.InputTokens, &a.OutputTokens,
			&a.CacheReadTokens, &a.CacheCreateTokens, &a.CacheCreate1hTokens,
			&a.CostUSD, &a.BilledUSD, &a.Errors, &a.TotalDurationMs); err != nil {
			return err
		}
		switch kind {
		case "total":
			// Ungrouped, so this row exists even when nothing matched — which
			// is what makes an empty result report a zero summary rather than
			// no summary at all.
			res.Summary = a
		case "client":
			res.ByClient[key] = a
		case "model":
			res.ByModel[key] = a
		case "day":
			res.ByDay[key] = a
		}
	}
	return rows.Err()
}

// rollupSelect re-aggregates pre-summed daily rows. It mirrors aggSelect's
// column order so both feed the same scanner.
const rollupSelect = `COALESCE(SUM(count),0), COALESCE(SUM(input),0), COALESCE(SUM(output),0),
	COALESCE(SUM(cache_read),0), COALESCE(SUM(cache_create),0), COALESCE(SUM(cache_create_1h),0),
	COALESCE(SUM(cost_usd),0), COALESCE(SUM(billed_usd),0),
	COALESCE(SUM(errors),0), COALESCE(SUM(duration_ms),0)`

type scannable interface{ Scan(dest ...any) error }

func scanAggregate(rows scannable, key *string, a *Aggregate) error {
	return rows.Scan(key, &a.Count, &a.InputTokens, &a.OutputTokens,
		&a.CacheReadTokens, &a.CacheCreateTokens, &a.CacheCreate1hTokens,
		&a.CostUSD, &a.BilledUSD, &a.Errors, &a.TotalDurationMs)
}

func scanRecord(rows scannable) (Record, error) {
	var r Record
	var ts int64
	var stream int
	var audit sql.NullString
	err := rows.Scan(&ts, &r.Client, &r.ClientToken, &r.Provider, &r.AuthID,
		&r.AuthLabel, &r.AuthKind, &r.Model, &r.Input, &r.Output, &r.CacheRead,
		&r.CacheCreate, &r.CacheCreate1h, &r.CostUSD, &r.BilledUSD, &r.Multiplier,
		&r.Status, &r.DurationMs, &stream, &r.Path, &r.Attempts, &r.Error,
		&r.UserID, &audit)
	if err != nil {
		return r, err
	}
	// Rendered in the display zone rather than the writer's original offset:
	// the instant is identical, and this is the zone every other panel value
	// is already labelled in.
	r.TS = time.Unix(0, ts).In(bucketLoc)
	r.Stream = stream != 0
	if audit.Valid && audit.String != "" {
		var ca ClaudeAudit
		if json.Unmarshal([]byte(audit.String), &ca) == nil {
			r.ClaudeAudit = &ca
		}
	}
	return r, nil
}

// timeWhere renders the day-then-timestamp bounds shared by the aggregate
// helpers. It returns a fragment that appends to an existing WHERE.
func timeWhere(from, to time.Time) (string, []any) {
	var sb strings.Builder
	var args []any
	if !from.IsZero() {
		sb.WriteString(` AND day >= ? AND ts >= ?`)
		args = append(args, from.UTC().Format("2006-01-02"), from.UnixNano())
	}
	if !to.IsZero() {
		sb.WriteString(` AND day <= ? AND ts <= ?`)
		args = append(args, to.UTC().Format("2006-01-02"), to.UnixNano())
	}
	return sb.String(), args
}

// filterWhere renders a Filter as a WHERE body (without the keyword).
//
// Model and Client use COLLATE NOCASE to mirror the scanning path's
// strings.EqualFold. That is ASCII-only folding where EqualFold is Unicode —
// model names and token labels are ASCII in every deployment, and the
// alternative (lower() on both sides) would defeat the indexes.
func filterWhere(f Filter) (string, []any) {
	var sb strings.Builder
	var args []any
	sb.WriteString(`attempt_only = 0`)

	if f.UserID != 0 {
		sb.WriteString(` AND user_id = ?`)
		args = append(args, f.UserID)
	}
	if f.ClientToken != "" {
		sb.WriteString(` AND client_token = ?`)
		args = append(args, f.ClientToken)
	} else if f.Client != "" {
		sb.WriteString(` AND client = ? COLLATE NOCASE`)
		args = append(args, f.Client)
	}
	if f.Model != "" {
		sb.WriteString(` AND model = ? COLLATE NOCASE`)
		args = append(args, f.Model)
	}
	if f.Provider != "" {
		// Records predating the provider field are treated as anthropic so
		// history stays reachable without a back-fill.
		sb.WriteString(` AND (CASE WHEN provider = '' THEN 'anthropic' ELSE provider END) = ? COLLATE NOCASE`)
		args = append(args, f.Provider)
	}
	if f.Status != 0 {
		sb.WriteString(` AND status = ?`)
		args = append(args, f.Status)
	}
	if f.AuthID != "" {
		sb.WriteString(` AND auth_id = ?`)
		args = append(args, f.AuthID)
	}
	tw, targs := timeWhere(f.From, f.To)
	sb.WriteString(tw)
	args = append(args, targs...)
	return sb.String(), args
}
