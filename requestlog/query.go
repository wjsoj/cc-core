package requestlog

import (
	"bufio"
	"container/heap"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// bucketLoc is the time zone used to assign records to day buckets (ByDay
// keys) and to label hourly buckets. It defaults to UTC so existing
// consumers are unaffected; a host can call SetBucketLocation to make the
// dashboard's "day" align with local time. Day buckets are recomputed from
// each record's raw timestamp at query time, so changing this re-buckets
// all historical data without a migration. On-disk file names
// (requests-YYYY-MM-DD.jsonl) and retention stay in UTC and are unaffected.
// Set once at startup before serving — not guarded for concurrent mutation.
var bucketLoc = time.UTC

// SetBucketLocation sets the time zone used for day/hour bucketing. A nil
// location is ignored. Call once during startup.
func SetBucketLocation(l *time.Location) {
	if l != nil {
		bucketLoc = l
	}
}

// BucketLocation returns the configured bucketing time zone (UTC by default).
func BucketLocation() *time.Location { return bucketLoc }

// Aggregate sums counters over a set of records.
type Aggregate struct {
	Count             int64   `json:"count"`
	InputTokens       int64   `json:"input_tokens"`
	OutputTokens      int64   `json:"output_tokens"`
	CacheReadTokens   int64   `json:"cache_read_tokens"`
	CacheCreateTokens int64   `json:"cache_create_tokens"`
	CostUSD           float64 `json:"cost_usd"`
	Errors            int64   `json:"errors"`
	TotalDurationMs   int64   `json:"total_duration_ms"`
}

func (a *Aggregate) add(r Record) {
	a.Count++
	a.InputTokens += r.Input
	a.OutputTokens += r.Output
	a.CacheReadTokens += r.CacheRead
	a.CacheCreateTokens += r.CacheCreate
	a.CostUSD += r.CostUSD
	a.TotalDurationMs += r.DurationMs
	if r.Status >= 400 || r.Error != "" {
		a.Errors++
	}
}

// Filter selects records. Empty string fields and zero time fields mean
// "no constraint".
type Filter struct {
	Dir         string
	From        time.Time // inclusive; compared at day granularity (UTC)
	To          time.Time // inclusive
	ClientToken string    // exact match on Record.ClientToken (masked); preferred over Client
	Client      string    // exact match on Record.Client (fallback for orphans)
	Model       string    // exact match on Record.Model
	Provider    string    // exact match on Record.Provider. Legacy records (no provider field) match when Provider == "anthropic" so back-fill isn't needed.
	Status      int       // 0 = any; otherwise exact match
	AuthID      string    // exact match on Record.AuthID (credential ID)
	// UserID limits results to records emitted by a specific SaaS user.
	// Used by public-facing dashboards so a customer sees only their own
	// bill. Zero = no constraint (operator query).
	UserID int64
	Limit  int // page size for Entries (0 = 50)
	Offset int // number of newest-first records to skip before Limit
	// PageOnly turns the query into a cheap table/list lookup: it skips the
	// Summary/ByClient/ByModel/ByDay aggregates AND stops scanning as soon
	// as Offset+Limit matching entries have been collected from the newest
	// log files. A full-archive scan (all retained days) collapses to a
	// newest-files-only scan — the common case reads one file. Use ONLY for
	// callers that render Entries alone and never read the aggregate maps or
	// Summary.Count (those are left zero/empty when PageOnly is set).
	PageOnly bool
}

// Result is the Query return value.
type Result struct {
	Summary  Aggregate            `json:"summary"`
	ByClient map[string]Aggregate `json:"by_client"`
	ByModel  map[string]Aggregate `json:"by_model"`
	ByDay    map[string]Aggregate `json:"by_day"`
	Entries  []Record             `json:"entries"`
	Scanned  int64                `json:"scanned"`
}

// HourBucket holds one hour's worth of aggregated counters.
type HourBucket struct {
	Hour              time.Time `json:"hour"` // truncated to the hour, in bucketLoc (UTC by default)
	Count             int64     `json:"count"`
	InputTokens       int64     `json:"input_tokens"`
	OutputTokens      int64     `json:"output_tokens"`
	CacheReadTokens   int64     `json:"cache_read_tokens"`
	CacheCreateTokens int64     `json:"cache_create_tokens"`
	CostUSD           float64   `json:"cost_usd"`
	Errors            int64     `json:"errors"`
}

// AggregateHourly scans the log files that could contain records in the
// last `hours` window and returns `hours` consecutive hour buckets ending
// at the current hour (inclusive). Missing hours are returned zero-filled
// so the UI can render a continuous timeseries without gap handling.
func AggregateHourly(dir string, hours int) ([]HourBucket, error) {
	if hours <= 0 {
		hours = 24
	}
	now := time.Now().UTC().Truncate(time.Hour)
	start := now.Add(-time.Duration(hours-1) * time.Hour)
	files, err := listLogFiles(dir)
	if err != nil {
		return nil, err
	}
	buckets := make([]HourBucket, hours)
	for i := 0; i < hours; i++ {
		// Window math stays in UTC (file names + idx are UTC); only the
		// displayed label is localized so the chart reads in local time.
		buckets[i].Hour = start.Add(time.Duration(i) * time.Hour).In(bucketLoc)
	}
	for _, path := range files {
		day := extractDay(path)
		if day < start.Format("2006-01-02") || day > now.Format("2006-01-02") {
			continue
		}
		fh, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 64*1024), 2*1024*1024)
		for sc.Scan() {
			var r Record
			if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
				continue
			}
			if r.TS.Before(start) || r.TS.After(now.Add(time.Hour)) {
				continue
			}
			idx := int(r.TS.UTC().Truncate(time.Hour).Sub(start) / time.Hour)
			if idx < 0 || idx >= hours {
				continue
			}
			b := &buckets[idx]
			b.Count++
			b.InputTokens += r.Input
			b.OutputTokens += r.Output
			b.CacheReadTokens += r.CacheRead
			b.CacheCreateTokens += r.CacheCreate
			b.CostUSD += r.CostUSD
			if r.Status >= 400 || r.Error != "" {
				b.Errors++
			}
		}
		_ = fh.Close()
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}
	return buckets, nil
}

// AggregateByAuth scans rotated log files whose day is within [from, to]
// (inclusive; zero values mean "unbounded"), filters records by exact
// timestamp, and returns per-AuthID aggregates. Intended for the admin
// summary to compute accurate lifetime and rolling-window totals directly
// from the request log, bypassing the in-memory counter (which resets on
// restart / state rebuild).
func AggregateByAuth(dir string, from, to time.Time) (map[string]Aggregate, error) {
	files, err := listLogFiles(dir)
	if err != nil {
		return nil, err
	}
	out := make(map[string]Aggregate)
	for _, path := range files {
		day := extractDay(path)
		if !dayInRange(day, from, to) {
			continue
		}
		fh, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 64*1024), 2*1024*1024)
		for sc.Scan() {
			var r Record
			if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
				continue
			}
			if !from.IsZero() && r.TS.Before(from) {
				continue
			}
			if !to.IsZero() && r.TS.After(to) {
				continue
			}
			if r.AuthID == "" {
				continue
			}
			agg := out[r.AuthID]
			agg.add(r)
			out[r.AuthID] = agg
		}
		_ = fh.Close()
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// Query scans rotated log files in dir that intersect the [From, To]
// window, applies the filter, aggregates counts, and returns the page
// [Offset, Offset+Limit) of matching entries sorted newest-first.
// Summary.Count holds the full match count, so callers can render
// pagination controls without a second query.
func Query(f Filter) (*Result, error) {
	if f.Limit <= 0 {
		f.Limit = 50
	}
	if f.Offset < 0 {
		f.Offset = 0
	}
	// keep is the most newest-first entries we could ever return; collecting
	// beyond it is wasted memory since Query only returns [Offset, Offset+Limit).
	keep := f.Offset + f.Limit
	files, err := listLogFiles(f.Dir)
	if err != nil {
		return nil, err
	}
	sort.Sort(sort.Reverse(sort.StringSlice(files)))

	res := &Result{
		ByClient: make(map[string]Aggregate),
		ByModel:  make(map[string]Aggregate),
		ByDay:    make(map[string]Aggregate),
	}
	// top is a min-heap (root = oldest kept) bounded to `keep` entries, so
	// memory stays O(page) regardless of how many records match — a
	// full-archive scan no longer materializes every matching row.
	top := &entryHeap{}
	for _, path := range files {
		day := extractDay(path)
		if !dayInRange(day, f.From, f.To) {
			continue
		}
		if err := scanFile(path, f, res, top, keep); err != nil {
			return nil, err
		}
		// PageOnly skips the aggregates, so once the newest `keep` matches
		// are in hand no older file can contribute to the returned page
		// (files are processed newest-day-first and a day's records are all
		// older than any record in a newer day). Stop early.
		if f.PageOnly && keep > 0 && top.Len() >= keep {
			break
		}
	}
	// Drain the min-heap into newest-first order: successive Pop() yields the
	// oldest kept first, so fill the slice back-to-front.
	ents := make([]Record, top.Len())
	for i := len(ents) - 1; i >= 0; i-- {
		ents[i] = heap.Pop(top).(Record)
	}
	if f.Offset >= len(ents) {
		ents = nil
	} else {
		ents = ents[f.Offset:]
	}
	if len(ents) > f.Limit {
		ents = ents[:f.Limit]
	}
	res.Entries = ents
	return res, nil
}

func scanFile(path string, f Filter, res *Result, top *entryHeap, keep int) error {
	fh, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer fh.Close()
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 64*1024), 2*1024*1024)
	for sc.Scan() {
		res.Scanned++
		var r Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			continue
		}
		if !matches(r, f) {
			continue
		}
		// Aggregates require a full scan of every match, so they're only
		// computed when the caller actually reads them (PageOnly == false).
		if !f.PageOnly {
			res.Summary.add(r)
			ckey := r.ClientToken
			if ckey == "" {
				ckey = r.Client
			}
			by := res.ByClient[ckey]
			by.add(r)
			res.ByClient[ckey] = by
			bm := res.ByModel[r.Model]
			bm.add(r)
			res.ByModel[r.Model] = bm
			dayKey := r.TS.In(bucketLoc).Format("2006-01-02")
			bd := res.ByDay[dayKey]
			bd.add(r)
			res.ByDay[dayKey] = bd
		}
		pushBounded(top, r, keep)
	}
	return sc.Err()
}

// pushBounded keeps `top` to at most `keep` records, retaining the newest
// (largest TS). It is the streaming equivalent of "collect all matches, sort
// newest-first, take the first keep" — same result, O(keep) memory.
func pushBounded(top *entryHeap, r Record, keep int) {
	if keep <= 0 {
		return
	}
	if top.Len() < keep {
		heap.Push(top, r)
		return
	}
	// Heap full: replace the oldest kept only if this record is newer.
	if r.TS.After((*top)[0].TS) {
		(*top)[0] = r
		heap.Fix(top, 0)
	}
}

// entryHeap is a min-heap of Records ordered by timestamp (root = oldest),
// used to retain the newest N matches during a scan without buffering all of
// them.
type entryHeap []Record

func (e entryHeap) Len() int           { return len(e) }
func (e entryHeap) Less(i, j int) bool { return e[i].TS.Before(e[j].TS) }
func (e entryHeap) Swap(i, j int)      { e[i], e[j] = e[j], e[i] }
func (e *entryHeap) Push(x any)        { *e = append(*e, x.(Record)) }
func (e *entryHeap) Pop() any {
	old := *e
	n := len(old)
	x := old[n-1]
	*e = old[:n-1]
	return x
}

func matches(r Record, f Filter) bool {
	if f.UserID != 0 && r.UserID != f.UserID {
		return false
	}
	if f.ClientToken != "" {
		if r.ClientToken != f.ClientToken {
			return false
		}
	} else if f.Client != "" && !strings.EqualFold(r.Client, f.Client) {
		return false
	}
	if f.Model != "" && !strings.EqualFold(r.Model, f.Model) {
		return false
	}
	if f.Provider != "" {
		// Records written before the provider field existed will have
		// r.Provider == "". Treat them as anthropic so historical data is
		// still reachable without a back-fill migration.
		rp := strings.ToLower(r.Provider)
		if rp == "" {
			rp = "anthropic"
		}
		if !strings.EqualFold(rp, f.Provider) {
			return false
		}
	}
	if f.Status != 0 && r.Status != f.Status {
		return false
	}
	if f.AuthID != "" && r.AuthID != f.AuthID {
		return false
	}
	if !f.From.IsZero() && r.TS.Before(f.From) {
		return false
	}
	if !f.To.IsZero() && r.TS.After(f.To) {
		return false
	}
	return true
}

func listLogFiles(dir string) ([]string, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, "requests-") || !strings.HasSuffix(name, ".jsonl") {
			continue
		}
		out = append(out, filepath.Join(dir, name))
	}
	return out, nil
}

func extractDay(path string) string {
	base := filepath.Base(path)
	base = strings.TrimPrefix(base, "requests-")
	base = strings.TrimSuffix(base, ".jsonl")
	return base
}

func dayInRange(day string, from, to time.Time) bool {
	if !from.IsZero() && day < from.UTC().Format("2006-01-02") {
		return false
	}
	if !to.IsZero() && day > to.UTC().Format("2006-01-02") {
		return false
	}
	return true
}
