package codexsidecar

import (
	"crypto/sha256"
	"encoding/binary"
	"sort"
	"strconv"
	"sync"
	"time"
)

// OTLP metrics, modelled on crack/codexapp0.153.4/rows/50.
//
// The captured export is 108 KB covering 19 metrics, most of them describing
// the Desktop app's own local subsystems. This package emits a subset chosen
// on one rule: a metric is emitted when its value is either MEASURED (the
// sidecar timed its own HTTP call) or per-account synthetic in the same sense
// sidecar.buildProcessMetrics already accepts (a stable, plausible local
// resource footprint anchored on the account, so accounts do not all report
// one identical machine). Metrics that would be neither — the sqlite log-write
// family, remote_models.load_cache — are omitted rather than fabricated.
//
// Temporality is 1 (DELTA) with isMonotonic true on the sums, verbatim from
// the capture, which is why export drains and resets the registry: a delta
// export that re-sent cumulative totals every 60s would be internally wrong.

const (
	// otlpExportInterval is the exporter's own period. The capture pins it
	// exactly: every data point's timeUnixNano is startTimeUnixNano + 60.000s,
	// and 15 exports landed across the 17-minute window.
	otlpExportInterval = 60 * time.Second

	otlpServiceName = "codex-app-server"
	otlpScopeName   = "codex"
	// otlpEnv is "dev" in the capture. It looks like a mistake in the shipped
	// build, but it is what the genuine client sends, so it is reproduced.
	otlpEnv = "dev"
	// otlpOriginator is the value of the `originator` data-point attribute —
	// the app-server component name, NOT the "Codex Desktop" header
	// originator. The two are different strings on purpose.
	otlpOriginator = "codex-app-server"
)

// durationMsBounds is the histogram ladder every *_duration_ms metric uses,
// verbatim from the capture (34 bounds → 35 buckets).
var durationMsBounds = []float64{
	0, 5, 10, 25, 50, 75, 100, 250, 500, 750, 1000, 1250, 1500, 1750, 2000,
	2250, 2500, 3000, 3500, 4000, 4500, 5000, 6000, 7000, 7500, 8000, 9000,
	10000, 12000, 15000, 20000, 30000, 60000, 120000,
}

// byteBounds is the ladder codex.app_server.codex_home.size_bytes uses
// (7 bounds → 8 buckets).
var byteBounds = []float64{
	1 << 20, 10 << 20, 100 << 20, 1 << 30, 10 << 30, 100 << 30, 1 << 40,
}

type metricKind int

const (
	metricSum metricKind = iota
	metricHistogramMs
	metricHistogramBytes
)

// attr is one ordered key/value data-point attribute. A slice preserves the
// capture's ordering; a map would let Go sort them into a different shape.
type attr struct {
	Key   string
	Value string
}

type metricSeries struct {
	name  string
	desc  string
	unit  string
	kind  metricKind
	attrs []attr

	sum     int64
	samples []float64
	start   time.Time
}

// metricRegistry accumulates one session's metrics between exports.
type metricRegistry struct {
	mu     sync.Mutex
	series map[string]*metricSeries
	order  []string
	start  time.Time
}

func newMetricRegistry(start time.Time) *metricRegistry {
	return &metricRegistry{series: map[string]*metricSeries{}, start: start}
}

func seriesKey(name string, attrs []attr) string {
	k := name
	for _, a := range attrs {
		k += "\x00" + a.Key + "\x00" + a.Value
	}
	return k
}

func (r *metricRegistry) get(name, desc, unit string, kind metricKind, attrs []attr) *metricSeries {
	key := seriesKey(name, attrs)
	if s, ok := r.series[key]; ok {
		return s
	}
	s := &metricSeries{name: name, desc: desc, unit: unit, kind: kind, attrs: attrs, start: r.start}
	r.series[key] = s
	r.order = append(r.order, key)
	return s
}

// AddCount records a delta on a monotonic sum.
func (r *metricRegistry) addCount(name string, attrs []attr, v int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.get(name, "", "", metricSum, attrs).sum += v
}

// observeMs records one duration sample in milliseconds.
func (r *metricRegistry) observeMs(name string, attrs []attr, d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.get(name, "Duration in milliseconds.", "ms", metricHistogramMs, attrs)
	s.samples = append(s.samples, float64(d.Milliseconds()))
}

// observeBytes records one size sample in bytes.
func (r *metricRegistry) observeBytes(name string, attrs []attr, v float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.get(name, "", "By", metricHistogramBytes, attrs)
	s.samples = append(s.samples, v)
}

// drain removes and returns everything accumulated since the previous drain,
// which is what DELTA temporality means. Returns nil when nothing was recorded
// — the caller then skips the export entirely rather than posting an empty
// resourceMetrics envelope, which no genuine exporter does.
func (r *metricRegistry) drain(now time.Time) []*metricSeries {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*metricSeries, 0, len(r.order))
	for _, k := range r.order {
		s := r.series[k]
		if s.sum == 0 && len(s.samples) == 0 {
			continue
		}
		cp := *s
		out = append(out, &cp)
		s.sum = 0
		s.samples = nil
		s.start = now
	}
	r.start = now
	return out
}

// buildOTLPBody renders the OTLP/JSON envelope. Resource attribute ORDER is
// the capture's (telemetry.sdk.name, service.name, telemetry.sdk.version, os,
// telemetry.sdk.language, os_version, env, service.version) — not alphabetical
// and not grouped, because that is the order the Rust SDK's attribute set
// happens to serialize in.
func buildOTLPBody(host osAttrs, series []*metricSeries, now time.Time) map[string]any {
	resourceAttrs := []map[string]any{
		otlpAttr("telemetry.sdk.name", "opentelemetry"),
		otlpAttr("service.name", otlpServiceName),
		otlpAttr("telemetry.sdk.version", otlpSDKVersion),
		otlpAttr("os", host.Name),
		otlpAttr("telemetry.sdk.language", "rust"),
		otlpAttr("os_version", host.Version),
		otlpAttr("env", otlpEnv),
		otlpAttr("service.version", desktopVersion),
	}

	// Group series by metric name, preserving first-seen order — the capture
	// carries one metric object per name with all its data points inside.
	type group struct {
		name string
		kind metricKind
		desc string
		unit string
		pts  []map[string]any
	}
	var groups []*group
	byName := map[string]*group{}
	for _, s := range series {
		g, ok := byName[s.name]
		if !ok {
			g = &group{name: s.name, kind: s.kind, desc: s.desc, unit: s.unit}
			byName[s.name] = g
			groups = append(groups, g)
		}
		g.pts = append(g.pts, dataPoint(s, now))
	}

	metrics := make([]map[string]any, 0, len(groups))
	for _, g := range groups {
		m := map[string]any{
			"name":        g.name,
			"description": g.desc,
			"unit":        g.unit,
			"metadata":    []any{},
		}
		if g.kind == metricSum {
			m["sum"] = map[string]any{
				"dataPoints":             g.pts,
				"aggregationTemporality": 1,
				"isMonotonic":            true,
			}
		} else {
			m["histogram"] = map[string]any{
				"dataPoints":             g.pts,
				"aggregationTemporality": 1,
			}
		}
		metrics = append(metrics, m)
	}

	return map[string]any{
		"resourceMetrics": []any{
			map[string]any{
				"resource": map[string]any{"attributes": resourceAttrs},
				"scopeMetrics": []any{
					map[string]any{
						"scope": map[string]any{
							"name":                   otlpScopeName,
							"version":                "",
							"attributes":             []any{},
							"droppedAttributesCount": 0,
						},
						"metrics": metrics,
					},
				},
				"schemaUrl": "",
			},
		},
	}
}

func otlpAttr(k, v string) map[string]any {
	return map[string]any{"key": k, "value": map[string]any{"stringValue": v}}
}

func dataPoint(s *metricSeries, now time.Time) map[string]any {
	attrs := make([]map[string]any, 0, len(s.attrs))
	for _, a := range s.attrs {
		attrs = append(attrs, otlpAttr(a.Key, a.Value))
	}
	dp := map[string]any{
		"attributes":        attrs,
		"startTimeUnixNano": strconv.FormatInt(s.start.UnixNano(), 10),
		"timeUnixNano":      strconv.FormatInt(now.UnixNano(), 10),
		"exemplars":         []any{},
		"flags":             0,
	}
	if s.kind == metricSum {
		dp["asInt"] = s.sum
		return dp
	}
	bounds := durationMsBounds
	if s.kind == metricHistogramBytes {
		bounds = byteBounds
	}
	buckets := make([]int, len(bounds)+1)
	total := 0.0
	minV, maxV := s.samples[0], s.samples[0]
	for _, v := range s.samples {
		total += v
		if v < minV {
			minV = v
		}
		if v > maxV {
			maxV = v
		}
		buckets[sort.SearchFloat64s(bounds, v)]++
	}
	dp["count"] = len(s.samples)
	dp["sum"] = total
	dp["bucketCounts"] = buckets
	dp["explicitBounds"] = bounds
	dp["min"] = minV
	dp["max"] = maxV
	return dp
}

// sqliteInitPhases is the (db, phase) matrix the capture reports at process
// start, verbatim and in capture order. These are local to the client, so the
// durations are per-account synthetic (see recordStartupMetrics) — but the
// phase list itself is ground truth and must not be invented or reordered.
var sqliteInitPhases = []struct{ DB, Phase string }{
	{"goals", "open_goals"},
	{"state", "ensure_backfill_state"},
	{"state", "backfill_gate"},
	{"logs", "migrate_logs"},
	{"memories", "open_memories"},
	{"queue", "migrate_queue"},
	{"memories", "migrate_memories"},
	{"logs", "open_logs"},
	{"state", "migrate_state"},
	{"state", "post_init_query"},
	{"state", "open_state"},
	{"goals", "migrate_goals"},
	{"queue", "open_queue"},
}

// codexHomeDirs is the directory set codex.app_server.codex_home.size_bytes
// reports, in capture order.
var codexHomeDirs = []string{"archived_sessions", "sessions", "codex_home"}

// recordStartupMetrics seeds the process-start metrics: the counter every
// export window opens with, the sqlite init matrix, and the codex_home size
// histogram.
//
// The sqlite durations and the directory sizes are per-account synthetic,
// anchored on the account key exactly the way sidecar.buildProcessMetrics
// anchors rss/heapTotal: a given machine has a stable disk footprint, and
// every account reporting byte-identical local metrics is the same
// "all one machine" signal the resource attributes exist to avoid.
func recordStartupMetrics(r *metricRegistry, accountKey string) {
	r.addCount("codex.process.start", []attr{{"originator", otlpOriginator}}, 1)

	seed := sha256.Sum256([]byte("cc-core-codexsidecar-otlp/" + accountKey))
	b := func(i int) int { return int(seed[i%len(seed)]) }

	for i, p := range sqliteInitPhases {
		a := []attr{
			{"db", p.DB},
			{"error", "none"},
			{"originator", otlpOriginator},
			{"phase", p.Phase},
			{"status", "success"},
		}
		r.addCount("codex.sqlite.init.count", a, 1)
		// Captured durations are 0–8 ms; keep the same range.
		r.observeMs("codex.sqlite.init.duration_ms", a, time.Duration(b(i)%9)*time.Millisecond)
	}

	// Captured sizes: archived_sessions 0, sessions ~0.96 GB, codex_home
	// ~1.76 GB. Scale per account within a plausible band and keep
	// codex_home > sessions, which is structurally true (it contains it).
	sizeSeed := binary.BigEndian.Uint32(seed[8:12])
	sessions := float64(200<<20) + float64(sizeSeed%uint32(3<<30))
	home := sessions * (1.4 + float64(b(13)%60)/100)
	sizes := map[string]float64{"archived_sessions": 0, "sessions": sessions, "codex_home": home}
	for _, d := range codexHomeDirs {
		r.observeBytes("codex.app_server.codex_home.size_bytes",
			[]attr{{"compression_enabled", "false"}, {"directory", d}}, sizes[d])
	}
}
