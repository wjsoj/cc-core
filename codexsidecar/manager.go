package codexsidecar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/wjsoj/cc-core/auth"
)

// Defaults and lifecycle constants. Everything with a cadence is cross-checked
// against capturedMinInterval below, which is the hard ceiling on request rate.
const (
	defaultBaseURL = "https://chatgpt.com"
	defaultOTLPURL = "https://ab.chatgpt.com/otlp/v1/metrics"

	// sessionIdleTTL: a virtual Desktop "process" with no traffic for this
	// long is considered exited. The next Notify starts a new one (subject to
	// bootstrapCooldown).
	sessionIdleTTL = 30 * time.Minute
	// gcInterval is how often the sweeper evicts idle sessions.
	gcInterval = 5 * time.Minute
	// requestTimeout caps any single sidecar HTTP call.
	requestTimeout = 30 * time.Second

	// bootstrapCooldown suppresses the burst when the same account bootstrapped
	// recently. One ChatGPT account is one installation (see
	// mimicry.CodexInstallationIDFor), so N downstream client tokens funnelling
	// through it must not look like N app launches.
	bootstrapCooldown = 12 * time.Hour

	// bootstrapJitterFrac perturbs each step's captured offset. Replaying the
	// exact ladder to the millisecond on every session is itself a fingerprint.
	bootstrapJitterFrac = 0.12

	// steadyJitterFrac perturbs the steady-state poll intervals so two accounts
	// on one proxy do not beat in lockstep.
	steadyJitterFrac = 0.25

	// idleStopWindow: steady-state pollers stop once the account has been
	// quiet this long. A real app keeps polling while its window is open and
	// stops when the user quits; polling forever for an account that stopped
	// sending turns is traffic no genuine client produces.
	idleStopWindow = 10 * time.Minute

	// analyticsFlushInterval batches queued turn events. The genuine client
	// posts 1-4 events per request; batching keeps event fidelity while
	// holding the POST rate under the captured one.
	analyticsFlushInterval = 60 * time.Second
	// analyticsQueueDepth bounds memory if a session generates turns faster
	// than they flush. Overflow is dropped, never sent late with stale ids.
	analyticsQueueDepth = 64
	// analyticsMaxBatch caps events per POST.
	analyticsMaxBatch = 8
)

// Steady-state poll intervals. Each is the interval this package USES; each is
// deliberately longer than the corresponding capturedMinInterval, so the
// scheduler sits below the real client's rate and the floor never binds during
// normal operation. Sum over 17 minutes is roughly a third of the ~215 requests
// one genuine Desktop emitted.
const (
	pollPluginsInstalled = 45 * time.Second
	pollPluginsList      = 90 * time.Second
	pollPluginsFeatured  = 180 * time.Second
	pollPluginsSuggested = 300 * time.Second
	pollCodexModels      = 180 * time.Second
	pollMCPRefresh       = 600 * time.Second
	pollSettingsUser     = 900 * time.Second
)

// capturedMinInterval is the shortest spacing each endpoint was observed at,
// computed as (17 min capture window / sample count) from
// crack/codexapp0.153.4/SPEC.md §4.3. It is the RATE FLOOR: no call goes out
// if the previous one for the same (account, endpoint) was more recently than
// this. It is a backstop against a scheduling bug or a retry storm, not the
// schedule — see the poll* constants for that.
//
//	ps/plugins/installed        42 → 24s
//	ps/plugins/list             23 → 44s
//	plugins/featured            11 → 92s
//	ps/mcp                      13 → 78s
//	otlp/v1/metrics             15 → 60s (exporter period, exact from the data)
//	codex/models                 9 → 113s
//	ps/plugins/suggested/codex   5 → 204s
//	wham/settings/user           2 → 510s
//	codex/analytics-events      10 → 102s
var capturedMinInterval = map[string]time.Duration{
	epPluginsInstalled: 24 * time.Second,
	epPluginsList:      44 * time.Second,
	epPluginsFeatured:  92 * time.Second,
	epPluginsSuggested: 204 * time.Second,
	epCodexModels:      113 * time.Second,
	epMCP:              78 * time.Second,
	epSettingsUser:     510 * time.Second,
	epOTLP:             60 * time.Second,
	epAnalytics:        102 * time.Second,
}

// Endpoint identifiers. The rate floor is keyed on these, so every ps/mcp call
// in a five-call handshake shares one budget line — which is what the captured
// 13 samples across 17 minutes actually counts.
const (
	epPluginsInstalled = "ps/plugins/installed"
	epPluginsList      = "ps/plugins/list"
	epPluginsFeatured  = "plugins/featured"
	epPluginsSuggested = "ps/plugins/suggested"
	epCodexModels      = "codex/models"
	epMCP              = "ps/mcp"
	epSettingsUser     = "wham/settings/user"
	epOTLP             = "otlp/v1/metrics"
	epAnalytics        = "codex/analytics-events"
)

// Config is the constructor argument for New.
type Config struct {
	Enabled bool
	UseUTLS bool
	// BaseURL is the ChatGPT backend origin; empty means defaultBaseURL.
	BaseURL string
	// OTLPURL is the full metrics endpoint; empty means defaultOTLPURL. It is
	// a separate host (ab.chatgpt.com) from BaseURL and carries no bearer.
	OTLPURL string
}

// Manager tracks one virtual Codex Desktop process per upstream account and
// dispatches its auxiliary traffic. Safe for concurrent use; every HTTP call
// runs on its own goroutine and never blocks the request path.
type Manager struct {
	enabled bool
	useUTLS bool
	baseURL string
	otlpURL string

	// httpClient, when set, overrides the per-credential pooled client. Tests
	// set it to an httptest client; production leaves it nil.
	httpClient *http.Client
	// timeScale compresses every scheduled delay. 1 in production; tests set a
	// small value so an 18-second bootstrap ladder runs in well under a second
	// while keeping the ORDER and the relative spacing intact.
	timeScale float64

	sessions sync.Map // accountKey → *session
	anchors  sync.Map // accountKey → *accountAnchor
	touched  sync.Map // accountKey|clientToken → struct{}

	stopOnce sync.Once
	stopCh   chan struct{}
}

type accountAnchor struct {
	lastBootstrap atomic.Int64 // unix-nano
}

type session struct {
	accountKey string
	startedAt  time.Time
	lastSeen   atomic.Int64
	fired      atomic.Bool
	metrics    *metricRegistry
	budget     *rateBudget
	threads    sync.Map // threadID → struct{}, for thread_initialized dedupe
	events     chan map[string]any
	cancel     context.CancelFunc
}

func (s *session) idle() time.Duration {
	last := s.lastSeen.Load()
	if last == 0 {
		return 0
	}
	return time.Since(time.Unix(0, last))
}

// New builds a Manager. A disabled Manager is inert: Notify and RecordTurn do
// nothing and start no goroutines.
func New(cfg Config) *Manager {
	m := &Manager{
		enabled:   cfg.Enabled,
		useUTLS:   cfg.UseUTLS,
		baseURL:   strings.TrimRight(orDefault(cfg.BaseURL, defaultBaseURL), "/"),
		otlpURL:   orDefault(cfg.OTLPURL, defaultOTLPURL),
		timeScale: 1,
		stopCh:    make(chan struct{}),
	}
	if !m.enabled {
		return m
	}
	go m.gcLoop()
	return m
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

// eligible reports whether a credential may generate this traffic at all.
//
// Two refusals, both mirroring sidecar.Notify:
//
//   - Kind != OAuth. A real Codex Desktop on a raw OpenAI API key emits none
//     of this: there is no plugin store, no wham settings, no ChatGPT account
//     id to send. Emitting it on an API key advertises a subscription client
//     where none exists.
//   - Provider != OpenAI. Every endpoint here is chatgpt.com/backend-api and
//     authenticates with a ChatGPT bearer. Without this guard an Anthropic
//     OAuth credential would send the whole Codex plugin-store burst signed
//     with an Anthropic access token.
func eligible(a *auth.Auth) bool {
	if a == nil || a.Kind != auth.KindOAuth {
		return false
	}
	return auth.NormalizeProvider(a.Provider) == auth.ProviderOpenAI
}

// Notify registers a request from (a, clientToken).
//
// The first touch of an (account, clientToken) pair starts the account's
// virtual Desktop process and fires the bootstrap burst. Subsequent pairs on
// the SAME account do not re-fire it: they are additional windows of one
// installation, and bootstrapCooldown enforces that at most one launch per
// account per 12h reaches upstream. Session state is therefore keyed on the
// account, matching mimicry.CodexInstallationIDFor's "one account is one
// installation" invariant — N launches from one installation in one minute is
// precisely the shape this exists to avoid.
//
// Returns immediately. Every HTTP call it schedules happens on another
// goroutine, and none of them can block or fail the caller's request.
func (m *Manager) Notify(a *auth.Auth, clientToken string) {
	if m == nil || !m.enabled || !eligible(a) {
		return
	}
	accountKey := a.AccountKey()
	now := time.Now().UnixNano()

	firstTouch := true
	if _, loaded := m.touched.LoadOrStore(accountKey+"|"+clientToken, struct{}{}); loaded {
		firstTouch = false
	}

	fresh := m.newSession(accountKey)
	v, loaded := m.sessions.LoadOrStore(accountKey, fresh)
	sess := v.(*session)
	prev := sess.lastSeen.Swap(now)

	isNew := !loaded
	if !isNew && prev > 0 && time.Duration(now-prev) >= sessionIdleTTL {
		if sess.cancel != nil {
			sess.cancel()
		}
		sess = m.newSession(accountKey)
		sess.lastSeen.Store(now)
		m.sessions.Store(accountKey, sess)
		isNew = true
	}
	if !isNew {
		return
	}
	if !sess.fired.CompareAndSwap(false, true) {
		return
	}

	// Pin the account's synthetic host profile to the credential file so the
	// OTLP resource block reports a stable machine for this account rather
	// than re-deriving it. Idempotent; off the hot path.
	go func() {
		if err := a.EnsureHostProfile(); err != nil {
			log.Debugf("codexsidecar: persist host profile for %s failed: %v", a.ID, err)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	sess.cancel = cancel

	anchor := m.anchorFor(accountKey)
	last := anchor.lastBootstrap.Load()
	withinCooldown := last > 0 && time.Duration(now-last) < bootstrapCooldown
	if withinCooldown {
		log.Debugf("codexsidecar: bootstrap suppressed (within %s) for %s clientToken=%s firstTouch=%v",
			bootstrapCooldown, a.ID, maskToken(clientToken), firstTouch)
	} else {
		recordStartupMetrics(sess.metrics, accountKey)
		go m.runBootstrap(ctx, a, sess, anchor)
	}
	go m.runSteadyState(ctx, a, sess)
	go m.runOTLPExporter(ctx, a, sess)
	go m.runAnalyticsFlusher(ctx, a, sess)
}

func (m *Manager) newSession(accountKey string) *session {
	now := time.Now()
	return &session{
		accountKey: accountKey,
		startedAt:  now,
		metrics:    newMetricRegistry(now),
		budget:     newRateBudget(),
		events:     make(chan map[string]any, analyticsQueueDepth),
	}
}

func (m *Manager) anchorFor(accountKey string) *accountAnchor {
	if v, ok := m.anchors.Load(accountKey); ok {
		return v.(*accountAnchor)
	}
	v, _ := m.anchors.LoadOrStore(accountKey, &accountAnchor{})
	return v.(*accountAnchor)
}

func maskToken(t string) string {
	if len(t) <= 7 {
		return t
	}
	return t[:7] + "***"
}

// =============================================================================
// Rate floor
// =============================================================================

// rateBudget enforces capturedMinInterval per endpoint for one account. Every
// outbound call passes through allow(); there is no bypass.
type rateBudget struct {
	mu   sync.Mutex
	last map[string]time.Time
}

func newRateBudget() *rateBudget { return &rateBudget{last: map[string]time.Time{}} }

// allow reserves a slot for endpoint if the floor permits, and reports whether
// it did. Reserving on success (rather than after the request completes) means
// a slow upstream cannot let a second call slip through underneath the first.
func (b *rateBudget) allow(endpoint string, now time.Time) bool {
	minGap, ok := capturedMinInterval[endpoint]
	if !ok {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if prev, seen := b.last[endpoint]; seen && now.Sub(prev) < minGap {
		return false
	}
	b.last[endpoint] = now
	return true
}

// =============================================================================
// Requests
// =============================================================================

// call is one outbound sidecar request.
type call struct {
	// endpoint is the rate-floor key.
	endpoint string
	// name is the log/test label; several calls share one endpoint.
	name        string
	method      string
	url         string
	ua          uaKind
	accept      string
	contentType string
	body        []byte
	// extra headers, applied after the common set.
	extra map[string]string
	// noAuth omits Authorization AND chatgpt-account-id. Only the OTLP
	// exporter sets it: that endpoint authenticates with statsig-api-key and
	// a bearer there would be a header no genuine exporter sends.
	noAuth bool
	// absolute marks url as already complete (OTLP); otherwise it is appended
	// to the manager's base URL.
	absolute bool
}

// do dispatches one call and returns how long the round trip took, which is
// what the OTLP duration histograms record.
func (m *Manager) do(parent context.Context, a *auth.Auth, sess *session, c call) (time.Duration, error) {
	if c.endpoint != "" && !sess.budget.allow(c.endpoint, time.Now()) {
		return 0, fmt.Errorf("codexsidecar: %s suppressed by captured rate floor", c.endpoint)
	}
	ctx, cancel := context.WithTimeout(parent, requestTimeout)
	defer cancel()

	url := c.url
	if !c.absolute {
		url = m.baseURL + c.url
	}
	var body io.Reader
	if len(c.body) > 0 {
		body = bytes.NewReader(c.body)
	}
	req, err := http.NewRequestWithContext(ctx, c.method, url, body)
	if err != nil {
		return 0, fmt.Errorf("build request: %w", err)
	}
	if !c.noAuth {
		token, _ := a.Credentials()
		if strings.TrimSpace(token) == "" {
			return 0, errors.New("no access token")
		}
		req.Header.Set("Authorization", "Bearer "+token)
		if accountID, _ := a.CodexIdentity(); accountID != "" {
			req.Header.Set("Chatgpt-Account-Id", accountID)
		}
	}
	req.Header.Set("User-Agent", userAgentFor(c.ua))
	req.Header.Set("Accept", orDefault(c.accept, "*/*"))
	if c.contentType != "" {
		req.Header.Set("Content-Type", c.contentType)
	}
	for k, v := range c.extra {
		req.Header.Set(k, v)
	}

	client := m.httpClient
	if client == nil {
		client = auth.ClientFor(a.ProxyURL, m.useUTLS)
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return time.Since(start), fmt.Errorf("transport: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	elapsed := time.Since(start)
	if resp.StatusCode >= 400 {
		return elapsed, fmt.Errorf("upstream %d", resp.StatusCode)
	}
	return elapsed, nil
}

// =============================================================================
// Bootstrap
// =============================================================================

// bootstrapStep is one call in the post-launch ladder, with the offset from
// process start derived from the capture.
type bootstrapStep struct {
	call
	// offset from the virtual process start.
	offset time.Duration
	// record folds this step's measured latency into the OTLP registry, so the
	// metrics we export describe calls that actually happened rather than
	// invented timings.
	record func(r *metricRegistry, d time.Duration)
}

// bootstrapSteps returns the launch ladder.
//
// TIMING PROVENANCE. The capture's response Date headers are second-granular
// and the whole plugin-store burst lands inside one second, so the offsets
// below come from the OTLP export instead: row 50's data points carry
// nanosecond startTimeUnixNano values, and codex.process.start fixes t0 at
// 2026-09-07T08:16:26.527Z. Everything is relative to that.
//
//	+0.50s  ps/plugins/installed        rows 41 — Date 08:16:27 (t0+0.47..1.47)
//	+0.60s  ps/plugins/list             rows 42 — same second
//	+0.70s  plugins/featured            rows 43 — same second
//	+0.80s  ps/plugins/suggested/codex  rows 44 — same second
//	+1.41s  codex/models                row 12 + codex.remote_models.fetch_update
//	                                    startTimeUnixNano = t0+1.414
//	+12.47s ps/mcp initialize           row 40 — Date 08:16:39, and
//	                                    codex.mcp.protocol_discovery = t0+12.466
//	+12.66s ps/mcp notifications/initialized — discovery duration 191 ms
//	+13.37s ps/mcp tools/list           codex.mcp.tools.list = t0+13.365
//	+14.27s ps/mcp resources/list       tools.list duration 898 ms → t0+14.263
//	+14.50s ps/mcp resources/templates/list — post-login rows put templates one
//	                                    step after resources/list
//	+18.00s wham/settings/user          row 21 — Date 08:25:47, +18s after the
//	                                    08:25:29 authorization-code grant
//
// Ordering within the ps/mcp block is not decorative: initialize must precede
// the mcp-protocol-version header the other four carry, and the jsonrpc ids
// (0,1,2,3) and progress tokens (0,1,2) are captured in that sequence.
func bootstrapSteps() []bootstrapStep {
	return []bootstrapStep{
		{call: pluginsInstalledCall(), offset: 500 * time.Millisecond},
		{
			call:   pluginsListCall(),
			offset: 600 * time.Millisecond,
			record: func(r *metricRegistry, d time.Duration) {
				r.addCount("codex.plugins.loaded_cache.request", []attr{{"outcome", "load"}}, 1)
				r.observeMs("codex.plugins.loaded_cache.load.duration_ms", nil, d)
			},
		},
		{call: pluginsFeaturedCall(), offset: 700 * time.Millisecond},
		{call: pluginsSuggestedCall(), offset: 800 * time.Millisecond},
		{
			call:   codexModelsCall(),
			offset: 1410 * time.Millisecond,
			record: func(r *metricRegistry, d time.Duration) {
				r.observeMs("codex.remote_models.fetch_update.duration_ms", nil, d)
			},
		},
		{
			call:   mcpInitializeCall(),
			offset: 12470 * time.Millisecond,
			record: func(r *metricRegistry, d time.Duration) {
				a := []attr{{"mode", "legacy"}, {"outcome", "legacy"}}
				r.addCount("codex.mcp.protocol_discovery", a, 1)
				r.observeMs("codex.mcp.protocol_discovery.duration_ms", a, d)
			},
		},
		{call: mcpInitializedCall(), offset: 12660 * time.Millisecond},
		{
			call:   mcpToolsListCall(),
			offset: 13370 * time.Millisecond,
			record: func(r *metricRegistry, d time.Duration) {
				r.observeMs("codex.mcp.tools.fetch_uncached.duration_ms", nil, d)
				r.observeMs("codex.mcp.tools.list.duration_ms", []attr{{"cache", "miss"}}, d)
			},
		},
		{call: mcpResourcesListCall(), offset: 14270 * time.Millisecond},
		{call: mcpResourceTemplatesCall(), offset: 14500 * time.Millisecond},
		{call: settingsUserCall(), offset: 18000 * time.Millisecond},
	}
}

// runBootstrap walks the ladder. Every step is best-effort: a failure is
// logged at debug and never propagates. The ps/mcp block shares one rate-floor
// line, so it is exempted from the floor within the burst — the captured
// client fires all five back to back too — by tracking the budget on the burst
// as a whole rather than per call.
func (m *Manager) runBootstrap(ctx context.Context, a *auth.Auth, sess *session, anchor *accountAnchor) {
	start := time.Now()
	prevDue := start
	for _, step := range bootstrapSteps() {
		due := start.Add(m.scaled(jitter(step.offset, bootstrapJitterFrac)))
		if !due.After(prevDue) {
			due = prevDue.Add(m.scaled(5 * time.Millisecond))
		}
		prevDue = due
		if w := time.Until(due); w > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(w):
			}
		}
		c := step.call
		// Inside the burst the floor is applied once for the whole ps/mcp
		// handshake (the first call reserves it); the rest ride along, which
		// is what the genuine five-call handshake does.
		if c.endpoint == epMCP && step.name != "mcp_initialize" {
			c.endpoint = ""
		}
		d, err := m.do(ctx, a, sess, c)
		if err != nil {
			log.Debugf("codexsidecar: bootstrap %s via %s failed: %v", step.name, a.ID, err)
			continue
		}
		if step.record != nil {
			step.record(sess.metrics, d)
		}
	}
	anchor.lastBootstrap.Store(time.Now().UnixNano())
	log.Debugf("codexsidecar: bootstrap complete for %s (account=%s)", a.ID, sess.accountKey)
}

// scaled applies the test time scale.
func (m *Manager) scaled(d time.Duration) time.Duration {
	if m == nil || m.timeScale <= 0 || m.timeScale == 1 {
		return d
	}
	return time.Duration(float64(d) * m.timeScale)
}

// jitter returns d ± frac·d, clamped at zero.
func jitter(d time.Duration, frac float64) time.Duration {
	if d <= 0 {
		return 0
	}
	out := time.Duration(float64(d) * (1 + (rand.Float64()*2-1)*frac))
	if out < 0 {
		return 0
	}
	return out
}

// =============================================================================
// Steady state
// =============================================================================

type pollTask struct {
	name     string
	interval time.Duration
	build    func() []call
	record   func(r *metricRegistry, d time.Duration)
}

func steadyTasks() []pollTask {
	return []pollTask{
		{name: "plugins_installed", interval: pollPluginsInstalled, build: func() []call {
			return []call{pluginsInstalledCall()}
		}},
		{
			name: "plugins_list", interval: pollPluginsList,
			build: func() []call { return []call{pluginsListCall()} },
			record: func(r *metricRegistry, d time.Duration) {
				r.addCount("codex.plugins.loaded_cache.request", []attr{{"outcome", "load"}}, 1)
				r.observeMs("codex.plugins.loaded_cache.load.duration_ms", nil, d)
			},
		},
		{name: "plugins_featured", interval: pollPluginsFeatured, build: func() []call {
			return []call{pluginsFeaturedCall()}
		}},
		{name: "plugins_suggested", interval: pollPluginsSuggested, build: func() []call {
			return []call{pluginsSuggestedCall()}
		}},
		{
			name: "codex_models", interval: pollCodexModels,
			build: func() []call { return []call{codexModelsCall()} },
			record: func(r *metricRegistry, d time.Duration) {
				r.observeMs("codex.remote_models.fetch_update.duration_ms", nil, d)
			},
		},
		{
			name: "mcp_refresh", interval: pollMCPRefresh,
			// A refresh re-lists tools on the already-initialized channel; it
			// does not re-send initialize, which is a per-connection handshake.
			build: func() []call { return []call{mcpToolsListCall(), mcpResourcesListCall()} },
			record: func(r *metricRegistry, d time.Duration) {
				r.observeMs("codex.mcp.tools.list.duration_ms", []attr{{"cache", "hit"}}, d)
			},
		},
		{name: "settings_user", interval: pollSettingsUser, build: func() []call {
			return []call{settingsUserCall()}
		}},
	}
}

// runSteadyState starts one goroutine per periodic task. Each stops on ctx
// cancel or once the account has been idle past idleStopWindow.
func (m *Manager) runSteadyState(ctx context.Context, a *auth.Auth, sess *session) {
	for _, task := range steadyTasks() {
		go m.runPoll(ctx, a, sess, task)
	}
}

func (m *Manager) runPoll(ctx context.Context, a *auth.Auth, sess *session, task pollTask) {
	for {
		wait := m.scaled(jitter(task.interval, steadyJitterFrac))
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		if sess.idle() > idleStopWindow {
			log.Debugf("codexsidecar: poll %s stopping, account %s idle", task.name, sess.accountKey)
			return
		}
		for i, c := range task.build() {
			// Only the first call of a multi-call task consumes the floor;
			// see runBootstrap for the same rule.
			if i > 0 {
				c.endpoint = ""
			}
			d, err := m.do(ctx, a, sess, c)
			if err != nil {
				log.Debugf("codexsidecar: poll %s via %s failed: %v", task.name, a.ID, err)
				break
			}
			if i == 0 && task.record != nil {
				task.record(sess.metrics, d)
			}
		}
	}
}

// =============================================================================
// OTLP export
// =============================================================================

// runOTLPExporter posts the accumulated metrics every otlpExportInterval,
// exactly like the Rust exporter in the capture. An interval with nothing
// recorded is skipped rather than posted empty.
func (m *Manager) runOTLPExporter(ctx context.Context, a *auth.Auth, sess *session) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(m.scaled(otlpExportInterval)):
		}
		if sess.idle() > idleStopWindow {
			return
		}
		if err := m.exportOTLP(ctx, a, sess); err != nil {
			log.Debugf("codexsidecar: otlp export via %s failed: %v", a.ID, err)
		}
	}
}

func (m *Manager) exportOTLP(ctx context.Context, a *auth.Auth, sess *session) error {
	now := time.Now()
	// Reserve the rate slot BEFORE draining. drain() is destructive (DELTA
	// temporality), so a floor rejection after the drain would silently throw
	// away a window of metrics; the call below therefore carries no endpoint
	// of its own.
	if !sess.budget.allow(epOTLP, now) {
		return nil
	}
	series := sess.metrics.drain(now)
	if len(series) == 0 {
		return nil
	}
	body, err := json.Marshal(buildOTLPBody(osAttrsFor(a), series, now))
	if err != nil {
		return fmt.Errorf("marshal otlp: %w", err)
	}
	_, err = m.do(ctx, a, sess, call{
		name:        "otlp_metrics",
		method:      http.MethodPost,
		url:         m.otlpURL,
		absolute:    true,
		ua:          uaOTLPExporter,
		contentType: "application/json",
		body:        body,
		noAuth:      true,
		extra:       map[string]string{"Statsig-Api-Key": statsigAPIKey},
	})
	return err
}

// =============================================================================
// Analytics
// =============================================================================

var (
	// ErrNotEligible is returned by RecordTurn for a credential that must
	// never emit this traffic (API key, or a non-OpenAI provider).
	ErrNotEligible = errors.New("codexsidecar: credential is not an OpenAI OAuth credential")
	// ErrNoSession is returned when RecordTurn is called for an account that
	// has no live virtual session. A turn cannot have happened on a client
	// that was never started, so there is nothing to attach the event to.
	ErrNoSession = errors.New("codexsidecar: no live session for account; call Notify first")
)

// RecordTurn queues analytics events for a turn that ACTUALLY happened.
//
// This is the only entry point to codex/analytics-events/events, and it
// refuses everything it cannot vouch for: a credential that may not emit the
// traffic, an account with no live session, and — through newVerifiedTurn — any
// observation whose thread/session/turn ids are missing or not UUIDs. The
// event builders take an unexported verifiedTurn, so there is no way to reach
// a request body from unvalidated strings.
//
// It never blocks: events go onto a bounded queue drained by one goroutine.
func (m *Manager) RecordTurn(a *auth.Auth, clientToken string, obs TurnObservation) error {
	if m == nil || !m.enabled {
		return nil
	}
	if !eligible(a) {
		return ErrNotEligible
	}
	v, ok := m.sessions.Load(a.AccountKey())
	if !ok {
		return ErrNoSession
	}
	sess := v.(*session)
	turn, err := newVerifiedTurn(obs)
	if err != nil {
		return err
	}
	sess.lastSeen.Store(time.Now().UnixNano())

	var events []map[string]any
	if _, seen := sess.threads.LoadOrStore(turn.threadID, struct{}{}); !seen {
		events = append(events, buildThreadInitializedEvent(a, turn))
	}
	events = append(events, buildTurnEvent(a, turn))
	for _, ev := range events {
		select {
		case sess.events <- ev:
		default:
			log.Debugf("codexsidecar: analytics queue full for %s, dropping event (clientToken=%s)",
				a.ID, maskToken(clientToken))
		}
	}
	return nil
}

// runAnalyticsFlusher batches queued events and posts them.
func (m *Manager) runAnalyticsFlusher(ctx context.Context, a *auth.Auth, sess *session) {
	for {
		select {
		case <-ctx.Done():
			// Last chance to deliver already-queued events; the parent
			// context is gone, so use a fresh one.
			if err := m.flushAnalytics(context.Background(), a, sess); err != nil {
				log.Debugf("codexsidecar: final analytics flush via %s failed: %v", a.ID, err)
			}
			return
		case <-time.After(m.scaled(jitter(analyticsFlushInterval, steadyJitterFrac))):
		}
		if err := m.flushAnalytics(ctx, a, sess); err != nil {
			log.Debugf("codexsidecar: analytics flush via %s failed: %v", a.ID, err)
		}
		if sess.idle() > idleStopWindow && len(sess.events) == 0 {
			return
		}
	}
}

func (m *Manager) flushAnalytics(ctx context.Context, a *auth.Auth, sess *session) error {
	// Nothing queued: return before touching the budget, or an empty tick
	// would burn the analytics rate slot and delay the next real batch.
	if len(sess.events) == 0 {
		return nil
	}
	// Same rule as exportOTLP: reserve first, because draining the queue is
	// destructive and a rejected batch would lose the events rather than
	// resend them later with ids that are still perfectly valid.
	if !sess.budget.allow(epAnalytics, time.Now()) {
		return nil
	}
	batch := make([]map[string]any, 0, analyticsMaxBatch)
	for len(batch) < analyticsMaxBatch {
		select {
		case ev := <-sess.events:
			batch = append(batch, ev)
		default:
			goto send
		}
	}
send:
	if len(batch) == 0 {
		return nil
	}
	body, err := json.Marshal(map[string]any{"events": batch})
	if err != nil {
		return fmt.Errorf("marshal analytics: %w", err)
	}
	_, err = m.do(ctx, a, sess, analyticsCall(body))
	return err
}

// =============================================================================
// Lifecycle
// =============================================================================

// Stop cancels every live session. Idempotent.
func (m *Manager) Stop() {
	if m == nil {
		return
	}
	m.stopOnce.Do(func() { close(m.stopCh) })
	m.sessions.Range(func(_, v any) bool {
		if s, ok := v.(*session); ok && s.cancel != nil {
			s.cancel()
		}
		return true
	})
}

func (m *Manager) gcLoop() {
	t := time.NewTicker(gcInterval)
	defer t.Stop()
	for {
		select {
		case <-m.stopCh:
			return
		case <-t.C:
			cutoff := time.Now().Add(-sessionIdleTTL).UnixNano()
			m.sessions.Range(func(k, v any) bool {
				s := v.(*session)
				if s.lastSeen.Load() < cutoff {
					if s.cancel != nil {
						s.cancel()
					}
					m.sessions.Delete(k)
				}
				return true
			})
		}
	}
}
