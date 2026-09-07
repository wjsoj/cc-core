package codexsidecar

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wjsoj/cc-core/auth"
)

// newOAuthAuth returns a Codex OAuth credential suitable for the emulator.
func newOAuthAuth(id string) *auth.Auth {
	return &auth.Auth{
		ID:          id,
		Kind:        auth.KindOAuth,
		Provider:    auth.ProviderOpenAI,
		Email:       id + "@example.com",
		AccessToken: "codex-access-" + id,
		AccountUUID: "acct-" + id,
		AccountID:   "chatgpt-account-" + id,
	}
}

type recordedCall struct {
	path    string
	rawURL  *url.URL
	method  string
	ua      string
	headers http.Header
	body    string
}

type recorder struct {
	mu    sync.Mutex
	calls []recordedCall
}

func (r *recorder) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		buf, _ := io.ReadAll(io.LimitReader(req.Body, 1<<20))
		r.mu.Lock()
		r.calls = append(r.calls, recordedCall{
			path:    req.URL.Path,
			rawURL:  req.URL,
			method:  req.Method,
			ua:      req.Header.Get("User-Agent"),
			headers: req.Header.Clone(),
			body:    string(buf),
		})
		r.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

func (r *recorder) snapshot() []recordedCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]recordedCall, len(r.calls))
	copy(out, r.calls)
	return out
}

// newTestManager wires a Manager at a compressed time scale so an 18-second
// bootstrap ladder runs in a fraction of a second with its ORDER and relative
// spacing intact.
func newTestManager(t *testing.T, rec *recorder, scale float64) (*Manager, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(rec.handler())
	m := New(Config{Enabled: true, BaseURL: srv.URL, OTLPURL: srv.URL + "/otlp/v1/metrics"})
	m.httpClient = srv.Client()
	m.timeScale = scale
	t.Cleanup(func() {
		m.Stop()
		srv.Close()
	})
	return m, srv
}

func waitForCalls(rec *recorder, n int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if rec.count() >= n {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

// TestBootstrapOrderAndEndpoints asserts the launch ladder fires every step in
// the captured order. The order is not cosmetic: ps/mcp initialize must
// precede the four calls that carry the negotiated mcp-protocol-version, and
// the plugin-store burst precedes the model catalog fetch in every sample.
func TestBootstrapOrderAndEndpoints(t *testing.T) {
	rec := &recorder{}
	m, _ := newTestManager(t, rec, 0.02)

	m.Notify(newOAuthAuth("a1"), "client-A")

	if !waitForCalls(rec, 11, 5*time.Second) {
		t.Fatalf("bootstrap incomplete: got %d calls, want 11", rec.count())
	}
	calls := rec.snapshot()[:11]

	want := []struct {
		method string
		path   string
		query  string
	}{
		{"GET", "/backend-api/ps/plugins/installed", "limit=200"},
		{"GET", "/backend-api/ps/plugins/list", "scope=GLOBAL&limit=200"},
		{"GET", "/backend-api/plugins/featured", "platform=codex"},
		{"GET", "/backend-api/ps/plugins/suggested/codex", "scope=GLOBAL"},
		{"GET", "/backend-api/codex/models", "client_version=" + desktopVersion},
		{"POST", "/backend-api/ps/mcp", ""},
		{"POST", "/backend-api/ps/mcp", ""},
		{"POST", "/backend-api/ps/mcp", ""},
		{"POST", "/backend-api/ps/mcp", ""},
		{"POST", "/backend-api/ps/mcp", ""},
		{"GET", "/backend-api/wham/settings/user", ""},
	}
	for i, w := range want {
		if calls[i].method != w.method || calls[i].path != w.path {
			t.Fatalf("step %d: got %s %s, want %s %s", i, calls[i].method, calls[i].path, w.method, w.path)
		}
		if calls[i].rawURL.RawQuery != w.query {
			t.Errorf("step %d query: got %q, want %q", i, calls[i].rawURL.RawQuery, w.query)
		}
	}

	// The ps/mcp block is a jsonrpc handshake with a fixed method sequence and
	// fixed ids; a reordering here is visible upstream.
	wantMCP := []string{
		`"method":"initialize"`,
		`"method":"notifications/initialized"`,
		`"method":"tools/list"`,
		`"method":"resources/list"`,
		`"method":"resources/templates/list"`,
	}
	for i, want := range wantMCP {
		if !strings.Contains(calls[5+i].body, want) {
			t.Errorf("mcp step %d: body %q missing %s", i, calls[5+i].body, want)
		}
	}
	// initialize negotiates the protocol version and therefore must NOT send
	// the header; every later call must.
	if got := calls[5].headers.Get("Mcp-Protocol-Version"); got != "" {
		t.Errorf("mcp initialize sent mcp-protocol-version=%q, capture sends none", got)
	}
	for i := 1; i < 5; i++ {
		if got := calls[5+i].headers.Get("Mcp-Protocol-Version"); got != mcpProtocolVersion {
			t.Errorf("mcp step %d: mcp-protocol-version=%q, want %q", i, got, mcpProtocolVersion)
		}
	}
}

// TestBootstrapStepOffsetsMatchCapture pins the derived timing ladder as data.
// The live ordering test above runs at a compressed scale and so cannot assert
// the real offsets; this one does, without spending 18 seconds.
func TestBootstrapStepOffsetsMatchCapture(t *testing.T) {
	want := []struct {
		name   string
		offset time.Duration
	}{
		{"plugins_installed", 500 * time.Millisecond},
		{"plugins_list", 600 * time.Millisecond},
		{"plugins_featured", 700 * time.Millisecond},
		{"plugins_suggested", 800 * time.Millisecond},
		{"codex_models", 1410 * time.Millisecond},
		{"mcp_initialize", 12470 * time.Millisecond},
		{"mcp_initialized", 12660 * time.Millisecond},
		{"mcp_tools_list", 13370 * time.Millisecond},
		{"mcp_resources_list", 14270 * time.Millisecond},
		{"mcp_resource_templates_list", 14500 * time.Millisecond},
		{"settings_user", 18000 * time.Millisecond},
	}
	steps := bootstrapSteps()
	if len(steps) != len(want) {
		t.Fatalf("step count: got %d, want %d", len(steps), len(want))
	}
	var prev time.Duration = -1
	for i, s := range steps {
		if s.name != want[i].name || s.offset != want[i].offset {
			t.Errorf("step %d: got (%s,%s), want (%s,%s)", i, s.name, s.offset, want[i].name, want[i].offset)
		}
		if s.offset <= prev {
			t.Errorf("step %d (%s) offset %s does not advance past %s", i, s.name, s.offset, prev)
		}
		prev = s.offset
	}
}

// TestBootstrapTimingIsMonotonicUnderJitter asserts the ladder never reorders
// itself. Two steps 190 ms apart under ±12% jitter could otherwise swap, which
// would put notifications/initialized before initialize.
func TestBootstrapTimingIsMonotonicUnderJitter(t *testing.T) {
	for i := 0; i < 5; i++ {
		// A fresh Manager per round: reusing one would leave the previous
		// round's steady-state pollers running into this round's recording.
		rec := &recorder{}
		m, _ := newTestManager(t, rec, 0.02)
		m.Notify(newOAuthAuth("jitter"), "client-A")
		if !waitForCalls(rec, 11, 5*time.Second) {
			t.Fatalf("round %d: bootstrap incomplete (%d calls)", i, rec.count())
		}
		calls := rec.snapshot()[:11]
		if !strings.Contains(calls[5].body, `"initialize"`) {
			t.Fatalf("round %d: mcp initialize is not the first ps/mcp call (%q)", i, calls[5].body)
		}
		if !strings.Contains(calls[6].body, "notifications/initialized") {
			t.Fatalf("round %d: notifications/initialized out of order (%q)", i, calls[6].body)
		}
		m.Stop()
	}
}

// TestPerComponentUserAgent is the header test that matters most. FOUR
// User-Agent forms coexist in one genuine process and they are per-COMPONENT:
// ps/mcp is the MCP client, the metrics endpoint is the OTel exporter, and
// everything else is the Desktop app itself. Crossing the first two is a
// one-header tell. See identity.go for why the Desktop calls all take the full
// form rather than a per-endpoint full/base split — SPEC §1 is explicit that
// the split is not per-endpoint.
func TestPerComponentUserAgent(t *testing.T) {
	rec := &recorder{}
	m, _ := newTestManager(t, rec, 0.02)
	a := newOAuthAuth("ua")
	m.Notify(a, "client-A")
	if !waitForCalls(rec, 11, 5*time.Second) {
		t.Fatalf("bootstrap incomplete: %d calls", rec.count())
	}

	// Drive one OTLP export directly so the exporter UA is covered too.
	sessAny, ok := m.sessions.Load(a.AccountKey())
	if !ok {
		t.Fatal("no session for account")
	}
	sess := sessAny.(*session)
	sess.budget.mu.Lock()
	delete(sess.budget.last, epOTLP)
	sess.budget.mu.Unlock()
	if err := m.exportOTLP(t.Context(), a, sess); err != nil {
		t.Fatalf("otlp export: %v", err)
	}

	want := map[string]string{
		"/backend-api/ps/plugins/installed":       desktopUAFull,
		"/backend-api/ps/plugins/list":            desktopUAFull,
		"/backend-api/plugins/featured":           desktopUAFull,
		"/backend-api/ps/plugins/suggested/codex": desktopUAFull,
		"/backend-api/codex/models":               desktopUAFull,
		"/backend-api/ps/mcp":                     mcpClientUA,
		"/backend-api/wham/settings/user":         desktopUAFull,
		"/otlp/v1/metrics":                        otlpExporterUA,
	}
	seen := map[string]bool{}
	for _, c := range rec.snapshot() {
		w, tracked := want[c.path]
		if !tracked {
			continue
		}
		seen[c.path] = true
		if c.ua != w {
			t.Errorf("%s: User-Agent %q, want %q", c.path, c.ua, w)
		}
	}
	for path := range want {
		if !seen[path] {
			t.Errorf("%s was never called; UA assertion did not run", path)
		}
	}

	// The two per-component forms must never leak onto an app endpoint, and
	// the app UA must never appear on ps/mcp or the metrics endpoint.
	for _, c := range rec.snapshot() {
		switch c.path {
		case "/backend-api/ps/mcp":
			if c.ua == desktopUAFull || c.ua == desktopUABase || c.ua == otlpExporterUA {
				t.Errorf("ps/mcp claimed a non-MCP client identity: %q", c.ua)
			}
		case "/otlp/v1/metrics":
			if c.ua != otlpExporterUA {
				t.Errorf("metrics endpoint claimed %q", c.ua)
			}
		default:
			if c.ua == mcpClientUA || c.ua == otlpExporterUA {
				t.Errorf("%s claimed a component identity it does not own: %q", c.path, c.ua)
			}
		}
	}
}

// TestEndpointSpecificHeaders covers the three easiest header details to lose.
func TestEndpointSpecificHeaders(t *testing.T) {
	rec := &recorder{}
	m, _ := newTestManager(t, rec, 0.02)
	a := newOAuthAuth("hdr")
	m.Notify(a, "client-A")
	if !waitForCalls(rec, 11, 5*time.Second) {
		t.Fatalf("bootstrap incomplete: %d calls", rec.count())
	}
	byPath := map[string]recordedCall{}
	for _, c := range rec.snapshot() {
		if _, dup := byPath[c.path]; !dup {
			byPath[c.path] = c
		}
	}

	if got := byPath["/backend-api/plugins/featured"].headers.Get("Oai-Product-Sku"); got != "" {
		t.Errorf("plugins/featured sent oai-product-sku=%q; the row sends none", got)
	}
	for _, p := range []string{"/backend-api/ps/plugins/installed", "/backend-api/ps/plugins/list", "/backend-api/ps/plugins/suggested/codex"} {
		if got := byPath[p].headers.Get("Oai-Product-Sku"); got != "codex" {
			t.Errorf("%s: oai-product-sku=%q, want codex", p, got)
		}
	}
	settings := byPath["/backend-api/wham/settings/user"]
	if got := settings.headers.Get("Originator"); got != "" {
		t.Errorf("wham/settings/user sent originator=%q; the row sends none", got)
	}
	if got := settings.headers.Get("Cache-Control"); got != "no-cache, no-store" {
		t.Errorf("wham/settings/user cache-control=%q, want %q", got, "no-cache, no-store")
	}
	mcp := byPath["/backend-api/ps/mcp"]
	if got := mcp.headers.Get("X-Openai-Product-Sku"); got != "codex" {
		t.Errorf("ps/mcp x-openai-product-sku=%q, want codex", got)
	}
	if got := mcp.headers.Get("Accept"); got != mcpAccept {
		t.Errorf("ps/mcp accept=%q, want %q", got, mcpAccept)
	}
	models := byPath["/backend-api/codex/models"]
	if got := models.headers.Get("Version"); got != desktopVersion {
		t.Errorf("codex/models version=%q, want %q", got, desktopVersion)
	}
	// Every backend-api call carries the account bearer and account id.
	for path, c := range byPath {
		if !strings.HasPrefix(path, backendAPI) {
			continue
		}
		if !strings.HasPrefix(c.headers.Get("Authorization"), "Bearer ") {
			t.Errorf("%s: missing bearer", path)
		}
		if c.headers.Get("Chatgpt-Account-Id") == "" {
			t.Errorf("%s: missing chatgpt-account-id", path)
		}
	}
}

// TestOTLPCarriesNoBearer — the metrics endpoint authenticates with the
// publishable statsig key and nothing else. An Authorization header there is a
// header no genuine exporter sends.
func TestOTLPCarriesNoBearer(t *testing.T) {
	rec := &recorder{}
	m, _ := newTestManager(t, rec, 0.02)
	a := newOAuthAuth("otlp")
	m.Notify(a, "client-A")
	if !waitForCalls(rec, 11, 5*time.Second) {
		t.Fatalf("bootstrap incomplete")
	}
	sess, _ := m.sessions.Load(a.AccountKey())
	if err := m.exportOTLP(t.Context(), a, sess.(*session)); err != nil {
		t.Fatalf("export: %v", err)
	}
	for _, c := range rec.snapshot() {
		if c.path != "/otlp/v1/metrics" {
			continue
		}
		if c.headers.Get("Authorization") != "" {
			t.Error("otlp export carried an Authorization header")
		}
		if c.headers.Get("Chatgpt-Account-Id") != "" {
			t.Error("otlp export carried chatgpt-account-id")
		}
		if got := c.headers.Get("Statsig-Api-Key"); got != statsigAPIKey {
			t.Errorf("otlp statsig-api-key=%q, want %q", got, statsigAPIKey)
		}
		return
	}
	t.Fatal("no otlp export recorded")
}

// TestAPIKeyCredentialEmitsNothing — a real Codex Desktop on a raw API key
// emits none of this traffic: no plugin store, no wham settings, no ChatGPT
// account. Emitting it advertises a subscription client that does not exist.
func TestAPIKeyCredentialEmitsNothing(t *testing.T) {
	rec := &recorder{}
	m, _ := newTestManager(t, rec, 0.02)

	apiKey := newOAuthAuth("apikey")
	apiKey.Kind = auth.KindAPIKey
	m.Notify(apiKey, "client-A")

	time.Sleep(400 * time.Millisecond)
	if n := rec.count(); n != 0 {
		t.Fatalf("API-key credential produced %d sidecar calls, want 0", n)
	}
	if _, ok := m.sessions.Load(apiKey.AccountKey()); ok {
		t.Fatal("API-key credential created a session")
	}
	if err := m.RecordTurn(apiKey, "client-A", validObservation()); err != ErrNotEligible {
		t.Fatalf("RecordTurn on API key: got %v, want ErrNotEligible", err)
	}
}

// TestAnthropicCredentialEmitsNothing — every endpoint here is
// chatgpt.com/backend-api. Without the provider guard an Anthropic OAuth
// credential would send the whole Codex plugin-store burst signed with an
// Anthropic access token.
func TestAnthropicCredentialEmitsNothing(t *testing.T) {
	rec := &recorder{}
	m, _ := newTestManager(t, rec, 0.02)

	anthropic := newOAuthAuth("anthropic")
	anthropic.Provider = auth.ProviderAnthropic
	m.Notify(anthropic, "client-A")

	time.Sleep(400 * time.Millisecond)
	if n := rec.count(); n != 0 {
		t.Fatalf("Anthropic credential produced %d Codex sidecar calls, want 0", n)
	}
	if err := m.RecordTurn(anthropic, "client-A", validObservation()); err != ErrNotEligible {
		t.Fatalf("RecordTurn on Anthropic auth: got %v, want ErrNotEligible", err)
	}
}

// TestDisabledManagerIsInert — the zero-config path must start no goroutines
// and touch no network.
func TestDisabledManagerIsInert(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(rec.handler())
	defer srv.Close()
	m := New(Config{Enabled: false, BaseURL: srv.URL})
	defer m.Stop()
	m.httpClient = srv.Client()

	a := newOAuthAuth("off")
	m.Notify(a, "client-A")
	if err := m.RecordTurn(a, "client-A", validObservation()); err != nil {
		t.Fatalf("RecordTurn on disabled manager: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	if n := rec.count(); n != 0 {
		t.Fatalf("disabled manager emitted %d calls", n)
	}
}

// TestSecondClientTokenDoesNotRelaunch — one ChatGPT account is one
// installation. A second downstream client token is another window of the same
// app, not a second launch, so it must not re-fire the bootstrap burst.
func TestSecondClientTokenDoesNotRelaunch(t *testing.T) {
	rec := &recorder{}
	m, _ := newTestManager(t, rec, 0.02)
	a := newOAuthAuth("shared")

	m.Notify(a, "client-A")
	if !waitForCalls(rec, 11, 5*time.Second) {
		t.Fatalf("first bootstrap incomplete: %d", rec.count())
	}
	after := rec.count()
	m.Notify(a, "client-B")
	m.Notify(a, "client-C")
	time.Sleep(300 * time.Millisecond)

	// Anything new must be steady-state polling, never a second ladder: a
	// second ps/mcp initialize is the specific tell.
	initializes := 0
	for _, c := range rec.snapshot() {
		if c.path == "/backend-api/ps/mcp" && strings.Contains(c.body, `"initialize"`) {
			initializes++
		}
	}
	if initializes != 1 {
		t.Fatalf("got %d ps/mcp initialize calls across 3 client tokens, want 1 (calls before=%d now=%d)",
			initializes, after, rec.count())
	}
}

// TestRateFloorBlocksAboveCapturedCadence — the floor is the backstop that
// makes "one account is never noisier than one genuine Desktop" true
// regardless of how the schedulers behave.
func TestRateFloorBlocksAboveCapturedCadence(t *testing.T) {
	b := newRateBudget()
	now := time.Now()
	for ep, min := range capturedMinInterval {
		if !b.allow(ep, now) {
			t.Fatalf("%s: first call rejected", ep)
		}
		if b.allow(ep, now.Add(min-time.Millisecond)) {
			t.Errorf("%s: second call allowed after %s, floor is %s", ep, min-time.Millisecond, min)
		}
		if !b.allow(ep, now.Add(min)) {
			t.Errorf("%s: call at the floor was rejected", ep)
		}
	}
}

// TestConfiguredCadenceStaysUnderCapturedFloor — the schedule must sit below
// the ceiling, so the floor is a backstop rather than a thing that fires in
// normal operation and silently drops traffic.
func TestConfiguredCadenceStaysUnderCapturedFloor(t *testing.T) {
	configured := map[string]time.Duration{
		epPluginsInstalled: pollPluginsInstalled,
		epPluginsList:      pollPluginsList,
		epPluginsFeatured:  pollPluginsFeatured,
		epPluginsSuggested: pollPluginsSuggested,
		epCodexModels:      pollCodexModels,
		epMCP:              pollMCPRefresh,
		epSettingsUser:     pollSettingsUser,
		epOTLP:             otlpExportInterval,
	}
	for ep, iv := range configured {
		floor, ok := capturedMinInterval[ep]
		if !ok {
			t.Fatalf("%s has no captured floor", ep)
		}
		if iv < floor {
			t.Errorf("%s: configured interval %s is faster than the captured cadence %s", ep, iv, floor)
		}
	}
	// Every endpoint with a floor must be reachable only through a call that
	// declares it, or the floor is decorative.
	declared := map[string]bool{}
	for _, c := range []call{
		pluginsInstalledCall(), pluginsListCall(), pluginsFeaturedCall(),
		pluginsSuggestedCall(), codexModelsCall(), settingsUserCall(),
		mcpInitializeCall(),
	} {
		declared[c.endpoint] = true
	}
	// epOTLP and epAnalytics are reserved explicitly by their senders.
	declared[epOTLP] = true
	declared[epAnalytics] = true
	for ep := range capturedMinInterval {
		if !declared[ep] {
			t.Errorf("endpoint %s has a floor but no call declares it", ep)
		}
	}
}

// TestStopCancelsSessions — shutdown must not leave goroutines polling.
func TestStopCancelsSessions(t *testing.T) {
	rec := &recorder{}
	m, _ := newTestManager(t, rec, 0.02)
	a := newOAuthAuth("stop")
	m.Notify(a, "client-A")
	if !waitForCalls(rec, 5, 5*time.Second) {
		t.Fatalf("bootstrap did not start")
	}
	m.Stop()
	time.Sleep(100 * time.Millisecond)
	before := rec.count()
	time.Sleep(600 * time.Millisecond) // several scaled poll intervals
	if after := rec.count(); after != before {
		t.Fatalf("calls continued after Stop: %d → %d", before, after)
	}
}
