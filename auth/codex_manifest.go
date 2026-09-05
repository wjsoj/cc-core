package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/wjsoj/cc-core/mimicry"
)

// Codex model manifest — what a Codex client reads to populate its model picker.
//
// A Codex client pointed at a third-party gateway does NOT use the plain
// OpenAI `/v1/models` listing. It refreshes its picker from one of two routes,
// both of which must answer with the ChatGPT backend's own manifest shape:
//
//	GET {base_url}/models?client_version=<ver>   — custom provider mode
//	                                               (config.toml model_providers)
//	GET /backend-api/codex/models?client_version=<ver>
//	                                             — chatgpt_base_url mode
//
// The distinguishing signal on the first route is the presence of the
// `client_version` query parameter, which no OpenAI-API client sends. See
// CodexModelsRequest.
//
// The shape is `{"models":[{slug, display_name, visibility, priority,
// minimal_client_version, supported_reasoning_levels, context_window, …}]}` —
// NOT `{"object":"list","data":[{"id":…}]}`. A gateway that answers the plain
// OpenAI list here does not fail loudly: the client cannot parse it, falls back
// to the model set compiled into that build, and the user simply never sees any
// model the gateway added after their CLI was released. That is precisely how
// gpt-6-astra stayed invisible.
//
// Two ways to produce the manifest, in this package:
//
//   - FetchCodexModelsManifest proxies the real thing from upstream using an
//     OAuth credential. Preferred, and self-maintaining: a model the backend
//     adds tomorrow appears without a code change here.
//   - SynthesizeCodexModelsManifest builds one from CodexModelCatalog for
//     deployments with no OAuth credential to borrow (API-key-only), or when
//     upstream is unreachable.

const codexModelsURL = "https://chatgpt.com/backend-api/codex/models"

// CodexModelsRequest reports whether an incoming /v1/models request came from a
// Codex client and therefore wants the manifest rather than the OpenAI list.
//
// The test is the PRESENCE of client_version, not its value: the real client
// sends `?client_version=0.153.4`, and CLIProxyAPI's own handler keys on
// presence alone (its tests exercise a bare `?client_version` with no value),
// so an empty value still means "a Codex client is asking".
func CodexModelsRequest(query map[string][]string) (clientVersion string, ok bool) {
	v, present := query["client_version"]
	if !present {
		return "", false
	}
	if len(v) > 0 {
		clientVersion = strings.TrimSpace(v[0])
	}
	return clientVersion, true
}

// FetchCodexModelsManifest GETs the upstream Codex model catalog with an OAuth
// credential and returns the response body verbatim.
//
// Verbatim matters. The payload is ~400 KB of per-model capability flags,
// instruction templates and plan lists whose schema the backend revises without
// notice; decoding it into a struct here would silently drop every field this
// package does not yet know about, and those fields are exactly what the client
// needs. It is raw bytes in and raw bytes out.
//
// The request identity is the models-fetch profile, which is NOT the one the
// WebSocket handshake uses: the capture shows the CLI sending originator
// `codex_cli_rs` with a User-Agent that omits the trailing
// "(codex-tui; <ver>)" parenthetical on this endpoint specifically
// (crack/codexv0.153.4/SPEC.md §1, trap 3). Sending the handshake's UA here
// would pair an originator with a User-Agent no genuine client emits.
func FetchCodexModelsManifest(ctx context.Context, a *Auth, clientVersion string, useUTLS bool) ([]byte, error) {
	if a == nil {
		return nil, fmt.Errorf("nil auth")
	}
	if a.Kind != KindOAuth {
		return nil, fmt.Errorf("codex models manifest requires an OAuth credential (got %v)", a.Kind)
	}
	if NormalizeProvider(a.Provider) != ProviderOpenAI {
		return nil, fmt.Errorf("codex models manifest is OpenAI-only (auth is %s)", a.Provider)
	}
	if err := a.EnsureFresh(ctx, 5*time.Minute, useUTLS); err != nil {
		return nil, fmt.Errorf("token refresh: %w", err)
	}
	token, _ := a.Credentials()
	if token == "" {
		return nil, fmt.Errorf("no access token after refresh")
	}

	if clientVersion == "" {
		clientVersion = mimicry.DefaultCodexProfile().ModelsClientVersion
	}
	endpoint := codexModelsURL + "?client_version=" + neturl.QueryEscape(clientVersion)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Originator", mimicry.CodexModelsOriginator)
	req.Header.Set("User-Agent", mimicry.CodexModelsUserAgent)
	req.Header.Set("Version", clientVersion)
	if accountID, _ := a.CodexIdentity(); accountID != "" {
		req.Header.Set("Chatgpt-Account-Id", accountID)
	}

	resp, err := ClientFor(a.ProxyURL, useUTLS).Do(req)
	if err != nil {
		return nil, fmt.Errorf("codex/models GET: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// 4 MB ceiling: the observed payload is ~400 KB, so this is ten times the
	// real thing and still bounded against a hostile or broken upstream.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("codex/models read: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("codex/models http %d: %s", resp.StatusCode, truncateForErr(body))
	}
	if !json.Valid(body) {
		// A 200 carrying HTML is how a captive portal or a dead relay presents
		// itself; serving that to a Codex client would wedge its picker.
		return nil, fmt.Errorf("codex/models returned non-JSON (%d bytes): %s", len(body), truncateForErr(body))
	}
	return body, nil
}

func truncateForErr(b []byte) string {
	const max = 160
	s := strings.TrimSpace(string(b))
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}

// SynthesizeCodexModelsManifest builds a manifest from the static per-plan
// catalog, for a deployment with no OAuth credential to borrow one from.
//
// It carries the capability fields a client needs to render and select a model,
// and deliberately omits `model_messages` / `base_instructions` — those are tens
// of KB of prose per model that only the real backend can author, and a client
// that does not receive them falls back to the prompts compiled into its own
// build, which is the correct degradation. Everything here is structural.
//
// Ordering follows the catalog slice, which is ordered flagship-first, and the
// priority field is assigned from that order so a client sorting by priority
// agrees with a client preserving wire order.
func SynthesizeCodexModelsManifest(models []string, clientVersion string) []byte {
	entries := make([]map[string]any, 0, len(models))
	for i, slug := range models {
		spec := codexModelSpecFor(slug)
		if !codexClientAtLeast(clientVersion, spec.minimalClientVersion) {
			continue
		}
		entries = append(entries, map[string]any{
			"slug":                         slug,
			"display_name":                 spec.displayName,
			"description":                  spec.description,
			"visibility":                   "list",
			"priority":                     i + 1,
			"minimal_client_version":       spec.minimalClientVersion,
			"supported_in_api":             true,
			"prefer_websockets":            true,
			"use_responses_lite":           spec.responsesLite,
			"context_window":               spec.contextWindow,
			"max_context_window":           spec.maxContextWindow,
			"default_reasoning_level":      spec.defaultReasoning,
			"supported_reasoning_levels":   codexReasoningLevelsFor(spec.reasoningLevels, clientVersion),
			"input_modalities":             []string{"text", "image"},
			"supports_parallel_tool_calls": true,
			"shell_type":                   "shell_command",
			"apply_patch_tool_type":        "freeform",
			"tool_mode":                    "code_mode_only",
			"truncation_policy":            map[string]any{"mode": "tokens", "limit": 10000},
		})
	}
	out, err := json.Marshal(map[string]any{"models": entries})
	if err != nil {
		// The map is built from strings and ints here, so this cannot fail;
		// return an empty-but-valid manifest rather than nil if it somehow does.
		return []byte(`{"models":[]}`)
	}
	return out
}

type codexModelSpec struct {
	displayName          string
	description          string
	minimalClientVersion string
	contextWindow        int
	maxContextWindow     int
	defaultReasoning     string
	reasoningLevels      []string
	responsesLite        bool
}

// codexModelSpecs holds the structural facts for the slugs this gateway
// advertises, transcribed from crack/codexv0.153.4/rows/01-get-codex-models.json.
// A slug with no entry falls back to a conservative default rather than being
// dropped, so a model added to CodexModelCatalog is never silently invisible.
var codexModelSpecs = map[string]codexModelSpec{
	"gpt-6-astra": {
		displayName: "GPT-6-Astra", description: "Our most capable model for complex, demanding work.",
		minimalClientVersion: "0.153.0", contextWindow: 272000, maxContextWindow: 872000,
		defaultReasoning: "medium",
		reasoningLevels:  []string{"low", "medium", "high", "xhigh", "max", "ultra"},
		responsesLite:    true,
	},
	"gpt-5.6-sol": {
		displayName: "GPT-5.6-Sol", description: "Reliable agentic workhorse for everyday tasks.",
		minimalClientVersion: "0.144.0", contextWindow: 272000, maxContextWindow: 872000,
		defaultReasoning: "low",
		reasoningLevels:  []string{"low", "medium", "high", "xhigh", "max", "ultra"},
		responsesLite:    true,
	},
	"gpt-5.6-terra": {
		displayName: "GPT-5.6-Terra", description: "Balances capability against cost.",
		minimalClientVersion: "0.144.0", contextWindow: 272000, maxContextWindow: 872000,
		defaultReasoning: "medium",
		reasoningLevels:  []string{"low", "medium", "high", "xhigh", "max"},
		responsesLite:    true,
	},
	"gpt-5.6-luna": {
		displayName: "GPT-5.6-Luna", description: "Cost-sensitive, high-volume workloads.",
		minimalClientVersion: "0.144.0", contextWindow: 272000, maxContextWindow: 872000,
		defaultReasoning: "low",
		reasoningLevels:  []string{"low", "medium", "high", "xhigh", "max"},
		responsesLite:    true,
	},
	"gpt-5.5": {
		displayName: "GPT-5.5", description: "Proven previous-generation model for coding and general work.",
		minimalClientVersion: "0.124.0", contextWindow: 272000, maxContextWindow: 272000,
		defaultReasoning: "medium",
		reasoningLevels:  []string{"low", "medium", "high", "xhigh"},
	},
	"gpt-5.4-mini": {
		displayName: "GPT-5.4-Mini", description: "Fast and affordable.",
		minimalClientVersion: "0.98.0", contextWindow: 272000, maxContextWindow: 272000,
		defaultReasoning: "medium",
		reasoningLevels:  []string{"low", "medium", "high"},
	},
	"gpt-5.3-codex-spark": {
		displayName: "GPT-5.3-Codex-Spark", description: "Research preview.",
		minimalClientVersion: "0.100.0", contextWindow: 272000, maxContextWindow: 272000,
		defaultReasoning: "medium",
		reasoningLevels:  []string{"low", "medium", "high"},
	},
}

func codexModelSpecFor(slug string) codexModelSpec {
	if spec, ok := codexModelSpecs[slug]; ok {
		return spec
	}
	return codexModelSpec{
		displayName:      codexDisplayNameFor(slug),
		description:      "",
		contextWindow:    272000,
		maxContextWindow: 272000,
		defaultReasoning: "medium",
		reasoningLevels:  []string{"low", "medium", "high"},
	}
}

func codexDisplayNameFor(slug string) string {
	parts := strings.Split(slug, "-")
	for i, p := range parts {
		if p == "" {
			continue
		}
		if p == "gpt" {
			parts[i] = "GPT"
			continue
		}
		parts[i] = strings.ToUpper(p[:1]) + p[1:]
	}
	return strings.Join(parts, "-")
}

// codexExtendedReasoningLevels are the efforts only newer clients understand.
// A client below the floor that receives one refuses to render the model at
// all, so they are filtered rather than passed through.
var codexExtendedReasoningLevels = map[string]bool{"xhigh": true, "max": true, "ultra": true}

const codexExtendedReasoningFloor = "0.144.0"

func codexReasoningLevelsFor(levels []string, clientVersion string) []map[string]any {
	extended := codexClientAtLeast(clientVersion, codexExtendedReasoningFloor)
	out := make([]map[string]any, 0, len(levels))
	for _, l := range levels {
		if !extended && codexExtendedReasoningLevels[l] {
			continue
		}
		out = append(out, map[string]any{"effort": l})
	}
	return out
}

// codexClientAtLeast reports whether clientVersion is at or above floor. An
// unparseable or absent client version is treated as new enough: the client did
// not tell us, and withholding models from it is the worse failure.
func codexClientAtLeast(clientVersion, floor string) bool {
	if strings.TrimSpace(floor) == "" {
		return true
	}
	cmp, ok := compareCodexVersions(clientVersion, floor)
	if !ok {
		return true
	}
	return cmp >= 0
}

func compareCodexVersions(a, b string) (int, bool) {
	na, nb := parseCodexVersion(a), parseCodexVersion(b)
	if len(na) == 0 || len(nb) == 0 {
		return 0, false
	}
	n := len(na)
	if len(nb) > n {
		n = len(nb)
	}
	for i := 0; i < n; i++ {
		var x, y int
		if i < len(na) {
			x = na[i]
		}
		if i < len(nb) {
			y = nb[i]
		}
		if x != y {
			if x < y {
				return -1, true
			}
			return 1, true
		}
	}
	return 0, true
}

// parseCodexVersion reads the leading dotted-numeric run, stopping at the first
// pre-release separator — Codex Desktop reports "0.147.0-alpha.6.6" and the
// suffix must not make the whole version unparseable.
func parseCodexVersion(v string) []int {
	v = strings.TrimSpace(v)
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil
		}
		out = append(out, n)
	}
	return out
}

// FilterCodexManifest drops models the requesting client is too old to use and
// trims reasoning levels it would not understand.
//
// Upstream already filters by the account's plan, but NOT by the caller's
// version — the manifest is fetched once with whatever version the gateway
// reports and then served to every client, so a 0.140 CLI would otherwise be
// offered gpt-6-astra, which its build cannot select. `minimal_client_version`
// is the backend's own declaration of that floor, so it is the field to honour.
//
// Unparseable input is returned unchanged: serving the upstream manifest as-is
// is strictly better than serving nothing.
func FilterCodexManifest(raw []byte, clientVersion string) []byte {
	if strings.TrimSpace(clientVersion) == "" {
		return raw
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return raw
	}
	list, ok := payload["models"].([]any)
	if !ok {
		return raw
	}
	kept := make([]any, 0, len(list))
	for _, item := range list {
		entry, ok := item.(map[string]any)
		if !ok {
			kept = append(kept, item)
			continue
		}
		floor, _ := entry["minimal_client_version"].(string)
		if !codexClientAtLeast(clientVersion, floor) {
			continue
		}
		filterCodexEntryReasoning(entry, clientVersion)
		kept = append(kept, entry)
	}
	payload["models"] = kept
	out, err := json.Marshal(payload)
	if err != nil {
		return raw
	}
	return out
}

func filterCodexEntryReasoning(entry map[string]any, clientVersion string) {
	if codexClientAtLeast(clientVersion, codexExtendedReasoningFloor) {
		return
	}
	levels, ok := entry["supported_reasoning_levels"].([]any)
	if !ok {
		return
	}
	kept := make([]any, 0, len(levels))
	for _, l := range levels {
		lvl, ok := l.(map[string]any)
		if !ok {
			kept = append(kept, l)
			continue
		}
		effort, _ := lvl["effort"].(string)
		if codexExtendedReasoningLevels[effort] {
			continue
		}
		kept = append(kept, l)
	}
	// An empty array is emitted rather than dropped: a client that reads a
	// missing key as "no constraint" and an empty one as "no levels" behaves
	// differently, and upstream sends the key unconditionally.
	entry["supported_reasoning_levels"] = kept
	if effort, _ := entry["default_reasoning_level"].(string); codexExtendedReasoningLevels[effort] {
		entry["default_reasoning_level"] = "high"
	}
}

// CodexManifestCache serves one manifest per client version, refreshing it in
// the background rather than on the request path.
//
// The picker refresh happens at client start, so several clients tend to ask at
// once; a cache miss must not turn into N upstream fetches, and an upstream
// hiccup must not empty a picker that was fine a second ago. Hence: singleflight
// per version, a TTL, and — deliberately — a stale entry is served forever if
// refreshes keep failing. Model catalogs change on the order of weeks, so stale
// is always the better answer than empty.
type CodexManifestCache struct {
	TTL time.Duration

	mu      sync.Mutex
	entries map[string]*codexManifestEntry
}

type codexManifestEntry struct {
	mu        sync.Mutex
	body      []byte
	fetchedAt time.Time
	lastErr   error
}

// Get returns the manifest for clientVersion, calling fetch at most once per
// TTL per version. fetch is only consulted when there is nothing cached or the
// entry has expired; if it fails and something is cached, the cached body wins
// and the error is reported alongside it so the caller can log it.
func (c *CodexManifestCache) Get(clientVersion string, fetch func() ([]byte, error)) ([]byte, error) {
	if c == nil {
		return fetch()
	}
	ttl := c.TTL
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}

	c.mu.Lock()
	if c.entries == nil {
		c.entries = make(map[string]*codexManifestEntry)
	}
	entry, ok := c.entries[clientVersion]
	if !ok {
		entry = &codexManifestEntry{}
		c.entries[clientVersion] = entry
	}
	c.mu.Unlock()

	// Per-version lock: one fetch in flight for this version, and a concurrent
	// request for a DIFFERENT version is not blocked behind it.
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.body != nil && time.Since(entry.fetchedAt) < ttl {
		return entry.body, nil
	}
	body, err := fetch()
	if err != nil {
		entry.lastErr = err
		if entry.body != nil {
			// Stale beats empty.
			return entry.body, err
		}
		return nil, err
	}
	entry.body, entry.fetchedAt, entry.lastErr = body, time.Now(), nil
	return body, nil
}

// Invalidate drops every cached manifest, e.g. after the credential pool
// changes and a different plan tier may now be reachable.
func (c *CodexManifestCache) Invalidate() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.entries = nil
	c.mu.Unlock()
}

// CodexManifestSlugs lists the model slugs in a manifest, in wire order. Used
// to fold a manifest back into the plain OpenAI /v1/models listing so both
// routes agree about what exists.
func CodexManifestSlugs(raw []byte) []string {
	var payload struct {
		Models []struct {
			Slug string `json:"slug"`
		} `json:"models"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil
	}
	out := make([]string, 0, len(payload.Models))
	for _, m := range payload.Models {
		if s := strings.TrimSpace(m.Slug); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// SortCodexSlugs orders slugs newest-family-first for the plain OpenAI listing,
// where there is no priority field to carry the intent.
func SortCodexSlugs(slugs []string) {
	sort.SliceStable(slugs, func(i, j int) bool { return slugs[i] > slugs[j] })
}
