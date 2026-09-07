package codexsidecar

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// validObservation is a turn that could really have happened: three
// well-formed UUIDs, a model slug, and a coherent time range.
func validObservation() TurnObservation {
	start := time.Now().Add(-5 * time.Second)
	return TurnObservation{
		ThreadID:             "01a06fa9-a7f8-7c31-9a1b-2c3d4e5f6071",
		SessionID:            "01a06fa9-a7f8-7c31-9a1b-2c3d4e5f6071",
		TurnID:               "01a06fa9-a85e-7c31-9a1b-2c3d4e5f6072",
		Model:                "gpt-6-astra",
		StartedAt:            start,
		CompletedAt:          start.Add(5 * time.Second),
		InputTokens:          13753,
		CachedInputTokens:    6912,
		OutputTokens:         38,
		SamplingRequestCount: 1,
		FirstTurn:            true,
	}
}

// TestAnalyticsRefusesWithoutRealIDs is the load-bearing test of this package.
//
// The analytics envelope carries thread_id / session_id / turn_id that the
// backend can join against the /responses traffic it actually served. Ids the
// proxy invented join against nothing, which is metadata no genuine client
// could produce — strictly worse than sending nothing at all. So every one of
// these must be refused before a body exists.
func TestAnalyticsRefusesWithoutRealIDs(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*TurnObservation)
	}{
		{"missing thread_id", func(o *TurnObservation) { o.ThreadID = "" }},
		{"missing session_id", func(o *TurnObservation) { o.SessionID = "" }},
		{"missing turn_id", func(o *TurnObservation) { o.TurnID = "" }},
		{"whitespace thread_id", func(o *TurnObservation) { o.ThreadID = "   " }},
		{"thread_id is not a UUID", func(o *TurnObservation) { o.ThreadID = "thread-1" }},
		{"session_id is not a UUID", func(o *TurnObservation) { o.SessionID = "deadbeef" }},
		{"turn_id truncated", func(o *TurnObservation) { o.TurnID = "01a06fa9-a85e-7c31-9a1b-2c3d4e5f60" }},
		{"turn_id has a non-hex digit", func(o *TurnObservation) { o.TurnID = "01a06fa9-a85e-7c31-9a1b-2c3d4e5f60zz" }},
		{"parent_thread_id is not a UUID", func(o *TurnObservation) { o.ParentThreadID = "parent" }},
		{"empty model", func(o *TurnObservation) { o.Model = "" }},
		{"zero started_at", func(o *TurnObservation) { o.StartedAt = time.Time{} }},
		{"zero completed_at", func(o *TurnObservation) { o.CompletedAt = time.Time{} }},
		{"completed before started", func(o *TurnObservation) { o.CompletedAt = o.StartedAt.Add(-time.Second) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			obs := validObservation()
			tc.mutate(&obs)
			if _, err := newVerifiedTurn(obs); err == nil {
				t.Fatal("accepted an observation that cannot describe a real turn")
			} else if !errors.Is(err, errNoTurn) {
				t.Fatalf("wrong error kind: %v", err)
			}
		})
	}
	if _, err := newVerifiedTurn(validObservation()); err != nil {
		t.Fatalf("rejected a valid observation: %v", err)
	}
}

// TestRecordTurnRefusesInvalidAndSessionless asserts the refusal reaches the
// public API, not just the internal constructor.
func TestRecordTurnRefusesInvalidAndSessionless(t *testing.T) {
	rec := &recorder{}
	m, _ := newTestManager(t, rec, 0.02)
	a := newOAuthAuth("rt")

	// No Notify yet: there is no client for a turn to have happened on.
	if err := m.RecordTurn(a, "client-A", validObservation()); !errors.Is(err, ErrNoSession) {
		t.Fatalf("sessionless RecordTurn: got %v, want ErrNoSession", err)
	}

	m.Notify(a, "client-A")
	if !waitForCalls(rec, 1, 5*time.Second) {
		t.Fatal("session never started")
	}

	bad := validObservation()
	bad.TurnID = "not-a-uuid"
	if err := m.RecordTurn(a, "client-A", bad); !errors.Is(err, errNoTurn) {
		t.Fatalf("invalid RecordTurn: got %v, want errNoTurn", err)
	}
	if err := m.RecordTurn(a, "client-A", validObservation()); err != nil {
		t.Fatalf("valid RecordTurn: %v", err)
	}
}

// TestAnalyticsBodyCarriesTheObservedIDs asserts the ids that reach the wire
// are the caller's, unchanged, and that a first turn is preceded by a
// codex_thread_initialized on the same thread — the pairing the capture shows.
func TestAnalyticsBodyCarriesTheObservedIDs(t *testing.T) {
	rec := &recorder{}
	m, _ := newTestManager(t, rec, 0.02)
	a := newOAuthAuth("body")
	m.Notify(a, "client-A")
	if !waitForCalls(rec, 11, 5*time.Second) {
		t.Fatal("bootstrap incomplete")
	}
	obs := validObservation()
	if err := m.RecordTurn(a, "client-A", obs); err != nil {
		t.Fatalf("RecordTurn: %v", err)
	}
	sessAny, _ := m.sessions.Load(a.AccountKey())
	sess := sessAny.(*session)
	if err := m.flushAnalytics(t.Context(), a, sess); err != nil {
		t.Fatalf("flush: %v", err)
	}

	var body string
	for _, c := range rec.snapshot() {
		if c.path == "/backend-api/codex/analytics-events/events" {
			body = c.body
		}
	}
	if body == "" {
		t.Fatal("no analytics POST recorded")
	}
	var parsed struct {
		Events []struct {
			EventType   string         `json:"event_type"`
			EventParams map[string]any `json:"event_params"`
		} `json:"events"`
	}
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatalf("analytics body is not JSON: %v (%s)", err, body)
	}
	if len(parsed.Events) != 2 {
		t.Fatalf("got %d events, want thread_initialized + turn_event", len(parsed.Events))
	}
	if parsed.Events[0].EventType != "codex_thread_initialized" {
		t.Errorf("first event is %s", parsed.Events[0].EventType)
	}
	if parsed.Events[1].EventType != "codex_turn_event" {
		t.Errorf("second event is %s", parsed.Events[1].EventType)
	}
	for i, ev := range parsed.Events {
		if got := ev.EventParams["thread_id"]; got != obs.ThreadID {
			t.Errorf("event %d thread_id=%v, want %v", i, got, obs.ThreadID)
		}
		if got := ev.EventParams["session_id"]; got != obs.SessionID {
			t.Errorf("event %d session_id=%v, want %v", i, got, obs.SessionID)
		}
	}
	turn := parsed.Events[1].EventParams
	if got := turn["turn_id"]; got != obs.TurnID {
		t.Errorf("turn_id=%v, want %v", got, obs.TurnID)
	}
	if got := turn["root_turn_id"]; got != obs.TurnID {
		t.Errorf("root_turn_id=%v, want %v", got, obs.TurnID)
	}
	if got := turn["input_tokens"]; got != float64(obs.InputTokens) {
		t.Errorf("input_tokens=%v, want %d", got, obs.InputTokens)
	}
	// Counts a proxy cannot observe stay at the truthful zero rather than
	// being randomised to look busy.
	for _, k := range []string{"shell_command_count", "file_change_count", "mcp_tool_call_count", "web_search_count"} {
		if got := turn[k]; got != float64(0) {
			t.Errorf("%s=%v, want 0 (a proxy runs none of these)", k, got)
		}
	}
	// The telemetry must not contradict the handshake metadata cc-core sends.
	if turn["sandbox_policy"] != turnSandboxPolicy {
		t.Errorf("sandbox_policy=%v, want %v", turn["sandbox_policy"], turnSandboxPolicy)
	}
	if turn["approvals_reviewer"] != turnApprovalReviewer {
		t.Errorf("approvals_reviewer=%v", turn["approvals_reviewer"])
	}
}

// TestThreadInitializedEmittedOnce — a second turn on a known thread is a turn
// event only. Re-announcing thread creation is a shape no client produces.
func TestThreadInitializedEmittedOnce(t *testing.T) {
	rec := &recorder{}
	m, _ := newTestManager(t, rec, 0.02)
	a := newOAuthAuth("dedupe")
	m.Notify(a, "client-A")
	if !waitForCalls(rec, 1, 5*time.Second) {
		t.Fatal("session never started")
	}
	first := validObservation()
	second := validObservation()
	second.TurnID = "01a06fa9-a85e-7c31-9a1b-2c3d4e5f6099"
	second.FirstTurn = false
	if err := m.RecordTurn(a, "client-A", first); err != nil {
		t.Fatal(err)
	}
	if err := m.RecordTurn(a, "client-A", second); err != nil {
		t.Fatal(err)
	}
	sessAny, _ := m.sessions.Load(a.AccountKey())
	sess := sessAny.(*session)
	if got := len(sess.events); got != 3 {
		t.Fatalf("queued %d events, want 3 (one thread_initialized + two turns)", got)
	}
}

// TestSubagentTurnCarriesParentThread — a guardian-review thread differs from
// an ordinary one in three linked fields; they move together or not at all
// (crack/codexapp0.153.4/rows/30-post-analytics-events-02.json).
func TestSubagentTurnCarriesParentThread(t *testing.T) {
	obs := validObservation()
	obs.ParentThreadID = "01a06fa9-a7f8-7c31-9a1b-2c3d4e5f6071"
	obs.ThreadID = "01a06fa9-a900-7c31-9a1b-2c3d4e5f6073"
	turn, err := newVerifiedTurn(obs)
	if err != nil {
		t.Fatalf("valid subagent turn rejected: %v", err)
	}
	ev := buildThreadInitializedEvent(newOAuthAuth("sub"), turn)
	params := ev["event_params"].(map[string]any)
	if params["parent_thread_id"] != obs.ParentThreadID {
		t.Errorf("parent_thread_id=%v", params["parent_thread_id"])
	}
	if params["thread_source"] != "guardian_review" {
		t.Errorf("thread_source=%v, want guardian_review", params["thread_source"])
	}
	if params["subagent_source"] != "guardian" {
		t.Errorf("subagent_source=%v, want guardian", params["subagent_source"])
	}

	plain, _ := newVerifiedTurn(validObservation())
	plainParams := buildThreadInitializedEvent(newOAuthAuth("plain"), plain)["event_params"].(map[string]any)
	if plainParams["parent_thread_id"] != nil {
		t.Errorf("plain thread parent_thread_id=%v, want JSON null", plainParams["parent_thread_id"])
	}
	if plainParams["thread_source"] != turnThreadSource {
		t.Errorf("plain thread_source=%v", plainParams["thread_source"])
	}
}

// TestAnalyticsRuntimeMatchesOTLPHost — the analytics runtime block and the
// OTLP resource block describe the same machine. A client whose telemetry says
// Arch while its metrics say Ubuntu is self-contradictory.
func TestAnalyticsRuntimeMatchesOTLPHost(t *testing.T) {
	for _, id := range []string{"h1", "h2", "h3", "h4", "h5", "h6", "h7", "h8"} {
		a := newOAuthAuth(id)
		host := osAttrsFor(a)
		rt := runtimeBlock(a)
		want := strings.ReplaceAll(host.Version, "_", " ")
		if rt["runtime_os_version"] != want {
			t.Errorf("%s: runtime_os_version=%v, otlp os_version=%q", id, rt["runtime_os_version"], host.Version)
		}
	}
}
