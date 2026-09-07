package codexsidecar

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/wjsoj/cc-core/auth"
	"github.com/wjsoj/cc-core/mimicry"
)

// TurnObservation describes a Codex turn that ACTUALLY happened upstream. It
// is the only way to get analytics traffic out of this package.
//
// Why the ceremony: POST /backend-api/codex/analytics-events/events carries
// thread_id / session_id / turn_id, and the backend can join those against its
// own record of the /responses traffic it served. Ids invented by the proxy
// join against nothing, which produces telemetry no genuine client could have
// emitted — a stronger signal than emitting no telemetry at all. So the caller
// must hand over the ids of a turn it really forwarded, and this package
// verifies their shape before any body is built (see newVerifiedTurn).
//
// Fields the proxy cannot observe are not invented here. Token counts and
// timings come from the caller (it saw the response); the client-configuration
// fields (sandbox policy, approval policy, reviewer) are NOT free-form — they
// are derived from the x-codex-turn-metadata cc-core actually sends on the
// handshake, so the telemetry and the handshake agree.
type TurnObservation struct {
	// ThreadID, SessionID and TurnID must be the ids carried on the real
	// upstream turn. All three are required and must be UUIDs.
	ThreadID  string
	SessionID string
	TurnID    string

	// ParentThreadID is set only for a subagent thread (guardian review and
	// friends); empty for an ordinary user thread.
	ParentThreadID string

	// Model is the upstream model slug actually used, e.g. "gpt-6-astra".
	Model string

	// StartedAt / CompletedAt bound the turn. Both required; CompletedAt must
	// not precede StartedAt.
	StartedAt   time.Time
	CompletedAt time.Time

	// Token counts as reported by the upstream usage block.
	InputTokens           int
	CachedInputTokens     int
	CacheWriteInputTokens int
	OutputTokens          int
	ReasoningOutputTokens int

	// SamplingRequestCount is how many upstream sampling requests the turn
	// took (1 for a single-shot turn). Zero is coerced to 1.
	SamplingRequestCount int
	// SamplingRetryCount is how many of those were retries.
	SamplingRetryCount int

	// FirstTurn reports whether this was the first turn on the thread. Drives
	// both is_first_turn and whether a codex_thread_initialized event is
	// emitted alongside the turn event.
	FirstTurn bool

	// Failed marks a turn that ended in an upstream error; ErrorKind and
	// HTTPStatus describe it. A successful turn leaves all three zero.
	Failed     bool
	ErrorKind  string
	HTTPStatus int
}

// errNoTurn is returned when analytics are requested without a real turn.
var errNoTurn = errors.New("codexsidecar: analytics event requires the ids of a turn that actually happened")

// verifiedTurn is a turn whose ids have been checked. It has no exported
// fields and exactly one constructor, so no code path outside newVerifiedTurn
// can conjure one: the event builders below take a verifiedTurn, which makes
// "analytics without real ids" unrepresentable rather than merely discouraged.
type verifiedTurn struct {
	threadID    string
	sessionID   string
	turnID      string
	parent      string
	model       string
	startedAt   time.Time
	completedAt time.Time

	inputTokens      int
	cachedInput      int
	cacheWriteInput  int
	outputTokens     int
	reasoningTokens  int
	samplingRequests int
	samplingRetries  int

	firstTurn  bool
	failed     bool
	errorKind  string
	httpStatus int
}

// newVerifiedTurn validates a TurnObservation. Every id must be a well-formed
// UUID — the genuine client's are v7, but this deliberately accepts any
// version so a caller forwarding a downstream client's own v4 is not rejected;
// what is rejected is anything that is not an id at all. The time range must
// be coherent, because started_at/completed_at land in the body as epoch
// seconds a backend can compare against when it actually served the turn.
func newVerifiedTurn(obs TurnObservation) (verifiedTurn, error) {
	ids := []struct {
		name  string
		value string
	}{
		{"thread_id", obs.ThreadID},
		{"session_id", obs.SessionID},
		{"turn_id", obs.TurnID},
	}
	for _, id := range ids {
		if strings.TrimSpace(id.value) == "" {
			return verifiedTurn{}, fmt.Errorf("%w: %s is empty", errNoTurn, id.name)
		}
		if !isUUID(id.value) {
			return verifiedTurn{}, fmt.Errorf("%w: %s %q is not a UUID", errNoTurn, id.name, id.value)
		}
	}
	if obs.ParentThreadID != "" && !isUUID(obs.ParentThreadID) {
		return verifiedTurn{}, fmt.Errorf("%w: parent_thread_id %q is not a UUID", errNoTurn, obs.ParentThreadID)
	}
	if strings.TrimSpace(obs.Model) == "" {
		return verifiedTurn{}, fmt.Errorf("%w: model is empty", errNoTurn)
	}
	if obs.StartedAt.IsZero() || obs.CompletedAt.IsZero() {
		return verifiedTurn{}, fmt.Errorf("%w: started_at/completed_at are required", errNoTurn)
	}
	if obs.CompletedAt.Before(obs.StartedAt) {
		return verifiedTurn{}, fmt.Errorf("%w: completed_at precedes started_at", errNoTurn)
	}
	sampling := obs.SamplingRequestCount
	if sampling <= 0 {
		sampling = 1
	}
	return verifiedTurn{
		threadID:         obs.ThreadID,
		sessionID:        obs.SessionID,
		turnID:           obs.TurnID,
		parent:           obs.ParentThreadID,
		model:            strings.TrimSpace(obs.Model),
		startedAt:        obs.StartedAt,
		completedAt:      obs.CompletedAt,
		inputTokens:      obs.InputTokens,
		cachedInput:      obs.CachedInputTokens,
		cacheWriteInput:  obs.CacheWriteInputTokens,
		outputTokens:     obs.OutputTokens,
		reasoningTokens:  obs.ReasoningOutputTokens,
		samplingRequests: sampling,
		samplingRetries:  obs.SamplingRetryCount,
		firstTurn:        obs.FirstTurn,
		failed:           obs.Failed,
		errorKind:        obs.ErrorKind,
		httpStatus:       obs.HTTPStatus,
	}, nil
}

// isUUID reports whether s is a canonical 8-4-4-4-12 hex UUID. Version and
// variant nibbles are not checked; shape is.
func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
			if !isHex {
				return false
			}
		}
	}
	return true
}

// appServerClient is the app_server_client block, identical in every captured
// analytics body for a stdio-transport thread (rows 30-01, 30-03, 30-04,
// 30-10). client_version is the app BUILD, not the codex-rs version.
func appServerClient() map[string]any {
	return map[string]any{
		"product_client_id":        mimicry.CodexDesktopOriginator,
		"client_name":              mimicry.CodexDesktopOriginator,
		"client_version":           desktopBuild,
		"rpc_transport":            "stdio",
		"experimental_api_enabled": true,
	}
}

// runtimeBlock is the runtime block. runtime_os_version tracks the same
// per-account host identity the OTLP resource block reports — a client whose
// telemetry says Arch while its metrics say Ubuntu is self-contradictory.
// runtime_os and runtime_arch stay fixed for the reason auth.HostProfile
// documents: we have one capture and no evidence for the shape of a non-Linux
// body.
func runtimeBlock(a *auth.Auth) map[string]any {
	os := osAttrsFor(a)
	return map[string]any{
		"codex_rs_version":   desktopVersion,
		"runtime_os":         "linux",
		"runtime_os_version": strings.ReplaceAll(os.Version, "_", " "),
		"runtime_arch":       "x86_64",
	}
}

// Turn-configuration values echoed into the analytics body. They are NOT free
// choices: each mirrors what cc-core's x-codex-turn-metadata declares on the
// handshake (mimicry.NewCodexHandshakeMetadata — workspace-write sandbox,
// auto-review on, thread_source "user"). Declaring one thing on the wire and
// another in telemetry is a self-contradiction a single join finds.
const (
	turnSandboxPolicy    = "workspace_write" // ← mimicry.CodexSandboxModeWorkspaceWrite
	turnThreadSource     = "user"            // ← handshake metadata thread_source
	turnApprovalPolicy   = "on-request"
	turnApprovalReviewer = "auto_review" // ← handshake metadata auto_review_enabled
	turnCollaboration    = "default"
	turnServiceTier      = "default"
	turnTrigger          = "composer"
	turnPersonality      = "friendly"
	turnWorkspaceKind    = "project"
	turnReasoningEffort  = "high"
	turnReasoningSummary = "detailed"
)

// buildThreadInitializedEvent renders codex_thread_initialized
// (crack/codexapp0.153.4/rows/30-post-analytics-events-01.json). Only a
// verifiedTurn can reach it, so the ids are always a real thread's.
func buildThreadInitializedEvent(a *auth.Auth, t verifiedTurn) map[string]any {
	params := map[string]any{
		"thread_id":             t.threadID,
		"session_id":            t.sessionID,
		"app_server_client":     appServerClient(),
		"runtime":               runtimeBlock(a),
		"model":                 t.model,
		"ephemeral":             false,
		"thread_source":         turnThreadSource,
		"initialization_mode":   "new",
		"subagent_source":       nil,
		"parent_thread_id":      nullableID(t.parent),
		"forked_from_thread_id": nil,
		"created_at":            t.startedAt.Unix(),
	}
	if t.parent != "" {
		params["thread_source"] = "guardian_review"
		params["subagent_source"] = "guardian"
	}
	return map[string]any{
		"event_type":   "codex_thread_initialized",
		"event_params": params,
	}
}

// buildTurnEvent renders codex_turn_event
// (crack/codexapp0.153.4/rows/30-post-analytics-events-04.json and -10, 61
// fields). Counts the proxy genuinely cannot observe — shell commands, file
// changes, MCP and dynamic tool calls, web searches, image generation — are
// emitted as 0, which is the truthful value for a proxy: it ran none of them.
// They are not randomised to look busy.
func buildTurnEvent(a *auth.Auth, t verifiedTurn) map[string]any {
	durationMS := t.completedAt.Sub(t.startedAt).Milliseconds()
	if durationMS < 0 {
		durationMS = 0
	}
	status := "completed"
	var turnError, errorKind any
	var httpStatus any
	if t.failed {
		status = "error"
		turnError = true
		if t.errorKind != "" {
			errorKind = t.errorKind
		}
		if t.httpStatus > 0 {
			httpStatus = t.httpStatus
		}
	}
	params := map[string]any{
		"thread_id":         t.threadID,
		"session_id":        t.sessionID,
		"turn_id":           t.turnID,
		"root_turn_id":      t.turnID,
		"turn_trigger":      turnTrigger,
		"codex_turn_source": nil,
		"submission_type":   nil,
		"app_server_client": appServerClient(),
		"runtime":           runtimeBlock(a),

		"ephemeral":           false,
		"thread_source":       turnThreadSource,
		"initialization_mode": "new",
		"subagent_source":     nil,
		"parent_thread_id":    nullableID(t.parent),

		"model":                  t.model,
		"model_provider":         "openai",
		"sandbox_policy":         turnSandboxPolicy,
		"reasoning_effort":       turnReasoningEffort,
		"reasoning_summary":      turnReasoningSummary,
		"service_tier":           turnServiceTier,
		"approval_policy":        turnApprovalPolicy,
		"approvals_reviewer":     turnApprovalReviewer,
		"guardian_v2_enabled":    true,
		"sandbox_network_access": false,
		"collaboration_mode":     turnCollaboration,
		"personality":            turnPersonality,
		"workspace_kind":         turnWorkspaceKind,

		"num_input_images":   0,
		"image_preparations": []any{},
		"is_first_turn":      t.firstTurn,

		"status": status,
		"explicit_client_interrupt_requested_at_ms": nil,
		"turn_error":                   turnError,
		"codex_error_kind":             errorKind,
		"codex_error_http_status_code": httpStatus,

		"steer_count":              0,
		"total_tool_call_count":    0,
		"shell_command_count":      0,
		"file_change_count":        0,
		"mcp_tool_call_count":      0,
		"dynamic_tool_call_count":  0,
		"subagent_tool_call_count": 0,
		"web_search_count":         0,
		"image_generation_count":   0,

		"input_tokens":             t.inputTokens,
		"cached_input_tokens":      t.cachedInput,
		"cache_write_input_tokens": t.cacheWriteInput,
		"output_tokens":            t.outputTokens,
		"reasoning_output_tokens":  t.reasoningTokens,
		"total_tokens":             t.inputTokens + t.outputTokens,

		"before_first_sampling_ms":     0,
		"sampling_ms":                  durationMS,
		"compaction_ms":                0,
		"between_sampling_overhead_ms": 0,
		"tool_blocking_ms":             0,
		"after_last_sampling_ms":       0,
		"sampling_request_count":       t.samplingRequests,
		"sampling_retry_count":         t.samplingRetries,
		"duration_ms":                  durationMS,
		"started_at":                   t.startedAt.Unix(),
		"completed_at":                 t.completedAt.Unix(),
	}
	if t.parent != "" {
		params["thread_source"] = "guardian_review"
		params["subagent_source"] = "guardian"
	}
	return map[string]any{
		"event_type":   "codex_turn_event",
		"event_params": params,
	}
}

// nullableID renders an empty id as JSON null, which is what the capture shows
// for an absent parent_thread_id — not an empty string.
func nullableID(s string) any {
	if s == "" {
		return nil
	}
	return s
}
