// Package advisor parses the `usage.iterations[]` slice that Anthropic
// added via the `advisor-tool-2026-03-01` beta. Each iteration is one
// billable sub-call inside a single /v1/messages response:
//
//	type:"message"          → orchestrator (the model the client asked for).
//	                          Top-level usage is the SUM of these — already
//	                          accounted for; we ignore them here.
//	type:"advisor_message"  → server-side advisor call, billed under its own
//	                          model (typically claude-opus-4-7), NOT rolled
//	                          into top-level totals.
//
// In real captures advisor sub-calls always run cache-cold
// (cache_read/cache_create = 0); the four-counter parsing is kept in case
// Anthropic enables advisor caching later.
//
// # Streaming semantics
//
// SSE emits cumulative `message_delta.usage.iterations` — the slice grows
// as sub-calls complete. Use ReplaceFrom on every observation (rather than
// Merge) to overwrite the snapshot, avoiding double-counting when both
// message_start and message_delta are seen.
//
// # Scope
//
// This package is parsing + aggregation only. Charging the counts to a
// credential ledger, emitting per-model requestlog rows, and rolling
// advisor cost into a per-client weekly bill are all billing-layer concerns
// that stay in the fork.
package advisor

import (
	"strings"

	"github.com/wjsoj/cc-core/usage"
)

// IterationUsage is the wire shape of one entry in
// `message_delta.usage.iterations[]`.
type IterationUsage struct {
	Type                     string `json:"type"`
	Model                    string `json:"model"`
	InputTokens              int64  `json:"input_tokens"`
	OutputTokens             int64  `json:"output_tokens"`
	CacheCreationInputTokens int64  `json:"cache_creation_input_tokens"`
	CacheReadInputTokens     int64  `json:"cache_read_input_tokens"`
}

// IsAdvisor reports whether this iteration is a server-side advisor call
// (`type == "advisor_message"`).
func (it IterationUsage) IsAdvisor() bool { return it.Type == "advisor_message" }

// Counts converts the iteration's token counters to a usage.Counts.
// Requests is left zero — counting is the caller's responsibility.
func (it IterationUsage) Counts() usage.Counts {
	return usage.Counts{
		InputTokens:       it.InputTokens,
		OutputTokens:      it.OutputTokens,
		CacheCreateTokens: it.CacheCreationInputTokens,
		CacheReadTokens:   it.CacheReadInputTokens,
	}
}

// FallbackModel is the placeholder used when an advisor iteration has no
// model field (defensive — should never happen in practice). Charging to
// this sentinel keeps the cost visible in dashboards instead of silently
// dropping it.
const FallbackModel = "advisor-unknown"

// SubUsage aggregates advisor (and any future server-side sub-model)
// counts per sub-model name. A request with no advisor invocations has
// nil byModel; IsEmpty reports true in that case.
//
// Not goroutine-safe — assume single-stream consumption.
type SubUsage struct {
	byModel map[string]usage.Counts
}

// Merge folds one iteration into the per-model totals if it's an advisor
// call. No-op for orchestrator (`type == "message"`) iterations.
func (s *SubUsage) Merge(it IterationUsage) {
	if !it.IsAdvisor() {
		return
	}
	model := strings.TrimSpace(it.Model)
	if model == "" {
		model = FallbackModel
	}
	if s.byModel == nil {
		s.byModel = make(map[string]usage.Counts, 1)
	}
	cur := s.byModel[model]
	cur.InputTokens += it.InputTokens
	cur.OutputTokens += it.OutputTokens
	cur.CacheCreateTokens += it.CacheCreationInputTokens
	cur.CacheReadTokens += it.CacheReadInputTokens
	s.byModel[model] = cur
}

// ReplaceFrom resets the per-model totals from a full iterations slice.
// Use this for cumulative SSE observations so the snapshot exactly
// matches the latest server-emitted iterations[] (no double-counting).
func (s *SubUsage) ReplaceFrom(its []IterationUsage) {
	if len(its) == 0 {
		return
	}
	s.byModel = nil
	for _, it := range its {
		s.Merge(it)
	}
}

// IsEmpty reports true when no advisor activity has been observed.
func (s *SubUsage) IsEmpty() bool { return len(s.byModel) == 0 }

// Snapshot returns a copy of the per-model usage map. Safe to retain
// while continued SSE parsing mutates the underlying SubUsage.
func (s *SubUsage) Snapshot() map[string]usage.Counts {
	if s.byModel == nil {
		return nil
	}
	out := make(map[string]usage.Counts, len(s.byModel))
	for k, v := range s.byModel {
		out[k] = v
	}
	return out
}
