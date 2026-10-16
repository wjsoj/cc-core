package mimicry

import (
	"context"
	"encoding/json"
	"strings"
	"time"
)

const (
	// ClaudeSecurityMonitorTimeout preserves the existing ceiling for fallback
	// classifiers. In particular, valid Opus fallback may take more than 20s.
	ClaudeSecurityMonitorTimeout = 120 * time.Second
	// ClaudeSecurityMonitorProbeTimeout leaves headroom under the known native
	// Sonnet probe's 60s wall-clock budget; it spans all upstream credentials.
	ClaudeSecurityMonitorProbeTimeout        = 55 * time.Second
	ClaudeSecurityMonitorProbeAttemptTimeout = 20 * time.Second
	ClaudeSecurityMonitorAttemptTimeoutCode  = "classifier_attempt_timeout"
	ClaudeSecurityMonitorAttemptTimeoutBody  = `{"type":"error","error":{"type":"api_error","message":"The classifier upstream attempt timed out."}}`
)

// ClaudeSecurityMonitorBudgets applies the short probe policy only to a strict
// stage-one request whose ORIGINAL client model is claude-sonnet-5 (optionally
// [1m]). It neither substitutes a model nor reads the credential's model map.
// Other strict monitors keep the prior total ceiling and no per-attempt limit;
// ordinary requests return zero budgets.
func ClaudeSecurityMonitorBudgets(body []byte) (total, attempt time.Duration) {
	if !IsClaudeSecurityMonitorStageOne(body) {
		return 0, 0
	}
	var request struct {
		Model string `json:"model"`
	}
	_ = json.Unmarshal(body, &request)
	model := strings.TrimSpace(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(request.Model)), "[1m]"))
	if model == "claude-sonnet-5" {
		return ClaudeSecurityMonitorProbeTimeout, ClaudeSecurityMonitorProbeAttemptTimeout
	}
	return ClaudeSecurityMonitorTimeout, 0
}

// ClaudeSecurityMonitorAttemptContext keeps the parent request context intact:
// an expired attempt may rotate credentials while the total request is alive.
// Earlier caller cancellation/deadlines always win.
func ClaudeSecurityMonitorAttemptContext(parent context.Context, body []byte) (context.Context, context.CancelFunc) {
	_, attempt := ClaudeSecurityMonitorBudgets(body)
	if attempt == 0 {
		return parent, func() {}
	}
	return context.WithTimeout(parent, attempt)
}
