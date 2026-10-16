package mimicry

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestClaudeSecurityMonitorModelAwareBudgets(t *testing.T) {
	for _, tc := range []struct {
		model          string
		total, attempt time.Duration
	}{
		{"claude-sonnet-5", 55 * time.Second, 20 * time.Second},
		{"claude-sonnet-5[1m]", 55 * time.Second, 20 * time.Second},
		{"claude-opus-5-5", 120 * time.Second, 0},
		{"claude-fable-5-1", 120 * time.Second, 0},
		{"claude-sonnet-4-6", 120 * time.Second, 0},
	} {
		var request map[string]any
		_ = json.Unmarshal(monitorStageOneFixture(true), &request)
		request["model"] = tc.model
		body, _ := json.Marshal(request)
		original := bytes.Clone(body)
		total, attempt := ClaudeSecurityMonitorBudgets(body)
		if total != tc.total || attempt != tc.attempt {
			t.Fatalf("%s budgets %s/%s", tc.model, total, attempt)
		}
		if !bytes.Equal(body, original) {
			t.Fatal("budget selection changed the request")
		}
		ctx, cancel := ClaudeSecurityMonitorAttemptContext(context.Background(), body)
		deadline, hasDeadline := ctx.Deadline()
		cancel()
		if attempt == 0 && hasDeadline {
			t.Fatalf("%s received a new attempt deadline", tc.model)
		}
		if attempt > 0 && (!hasDeadline || time.Until(deadline) > attempt || time.Until(deadline) < attempt-time.Second) {
			t.Fatal("incorrect probe attempt deadline")
		}
		request["max_tokens"] = 65
		ordinary, _ := json.Marshal(request)
		if total, attempt = ClaudeSecurityMonitorBudgets(ordinary); total != 0 || attempt != 0 {
			t.Fatal("non-stage-one request received a budget")
		}
	}
}

func TestClaudeSecurityMonitorAttemptRespectsParent(t *testing.T) {
	var request map[string]any
	_ = json.Unmarshal(monitorStageOneFixture(true), &request)
	request["model"] = "claude-sonnet-5"
	body, _ := json.Marshal(request)
	parent, release := context.WithTimeout(context.Background(), time.Second)
	defer release()
	expected, _ := parent.Deadline()
	child, cancel := ClaudeSecurityMonitorAttemptContext(parent, body)
	defer cancel()
	actual, _ := child.Deadline()
	if !actual.Equal(expected) {
		t.Fatal("attempt extended caller deadline")
	}
	release()
	if child.Err() != context.Canceled {
		t.Fatal("caller cancellation did not reach attempt")
	}
}
