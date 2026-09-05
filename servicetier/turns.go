package servicetier

import (
	"encoding/json"
	"sync"
)

// Turn captures billing metadata independently of token counters and queued
// settlement, so a later request cannot change an earlier turn's price.
type Turn struct {
	Model     string
	Requested string
	Observed  string
}

// TurnTracker follows the ordered response.create/terminal sequence of a Codex
// connection. Writes and reads run in different goroutines. Omitted tiers reset
// to Standard on every turn; they never inherit Priority from a previous turn.
type TurnTracker struct {
	mu       sync.Mutex
	pending  []Turn
	observed string
	last     Turn
}

// Sent queues the FINAL outbound frame before writing it to the socket. False
// means malformed metadata or too many in-flight turns; the caller must not
// forward that frame. Non-response.create frames require no tracking.
func (t *TurnTracker) Sent(frame []byte) bool {
	if t == nil {
		return true
	}
	var request struct {
		Type  string `json:"type"`
		Model string `json:"model"`
		Tier  string `json:"service_tier"`
	}
	if json.Unmarshal(frame, &request) != nil {
		return false
	}
	if request.Type != "response.create" {
		return true
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.pending) >= 128 {
		return false
	}
	t.pending = append(t.pending, Turn{Model: request.Model, Requested: Normalize(request.Tier)})
	return true
}

// Observe is called on the upstream reader before response scrubbing.
func (t *TurnTracker) Observe(frame []byte) {
	if t == nil {
		return
	}
	if tier := Response(frame); tier != "" {
		t.mu.Lock()
		t.observed = tier
		t.mu.Unlock()
	}
}

// Complete freezes one turn's metadata before invoking/queuing its settlement.
func (t *TurnTracker) Complete() {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.last = Turn{Observed: t.observed}
	if len(t.pending) > 0 {
		t.last.Model, t.last.Requested = t.pending[0].Model, t.pending[0].Requested
		t.pending[0] = Turn{}
		t.pending = t.pending[1:]
	}
	t.observed = ""
}

func (t *TurnTracker) LastCompleted() Turn {
	if t == nil {
		return Turn{}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.last
}
