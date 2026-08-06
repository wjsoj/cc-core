package usage

import (
	"encoding/json"
	"testing"
)

func TestEnsureOpenAIStreamUsageAddsFlag(t *testing.T) {
	body := []byte(`{"model":"gpt-5","stream":true,"messages":[]}`)
	got, err := EnsureOpenAIStreamUsage(body)
	if err != nil {
		t.Fatalf("EnsureOpenAIStreamUsage: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(got, &raw); err != nil {
		t.Fatalf("decode rewritten body: %v", err)
	}
	opts, _ := raw["stream_options"].(map[string]any)
	if opts == nil || opts["include_usage"] != true {
		t.Fatalf("include_usage not set: %s", got)
	}
}

func TestEnsureOpenAIStreamUsageForcesUsageAndPreservesOtherOptions(t *testing.T) {
	body := []byte(`{"messages":[],"stream_options":{"include_usage":false,"foo":"bar"}}`)
	got, err := EnsureOpenAIStreamUsage(body)
	if err != nil {
		t.Fatalf("EnsureOpenAIStreamUsage: %v", err)
	}
	var raw struct {
		StreamOptions map[string]any `json:"stream_options"`
	}
	if err := json.Unmarshal(got, &raw); err != nil {
		t.Fatalf("decode rewritten body: %v", err)
	}
	if raw.StreamOptions["include_usage"] != true {
		t.Fatalf("include_usage should be forced true: %s", got)
	}
	if raw.StreamOptions["foo"] != "bar" {
		t.Fatalf("existing stream option lost: %s", got)
	}
}

// A Responses API request (has `input`, no `messages`) must NOT get
// stream_options injected — /v1/responses rejects the unknown parameter with a
// 400 on strict upstreams (observed in prod: "Unknown parameter:
// 'stream_options.include_usage'"). Its usage is already carried by the
// response.completed event, so the body must pass through byte-for-byte.
func TestEnsureOpenAIStreamUsageSkipsResponsesAPI(t *testing.T) {
	body := []byte(`{"model":"gpt-5.6-sol","stream":true,"input":"hi"}`)
	got, err := EnsureOpenAIStreamUsage(body)
	if err != nil {
		t.Fatalf("EnsureOpenAIStreamUsage: %v", err)
	}
	if string(got) != string(body) {
		t.Fatalf("Responses API body must pass through unchanged; got %s", got)
	}
	var raw map[string]any
	if err := json.Unmarshal(got, &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, injected := raw["stream_options"]; injected {
		t.Fatalf("stream_options must NOT be injected into a Responses request: %s", got)
	}
}

// TestStreamOutcomeBillingPolicy is the regression barrier for the production
// incident this replaced: 233 charged rows totalling $170.28 built from
// fabricated token counts, the largest claiming 2,258,861 input tokens.
//
// The three cases below are the entire policy. If any of them starts allowing a
// charge that wasn't observed, an estimator has crept back in.
func TestStreamOutcomeBillingPolicy(t *testing.T) {
	observed := Counts{InputTokens: 120, OutputTokens: 40, Requests: 1}
	none := Counts{}

	t.Run("complete stream bills observed usage", func(t *testing.T) {
		o := ClassifyStreamOutcome(observed, false)
		if o != StreamComplete {
			t.Fatalf("outcome=%v want StreamComplete", o)
		}
		if !o.Billable(observed) {
			t.Error("a completed stream with usage must be billable")
		}
		if o.CredentialFault() {
			t.Error("a completed stream must not fault the credential")
		}
		if o.LogError() != "" {
			t.Errorf("LogError=%q want empty", o.LogError())
		}
	})

	t.Run("client cancel bills partial usage and spares the credential", func(t *testing.T) {
		o := ClassifyStreamOutcome(observed, true)
		if o != StreamClientCanceled {
			t.Fatalf("outcome=%v want StreamClientCanceled", o)
		}
		if !o.Billable(observed) {
			t.Error("usage observed before the hang-up is still owed")
		}
		if o.CredentialFault() {
			t.Error("a client hang-up must never cool the credential — this is what " +
				"turned every Ctrl-C into a spurious breaker trip")
		}
		if o.LogError() != ClientCanceledError {
			t.Errorf("LogError=%q want %q", o.LogError(), ClientCanceledError)
		}
		// Cancel before any usage arrived → nothing observed, nothing billed.
		if ClassifyStreamOutcome(none, true).Billable(none) {
			t.Error("a cancel with zero observed usage must bill nothing")
		}
	})

	t.Run("upstream without usage bills nothing and faults the credential", func(t *testing.T) {
		o := ClassifyStreamOutcome(none, false)
		if o != StreamUpstreamNoUsage {
			t.Fatalf("outcome=%v want StreamUpstreamNoUsage", o)
		}
		if o.Billable(none) {
			t.Fatal("BILLING REGRESSION: a response with no reported usage must cost $0. " +
				"The removed estimator charged $170.28 across 233 such rows.")
		}
		if !o.CredentialFault() {
			t.Error("a relay that cannot account for what it served must be cooled")
		}
		if o.LogError() != MissingUsageError {
			t.Errorf("LogError=%q want %q", o.LogError(), MissingUsageError)
		}
	})
}

// TestNoUsageEstimatorRemains guards the invariant by construction: nothing in
// this package may turn a request body into billable tokens. The audit that
// motivated the removal found the estimator overstating input by ~10× (billing
// a 92%-cached prompt at the uncached rate) while understating output by up to
// 86%. A "conservative floor" that is wrong in both directions is not
// conservative.
func TestNoUsageEstimatorRemains(t *testing.T) {
	c := Counts{}
	if !MissingUsage(c) {
		t.Fatal("zero Counts must read as missing usage")
	}
	// The classifier's inputs are the observed counts and whether the client
	// left — the request body is not among them, and must never become one.
	// A 2 MiB Codex body is exactly what produced the $11.32 row.
	if o := ClassifyStreamOutcome(c, false); o.Billable(c) || o != StreamUpstreamNoUsage {
		t.Fatal("an unobserved response must be unbillable regardless of request size")
	}
}
