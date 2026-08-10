// Package codexerr classifies the error events the ChatGPT Codex backend sends
// inside an otherwise-200 SSE stream, so a proxy can tell "this credential is
// having a bad minute" apart from "this request was never going to work".
//
// The distinction matters because of how the real client reacts. In
// codex-rs/codex-api/src/sse/responses.rs (0.147.0), an error event maps to an
// ApiError like this:
//
//	insufficient_quota / usage_not_included / cyber_policy → their own variants
//	invalid_prompt / bio_policy                            → InvalidRequest
//	server_is_overloaded / slow_down                       → ServerOverloaded
//	everything else                                        → Retryable{message, delay}
//
// ServerOverloaded is terminal for the session — the CLI stops and shows
// "Selected model is at capacity. Please try a different model." The *default*
// arm, by contrast, is `Retryable`, which the CLI backs off and retries.
//
// So a capacity-shed frame forwarded verbatim ends the user's session, while
// the same failure reported under almost any other code would have been
// retried. That is what DemoteCapacityCode exists to fix, and what Class exists
// to decide.
package codexerr

import (
	"bytes"
	"encoding/json"
)

// Class is what a proxy should do with a Codex SSE data payload.
type Class int

const (
	// ClassNone means the payload is not an error event.
	ClassNone Class = iota
	// ClassRetryable means the failure is about capacity, quota, or rate —
	// a property of the credential or the moment, not of the request. Another
	// credential (or the same one later) can plausibly serve it, so the frame
	// may be withheld from the client while the caller fails over.
	ClassRetryable
	// ClassFatal means the request itself was rejected — content policy,
	// malformed input, and anything unrecognised. Retrying on another
	// credential would fail identically, so the frame must reach the client
	// verbatim, error details intact.
	ClassFatal
)

// retryableCodes are the error codes worth failing over on. The list is a
// closed allowlist rather than a "fatal codes" denylist on purpose: an
// unrecognised code is treated as fatal and forwarded untouched, so a new
// upstream error can never be silently swallowed by the failover path. The
// cost of guessing wrong in this direction is a passed-through error; in the
// other direction it is a burned pool and a lost error message.
var retryableCodes = map[string]bool{
	"server_is_overloaded": true,
	"slow_down":            true,
	"rate_limit_exceeded":  true,
	"insufficient_quota":   true,
	"usage_not_included":   true,
}

// capacityCodes are the two codes the real CLI treats as session-terminating.
// Only these get demoted by DemoteCapacityCode.
var capacityCodes = map[string]bool{
	"server_is_overloaded": true,
	"slow_down":            true,
}

// DemotedCode is what a capacity code is rewritten to. Any value outside the
// CLI's special-cased set lands in its `Retryable` arm; "server_error" is the
// conventional generic and carries no extra meaning of its own.
const DemotedCode = "server_error"

type errFrame struct {
	Type  string `json:"type"`
	Error *struct {
		Code string `json:"code"`
	} `json:"error"`
	Response *struct {
		Error *struct {
			Code string `json:"code"`
		} `json:"error"`
	} `json:"response"`
}

// code extracts the error code from either frame shape the backend uses:
//
//	{"type":"error","error":{"code":"…"}}
//	{"type":"response.failed","response":{"error":{"code":"…"}}}
//
// ok=false means the payload carries no error at all.
func code(payload []byte) (string, bool) {
	// Cheap reject before paying for a JSON parse on every content delta.
	if !bytes.Contains(payload, []byte(`"error"`)) {
		return "", false
	}
	var f errFrame
	if json.Unmarshal(payload, &f) != nil {
		return "", false
	}
	switch {
	case f.Error != nil:
		return f.Error.Code, true
	case f.Response != nil && f.Response.Error != nil:
		return f.Response.Error.Code, true
	}
	return "", false
}

// Classify reports what to do with one SSE data payload.
//
// An error frame with no code is ClassFatal: an unidentifiable failure is
// exactly the case where guessing "retryable" would loop the pool.
func Classify(payload []byte) Class {
	c, ok := code(payload)
	if !ok {
		return ClassNone
	}
	if retryableCodes[c] {
		return ClassRetryable
	}
	return ClassFatal
}

// DemoteCapacityCode rewrites a server_is_overloaded / slow_down code to
// DemotedCode, returning the rewritten payload and true when it changed
// anything. Every other field — including the human-readable message — is left
// exactly as the upstream wrote it, so the user still sees why their request
// failed; only the CLI's dispatch code changes, turning a session-ending
// verdict into a backoff-and-retry.
//
// Use it only on frames that must reach the client (output already started, or
// a bridge with no failover left). When the caller can still fail over,
// withholding the frame is strictly better than demoting it.
//
// Callers must classify and record health/billing from the ORIGINAL payload:
// after this call the code no longer says why the request failed.
func DemoteCapacityCode(payload []byte) ([]byte, bool) {
	c, ok := code(payload)
	if !ok || !capacityCodes[c] {
		return payload, false
	}
	var obj map[string]any
	if json.Unmarshal(payload, &obj) != nil {
		return payload, false
	}
	// Rewrite in whichever shape carried the code.
	if e, isMap := obj["error"].(map[string]any); isMap {
		if _, has := e["code"]; has {
			e["code"] = DemotedCode
		}
	} else if r, isMap := obj["response"].(map[string]any); isMap {
		if e, isMap := r["error"].(map[string]any); isMap {
			if _, has := e["code"]; has {
				e["code"] = DemotedCode
			}
		}
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return payload, false
	}
	return out, true
}

// ClientFrame decides what one upstream frame should look like by the time it
// reaches the client, for a relay that has no failover left — a WebSocket
// session, or an HTTP stream that has already committed output. It reports
// whether upstream shed the turn, and whether that shed was about capacity.
//
// Withholding the frame is strictly better whenever the caller can still fail
// over; use Classify directly there. This is the other case, where the client
// must be told something: the frame is forwarded with only the two
// session-ending capacity codes demoted, so the CLI backs off and retries
// instead of ending the session, and the human-readable message survives.
//
// capacity splits ClassRetryable in half, and the split decides who is to
// blame. server_is_overloaded / slow_down are a property of the model and the
// moment — the same request would shed on any account — so nothing about the
// credential should change. Quota and rate codes ARE account-scoped, and are
// the only half worth moving a session off its credential for. They are never
// demoted: the CLI handles them non-terminally and parses its retry delay off
// the original code.
//
// Record health and billing from the ORIGINAL payload, not the returned one.
func ClientFrame(payload []byte) (out []byte, shed, capacity bool) {
	if Classify(payload) != ClassRetryable {
		return payload, false, false
	}
	demoted, isCapacity := DemoteCapacityCode(payload)
	return demoted, true, isCapacity
}
