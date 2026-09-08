package mimicry

import (
	"bytes"
	"errors"
)

// Building a `response.create` frame from an HTTP-shaped Responses body.
//
// The two Codex transports carry the SAME request in two envelopes. The HTTP
// path POSTs the Responses body as-is; the WebSocket path sends that body's
// fields spread into a frame whose first key is `"type":"response.create"`
// (crack/codexapp0.147.0/rows/15). So a proxy that accepts an HTTP request and
// wants to forward it over a WebSocket needs exactly one transformation:
// prepend that key.
//
// It is a byte splice rather than an unmarshal/marshal for the reason stated at
// length in codex_frame.go — the frame's top-level key order is stable across
// every captured frame and is part of the shape we imitate, while Go's
// map-based encoder emits keys sorted. Splicing keeps every original byte and
// puts `type` exactly where the captures put it: first.

// CodexResponseCreateType is the frame type that opens a turn on the Codex
// WebSocket transport.
const CodexResponseCreateType = "response.create"

// NewCodexResponseCreateFrame wraps a Responses request body as the
// `response.create` frame the Codex WebSocket transport expects.
//
// body must be a JSON object — the sanitized upstream body that would otherwise
// have been POSTed to /codex/responses (i.e. the output of
// SanitizeCodexRequestBody). Every byte of it is preserved in order; only the
// leading `"type":"response.create",` is added.
//
// A body that already declares a top-level `type` is returned unchanged when
// that type is already response.create, and rejected otherwise — silently
// re-typing a frame the caller meant as something else would turn a control
// message into a turn.
//
// The result still needs RewriteCodexClientFrame to bind it to the connection's
// identity; that call synthesizes the client_metadata this frame does not have
// and rebinds prompt_cache_key. Sending the output of THIS function directly
// would present a frame with no client_metadata at all, which no genuine client
// emits.
func NewCodexResponseCreateFrame(body []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || trimmed[0] != '{' || trimmed[len(trimmed)-1] != '}' {
		return nil, errors.New("mimicry: response.create frame body is not a JSON object")
	}
	switch t := codexFrameType(trimmed); t {
	case CodexResponseCreateType:
		return trimmed, nil
	case "":
		// The expected case: an HTTP Responses body, which has no `type`.
	default:
		return nil, errors.New("mimicry: refusing to re-type frame " + t + " as response.create")
	}

	const key = `"type":"` + CodexResponseCreateType + `"`
	sep := ","
	if len(bytes.TrimSpace(trimmed[1:len(trimmed)-1])) == 0 {
		// `{}` — no following member to separate from.
		sep = ""
	}
	out := make([]byte, 0, len(trimmed)+len(key)+1)
	out = append(out, '{')
	out = append(out, key...)
	out = append(out, sep...)
	out = append(out, trimmed[1:]...)
	return out, nil
}
