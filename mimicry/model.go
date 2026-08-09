package mimicry

import (
	"encoding/json"
	"errors"
	"fmt"
)

// RewriteModelFieldPreservingBytes replaces the top-level "model" string with
// upstream, touching nothing else in the body.
//
// The obvious implementation unmarshals into a map and marshals it back, which
// reorders every top-level key alphabetically — turning the captured Claude
// Code key order (model, messages, system, tools, metadata, max_tokens,
// thinking, context_management, output_config, stream) into something no real
// client emits. On a body we are about to forward on an OAuth credential that
// is a fingerprint change, so the edit is done as a byte splice instead.
//
// It must also run BEFORE PrepareClaudeCodeRequest: the prepared result pins a
// sha256 of the body, so a model rewrite afterwards is rejected at Apply time
// rather than silently forwarded.
//
// Returns an error rather than the original body when the field is missing,
// duplicated, or not a string. A per-credential model map that cannot be
// applied means the request would reach upstream under the wrong model name,
// which is a billing question, not a cosmetic one — the caller decides.
func RewriteModelFieldPreservingBytes(body []byte, upstream string) ([]byte, error) {
	if upstream == "" {
		return nil, errors.New("empty upstream model")
	}
	span, err := requireJSONObjectMemberSpan(body, "model")
	if err != nil {
		return nil, fmt.Errorf("locate top-level model: %w", err)
	}
	var current string
	if err := json.Unmarshal(body[span.start:span.end], &current); err != nil {
		return nil, errors.New("top-level model is not a JSON string")
	}
	if current == upstream {
		return body, nil
	}
	encoded, err := json.Marshal(upstream)
	if err != nil {
		return nil, err
	}
	return applyByteReplacements(body, []byteReplacement{
		{start: span.start, end: span.end, value: encoded},
	})
}
