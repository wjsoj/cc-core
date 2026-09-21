package codexoauth

import (
	"fmt"

	"github.com/wjsoj/cc-core/apicompat"
	"github.com/wjsoj/cc-core/mimicry"
	"github.com/wjsoj/cc-core/servicetier"
)

// CodexRequest is the transport-independent OAuth request shared by both apps.
// The original client body stays with the caller for retries through API keys.
type CodexRequest struct {
	Body  []byte
	Path  string
	Model string
	Chat  bool
}

// PrepareCodexRequest builds the OAuth payload without changing the client body.
func PrepareCodexRequest(body []byte, path string) (CodexRequest, error) {
	request := CodexRequest{Path: path, Chat: path == "/v1/chat/completions"}
	switch path {
	case "/v1/chat/completions", "/v1/responses", "/v1/responses/compact":
	default:
		return request, fmt.Errorf("unsupported Codex OAuth route %q", path)
	}
	normalized, _, err := servicetier.NormalizeRequest(body)
	if err != nil {
		return request, err
	}
	if request.Chat {
		normalized, err = apicompat.ChatCompletionsToResponses(normalized)
		if err != nil {
			return request, err
		}
		request.Path = "/v1/responses"
	}
	request.Body, request.Model, err = mimicry.SanitizeCodexRequestBody(normalized, request.Path)
	return request, err
}
