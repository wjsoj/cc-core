package mimicry

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

const ClaudeSecurityMonitorInvalidCode = "classifier_response_invalid"
const ClaudeSecurityMonitorInvalidMessage = "The classifier service returned an unusable response. Please retry."
const ClaudeSecurityMonitorInvalidBody = `{"type":"error","error":{"type":"api_error","code":"classifier_response_invalid","message":"The classifier service returned an unusable response. Please retry."}}`

const claudeMonitorResponseLimit = 64 * 1024

// IsClaudeSecurityMonitorStageOne recognizes only the known short, nonstreaming
// classifier profile. It is not a trust signal or a verdict about the tool.
func IsClaudeSecurityMonitorStageOne(body []byte) bool {
	var request struct {
		Model     string            `json:"model"`
		System    json.RawMessage   `json:"system"`
		Messages  []json.RawMessage `json:"messages"`
		MaxTokens int               `json:"max_tokens"`
		Stream    bool              `json:"stream"`
		Thinking  struct {
			Type string `json:"type"`
		} `json:"thinking"`
		StopSequences []string `json:"stop_sequences"`
	}
	if json.Unmarshal(body, &request) != nil || request.Model == "" || len(request.Messages) == 0 ||
		request.MaxTokens != 64 || request.Stream || request.Thinking.Type != "disabled" ||
		len(request.StopSequences) != 1 || !isClaudeSecurityMonitorSystem(request.System) {
		return false
	}
	return request.StopSequences[0] == "</block>" || request.StopSequences[0] == "</severity>"
}

func emptyClaudeSecurityMonitorCompletion(body []byte) bool {
	var response struct {
		Type       string `json:"type"`
		StopReason string `json:"stop_reason"`
		Content    []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if json.Unmarshal(body, &response) != nil || response.Type != "message" ||
		response.StopReason != "max_tokens" || response.Content == nil {
		return false
	}
	for _, block := range response.Content {
		switch block.Type {
		case "text":
			if strings.TrimSpace(block.Text) != "" {
				return false
			}
		case "thinking", "redacted_thinking":
		default:
			// Explicit refusals and future content types are never reinterpreted.
			return false
		}
	}
	return true
}

// CheckClaudeSecurityMonitorResponse reports a narrowly invalid empty stage-one
// completion before a gateway commits or bills it. The bounded, non-consuming
// peek installs a reader that preserves every response byte and closes the
// original body. Oversized, streaming and unfamiliar responses pass unchanged.
// Callers may retry another credential with the same request; they must not
// manufacture approval, increase the budget, or quarantine the entire channel.
func CheckClaudeSecurityMonitorResponse(request []byte, response *http.Response) (invalid bool, readErr error) {
	if response == nil || response.Body == nil || response.StatusCode != http.StatusOK ||
		strings.Contains(strings.ToLower(response.Header.Get("Content-Type")), "text/event-stream") ||
		!IsClaudeSecurityMonitorStageOne(request) {
		return false, nil
	}
	original := response.Body
	reader := bufio.NewReaderSize(original, claudeMonitorResponseLimit+1)
	response.Body = struct {
		io.Reader
		io.Closer
	}{reader, original}
	peek, err := reader.Peek(claudeMonitorResponseLimit + 1)
	if err != nil && err != io.EOF {
		return false, err
	}
	if len(peek) > claudeMonitorResponseLimit {
		return false, nil
	}
	return emptyClaudeSecurityMonitorCompletion(peek), nil
}
