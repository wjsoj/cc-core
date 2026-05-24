package kirobridge

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/wjsoj/cc-core/kirotransport"
)

// WebSearch handles the Anthropic `web_search` tool as a side-channel against
// Kiro's MCP endpoint (`q.<region>.amazonaws.com/mcp`), rather than going
// through GenerateAssistantResponse. Mirrors kiro.rs anthropic/websearch.rs.
//
// Typical usage in a fork's handler:
//
//	if query, ok := IsWebSearchRequest(req); ok {
//	    results, err := client.WebSearch(ctx, query)
//	    // Synthesize SSE event stream as the model's response.
//	    events := SynthesizeWebSearchSSE(req.Model, query, results)
//	    for _, e := range events { w.Write(e.Marshal()) }
//	    return
//	}

// WebSearchQueryPrefix is the magic prefix Anthropic clients sometimes prepend
// to the search query. We strip it before forwarding to Kiro.
const WebSearchQueryPrefix = "Perform a web search for the query: "

// IsWebSearchRequest returns the search query and ok=true when req is a pure
// WebSearch invocation. Defined as `tools.length == 1 && tools[0].name ==
// "web_search"` matching kiro.rs has_web_search_tool().
func IsWebSearchRequest(req *AnthropicRequest) (query string, ok bool) {
	if req == nil || len(req.Tools) != 1 || req.Tools[0].Name != "web_search" {
		return "", false
	}
	if len(req.Messages) == 0 {
		return "", false
	}
	// Extract from first message's first text block.
	blocks := parseContent(req.Messages[0].Content)
	for _, b := range blocks {
		if b.Type == "text" && b.Text != "" {
			q := strings.TrimPrefix(b.Text, WebSearchQueryPrefix)
			if q != "" {
				return q, true
			}
		}
	}
	// Fallback: bare string content
	var s string
	if err := json.Unmarshal(req.Messages[0].Content, &s); err == nil && s != "" {
		q := strings.TrimPrefix(s, WebSearchQueryPrefix)
		if q != "" {
			return q, true
		}
	}
	return "", false
}

// --- MCP wire types ---

// mcpRequest is the JSON-RPC 2.0 envelope for a tools/call invocation.
type mcpRequest struct {
	ID      string    `json:"id"`
	JSONRPC string    `json:"jsonrpc"`
	Method  string    `json:"method"`
	Params  mcpParams `json:"params"`
}

type mcpParams struct {
	Name      string       `json:"name"`
	Arguments mcpArguments `json:"arguments"`
}

type mcpArguments struct {
	Query string `json:"query"`
}

// mcpResponse mirrors the wire shape returned by `q.<region>/mcp`.
type mcpResponse struct {
	ID      string     `json:"id"`
	JSONRPC string     `json:"jsonrpc"`
	Result  *mcpResult `json:"result,omitempty"`
	Error   *mcpError  `json:"error,omitempty"`
}

type mcpResult struct {
	Content []mcpContent `json:"content"`
	IsError bool         `json:"isError"`
}

type mcpContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type mcpError struct {
	Code    int    `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

// WebSearchResults is the typed search-results payload Kiro returns. It is
// the JSON-encoded `result.content[0].text` after one layer of unwrap.
type WebSearchResults struct {
	Results      []WebSearchResult `json:"results"`
	TotalResults int               `json:"totalResults,omitempty"`
	Query        string            `json:"query,omitempty"`
	Error        string            `json:"error,omitempty"`
}

// WebSearchResult is one hit.
type WebSearchResult struct {
	Title         string `json:"title"`
	URL           string `json:"url"`
	Snippet       string `json:"snippet,omitempty"`
	PublishedDate int64  `json:"publishedDate,omitempty"` // unix ms
	ID            string `json:"id,omitempty"`
	Domain        string `json:"domain,omitempty"`
}

// WebSearchClient calls the Kiro MCP endpoint.
type WebSearchClient struct {
	HTTP      HTTPDoer
	Token     string
	IsAPIKey  bool
	Region    string
	Flavor    kirotransport.Flavor
	MachineID string
}

// HTTPDoer is anything that performs an HTTP request.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// Execute makes the MCP tools/call against q.<region>/mcp and returns the
// parsed search results.
func (c *WebSearchClient) Execute(ctx context.Context, query string) (*WebSearchResults, error) {
	if query == "" {
		return nil, fmt.Errorf("kirobridge: web search query is empty")
	}
	region := c.Region
	if region == "" {
		region = "us-east-1"
	}
	endpoint := "https://q." + region + ".amazonaws.com/mcp"

	body, _ := json.Marshal(mcpRequest{
		ID:      buildMCPRequestID(),
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  mcpParams{Name: "web_search", Arguments: mcpArguments{Query: query}},
	})

	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("kirobridge: web search: build req: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	kirotransport.ApplyCommonAWSHeaders(req, c.Flavor, c.MachineID)
	kirotransport.ApplyBearerAuth(req, c.Token, c.IsAPIKey)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kirobridge: web search: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("kirobridge: web search: HTTP %d: %s", resp.StatusCode, truncateLine(string(data), 256))
	}
	var mcp mcpResponse
	if err := json.Unmarshal(data, &mcp); err != nil {
		return nil, fmt.Errorf("kirobridge: web search: parse outer: %w", err)
	}
	if mcp.Error != nil {
		return nil, fmt.Errorf("kirobridge: web search: MCP error %d: %s", mcp.Error.Code, mcp.Error.Message)
	}
	if mcp.Result == nil || len(mcp.Result.Content) == 0 || mcp.Result.Content[0].Type != "text" {
		return &WebSearchResults{}, nil
	}
	var out WebSearchResults
	if err := json.Unmarshal([]byte(mcp.Result.Content[0].Text), &out); err != nil {
		return nil, fmt.Errorf("kirobridge: web search: parse inner: %w", err)
	}
	return &out, nil
}

// SynthesizeWebSearchSSE produces the Anthropic SSE event sequence for a
// completed WebSearch round-trip. Mirrors kiro.rs generate_websearch_events:
//
//	message_start
//	  → content_block[0] = text  ("I'll search for …")
//	  → content_block[1] = server_tool_use (web_search, with the query)
//	  → content_block[2] = web_search_tool_result (list of {title, url, encrypted_content, page_age})
//	  → content_block[3] = text (numbered summary)
//	message_delta (stop_reason=end_turn, usage.server_tool_use.web_search_requests=1)
//	message_stop
//
// inputTokens is echoed back into message_start.usage.input_tokens; pass 0 if
// unknown.
func SynthesizeWebSearchSSE(model, query string, results *WebSearchResults, inputTokens int) []SSEEvent {
	messageID := "msg_" + randomLowerHex(24)
	toolUseID := "srvtoolu_" + randomLowerHex(32)
	var out []SSEEvent

	// message_start
	out = append(out, jsonEvent("message_start", map[string]any{
		"type": "message_start",
		"message": map[string]any{
			"id":            messageID,
			"type":          "message",
			"role":          "assistant",
			"model":         model,
			"content":       []any{},
			"stop_reason":   nil,
			"stop_sequence": nil,
			"usage": map[string]any{
				"input_tokens":                inputTokens,
				"output_tokens":               0,
				"cache_creation_input_tokens": 0,
				"cache_read_input_tokens":     0,
			},
		},
	}))

	// block[0] — decision text
	decision := fmt.Sprintf("I'll search for %q.", query)
	out = append(out, blockStart(0, map[string]any{"type": "text", "text": ""}))
	out = append(out, jsonEvent("content_block_delta", map[string]any{
		"type": "content_block_delta", "index": 0,
		"delta": map[string]any{"type": "text_delta", "text": decision},
	}))
	out = append(out, blockStop(0))

	// block[1] — server_tool_use
	out = append(out, blockStart(1, map[string]any{
		"id":    toolUseID,
		"type":  "server_tool_use",
		"name":  "web_search",
		"input": map[string]any{"query": query},
	}))
	out = append(out, blockStop(1))

	// block[2] — web_search_tool_result
	var content []any
	if results != nil {
		for _, r := range results.Results {
			var pageAge any
			if r.PublishedDate > 0 {
				pageAge = time.UnixMilli(r.PublishedDate).Format("January 2, 2006")
			}
			content = append(content, map[string]any{
				"type":              "web_search_result",
				"title":             r.Title,
				"url":               r.URL,
				"encrypted_content": r.Snippet,
				"page_age":          pageAge,
			})
		}
	}
	out = append(out, blockStart(2, map[string]any{
		"type":    "web_search_tool_result",
		"content": content,
	}))
	out = append(out, blockStop(2))

	// block[3] — summary text
	summary := generateSearchSummary(query, results)
	out = append(out, blockStart(3, map[string]any{"type": "text", "text": ""}))
	const chunkSize = 100
	runes := []rune(summary)
	for i := 0; i < len(runes); i += chunkSize {
		end := i + chunkSize
		if end > len(runes) {
			end = len(runes)
		}
		out = append(out, jsonEvent("content_block_delta", map[string]any{
			"type": "content_block_delta", "index": 3,
			"delta": map[string]any{"type": "text_delta", "text": string(runes[i:end])},
		}))
	}
	out = append(out, blockStop(3))

	// message_delta + message_stop
	outputTokens := (len(summary) + 3) / 4
	out = append(out, jsonEvent("message_delta", map[string]any{
		"type": "message_delta",
		"delta": map[string]any{
			"stop_reason": "end_turn",
		},
		"usage": map[string]any{
			"output_tokens":   outputTokens,
			"server_tool_use": map[string]any{"web_search_requests": 1},
		},
	}))
	out = append(out, SSEEvent{Name: "message_stop", Data: []byte(`{"type":"message_stop"}`)})

	return out
}

// --- internal helpers ---

func generateSearchSummary(query string, results *WebSearchResults) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Here are the search results for %q:\n\n", query)
	if results == nil || len(results.Results) == 0 {
		sb.WriteString("No results found.\n")
	} else {
		for i, r := range results.Results {
			fmt.Fprintf(&sb, "%d. **%s**\n", i+1, r.Title)
			if r.Snippet != "" {
				runes := []rune(r.Snippet)
				if len(runes) > 200 {
					fmt.Fprintf(&sb, "   %s...\n", string(runes[:200]))
				} else {
					fmt.Fprintf(&sb, "   %s\n", r.Snippet)
				}
			}
			fmt.Fprintf(&sb, "   Source: %s\n\n", r.URL)
		}
	}
	sb.WriteString("\nPlease note that these are web search results and may not be fully accurate or up-to-date.")
	return sb.String()
}

func buildMCPRequestID() string {
	return "web_search_tooluse_" + randomMixed(22) + "_" + fmt.Sprintf("%d", time.Now().UnixMilli()) + "_" + randomLower(8)
}

func randomMixed(n int) string {
	return randomFromCharset(n, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
}
func randomLower(n int) string {
	return randomFromCharset(n, "abcdefghijklmnopqrstuvwxyz0123456789")
}
func randomFromCharset(n int, charset string) string {
	out := make([]byte, n)
	max := big.NewInt(int64(len(charset)))
	for i := range out {
		idx, _ := rand.Int(rand.Reader, max)
		out[i] = charset[idx.Int64()]
	}
	return string(out)
}
func randomLowerHex(n int) string {
	b := make([]byte, (n+1)/2)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)[:n]
}

func jsonEvent(name string, payload any) SSEEvent {
	data, _ := json.Marshal(payload)
	return SSEEvent{Name: name, Data: data}
}

func blockStart(index int, block any) SSEEvent {
	return jsonEvent("content_block_start", map[string]any{
		"type": "content_block_start", "index": index, "content_block": block,
	})
}

func blockStop(index int) SSEEvent {
	return SSEEvent{
		Name: "content_block_stop",
		Data: []byte(fmt.Sprintf(`{"type":"content_block_stop","index":%d}`, index)),
	}
}

func truncateLine(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
