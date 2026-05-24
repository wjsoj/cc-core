package kirobridge

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIsWebSearchRequest(t *testing.T) {
	// Positive: 1 tool, name=web_search
	req := &AnthropicRequest{
		Tools: []AnthropicTool{{Name: "web_search"}},
		Messages: []AnthropicMessage{
			{Role: "user", Content: json.RawMessage(`"Perform a web search for the query: golang event-stream"`)},
		},
	}
	q, ok := IsWebSearchRequest(req)
	if !ok || q != "golang event-stream" {
		t.Fatalf("expected ok+stripped query, got ok=%v q=%q", ok, q)
	}

	// Positive: bare query string, no prefix
	req.Messages[0].Content = json.RawMessage(`"weather in sf"`)
	q, ok = IsWebSearchRequest(req)
	if !ok || q != "weather in sf" {
		t.Errorf("bare query: ok=%v q=%q", ok, q)
	}

	// Positive: array content
	req.Messages[0].Content = json.RawMessage(`[{"type":"text","text":"recent rust async news"}]`)
	q, ok = IsWebSearchRequest(req)
	if !ok || q != "recent rust async news" {
		t.Errorf("array content: ok=%v q=%q", ok, q)
	}

	// Negative: 2 tools
	req.Tools = []AnthropicTool{{Name: "web_search"}, {Name: "other"}}
	if _, ok := IsWebSearchRequest(req); ok {
		t.Error("should not detect when >1 tool")
	}

	// Negative: name mismatch
	req.Tools = []AnthropicTool{{Name: "search"}}
	if _, ok := IsWebSearchRequest(req); ok {
		t.Error("should not detect when name != web_search")
	}

	// Negative: nil
	if _, ok := IsWebSearchRequest(nil); ok {
		t.Error("nil should not detect")
	}
}

func TestWebSearchExecuteMCPWire(t *testing.T) {
	var sawPath string
	var sawBody mcpRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&sawBody)
		// Synthesize a Kiro MCP response with one search result.
		inner, _ := json.Marshal(WebSearchResults{
			Query: "go",
			Results: []WebSearchResult{
				{Title: "Go", URL: "https://go.dev", Snippet: "The Go language", PublishedDate: 1735689600000},
			},
		})
		resp := mcpResponse{
			ID:      sawBody.ID,
			JSONRPC: "2.0",
			Result:  &mcpResult{Content: []mcpContent{{Type: "text", Text: string(inner)}}},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	c := &WebSearchClient{
		HTTP:  &wsHostRewriter{base: srv.URL, next: srv.Client()},
		Token: "aoaABC",
	}
	results, err := c.Execute(context.Background(), "go")
	if err != nil {
		t.Fatal(err)
	}
	if sawPath != "/mcp" {
		t.Errorf("path: %s", sawPath)
	}
	if sawBody.Method != "tools/call" || sawBody.Params.Name != "web_search" || sawBody.Params.Arguments.Query != "go" {
		t.Errorf("mcp request body: %+v", sawBody)
	}
	if !strings.HasPrefix(sawBody.ID, "web_search_tooluse_") {
		t.Errorf("id format: %s", sawBody.ID)
	}
	if len(results.Results) != 1 || results.Results[0].URL != "https://go.dev" {
		t.Errorf("results: %+v", results)
	}
}

func TestSynthesizeWebSearchSSE(t *testing.T) {
	results := &WebSearchResults{
		Query: "go",
		Results: []WebSearchResult{
			{Title: "Go", URL: "https://go.dev", Snippet: "The Go language"},
		},
	}
	events := SynthesizeWebSearchSSE("claude-opus-4-7", "go", results, 10)
	got := names(events)

	// Expect: message_start, [text block: start, delta, stop], [server_tool_use: start, stop],
	//         [web_search_tool_result: start, stop], [summary text: start, delta(s), stop],
	//         message_delta, message_stop
	if got[0] != "message_start" || got[len(got)-1] != "message_stop" {
		t.Fatalf("framing wrong: %v", got)
	}
	// Find the server_tool_use content_block_start
	var foundServerTool bool
	for _, e := range events {
		if e.Name == "content_block_start" {
			var v map[string]any
			_ = json.Unmarshal(e.Data, &v)
			cb := v["content_block"].(map[string]any)
			if cb["type"] == "server_tool_use" && cb["name"] == "web_search" {
				foundServerTool = true
			}
		}
	}
	if !foundServerTool {
		t.Errorf("server_tool_use block missing")
	}
	// Find the web_search_tool_result
	var foundResultBlock bool
	for _, e := range events {
		if e.Name == "content_block_start" {
			var v map[string]any
			_ = json.Unmarshal(e.Data, &v)
			cb := v["content_block"].(map[string]any)
			if cb["type"] == "web_search_tool_result" {
				foundResultBlock = true
				contentArr := cb["content"].([]any)
				if len(contentArr) != 1 {
					t.Errorf("result content length: %d", len(contentArr))
				}
			}
		}
	}
	if !foundResultBlock {
		t.Errorf("web_search_tool_result block missing")
	}
}

func TestSynthesizeWebSearchSSENoResults(t *testing.T) {
	events := SynthesizeWebSearchSSE("claude-opus-4-7", "void", nil, 0)
	// Should still produce valid framing; summary should say "No results found"
	var summaryHasNoResults bool
	for _, e := range events {
		if e.Name == "content_block_delta" {
			var v map[string]any
			_ = json.Unmarshal(e.Data, &v)
			delta := v["delta"].(map[string]any)
			if t, ok := delta["text"].(string); ok && strings.Contains(t, "No results found") {
				summaryHasNoResults = true
			}
		}
	}
	if !summaryHasNoResults {
		t.Error("nil results should produce 'No results found' summary")
	}
}

type wsHostRewriter struct {
	base string
	next *http.Client
}

func (r *wsHostRewriter) Do(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = "http"
	// Strip http:// prefix
	host := strings.TrimPrefix(strings.TrimPrefix(r.base, "https://"), "http://")
	if i := strings.IndexByte(host, '/'); i >= 0 {
		host = host[:i]
	}
	req.URL.Host = host
	return r.next.Do(req)
}

// keep unused imports happy if test shrinks
var _ = io.EOF
