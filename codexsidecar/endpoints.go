package codexsidecar

import (
	"encoding/json"
	"net/http"

	"github.com/wjsoj/cc-core/mimicry"
)

// Every call constructor below is a transcription of one row in
// crack/codexapp0.153.4/rows/. URL, method, User-Agent form and the
// endpoint-specific headers are the row's; nothing is generalised across rows,
// because the differences ARE the fingerprint. Three that are easy to lose:
//
//   - plugins/featured does NOT send oai-product-sku; the other three
//     plugin-store GETs do (rows 41/42/43/44).
//   - wham/settings/user sends NO originator, but does send
//     cache-control: no-cache, no-store (row 21).
//   - ps/mcp uses x-openai-product-sku, not oai-product-sku, and its
//     mcp-protocol-version header is absent on initialize and present on
//     every later call (rows 40-*).
//
// Header ORDER is captured in the rows but is not reproducible through
// net/http, which sorts header keys on the wire. Same limitation as package
// sidecar; noted here so nobody assumes the order below is what ships.

const backendAPI = "/backend-api"

// pluginsInstalledCall — crack/codexapp0.153.4/rows/41.
func pluginsInstalledCall() call {
	return call{
		endpoint: epPluginsInstalled,
		name:     "plugins_installed",
		method:   http.MethodGet,
		url:      backendAPI + "/ps/plugins/installed?limit=200",
		ua:       uaDesktopFull,
		extra: map[string]string{
			"Originator":      mimicry.CodexDesktopOriginator,
			"Oai-Product-Sku": "codex",
		},
	}
}

// pluginsListCall — crack/codexapp0.153.4/rows/42. The long-polled one.
func pluginsListCall() call {
	return call{
		endpoint: epPluginsList,
		name:     "plugins_list",
		method:   http.MethodGet,
		url:      backendAPI + "/ps/plugins/list?scope=GLOBAL&limit=200",
		ua:       uaDesktopFull,
		extra: map[string]string{
			"Originator":      mimicry.CodexDesktopOriginator,
			"Oai-Product-Sku": "codex",
		},
	}
}

// pluginsFeaturedCall — crack/codexapp0.153.4/rows/43. Note the missing
// oai-product-sku: this endpoint is under /plugins, not /ps/plugins.
func pluginsFeaturedCall() call {
	return call{
		endpoint: epPluginsFeatured,
		name:     "plugins_featured",
		method:   http.MethodGet,
		url:      backendAPI + "/plugins/featured?platform=codex",
		ua:       uaDesktopFull,
		extra:    map[string]string{"Originator": mimicry.CodexDesktopOriginator},
	}
}

// pluginsSuggestedCall — crack/codexapp0.153.4/rows/44.
func pluginsSuggestedCall() call {
	return call{
		endpoint: epPluginsSuggested,
		name:     "plugins_suggested",
		method:   http.MethodGet,
		url:      backendAPI + "/ps/plugins/suggested/codex?scope=GLOBAL",
		ua:       uaDesktopFull,
		extra: map[string]string{
			"Originator":      mimicry.CodexDesktopOriginator,
			"Oai-Product-Sku": "codex",
		},
	}
}

// codexModelsCall — crack/codexapp0.153.4/rows/12. Carries the `version`
// header, and the client_version query parameter must agree with it. Desktop
// 0.147.0 sent a base version in the query and a pre-release in the header;
// 0.153.4 is a plain release, so both are desktopVersion.
func codexModelsCall() call {
	return call{
		endpoint: epCodexModels,
		name:     "codex_models",
		method:   http.MethodGet,
		url:      backendAPI + "/codex/models?client_version=" + desktopVersion,
		ua:       uaDesktopFull,
		extra: map[string]string{
			"Version":    desktopVersion,
			"Originator": mimicry.CodexDesktopOriginator,
		},
	}
}

// settingsUserCall — crack/codexapp0.153.4/rows/21.
func settingsUserCall() call {
	return call{
		endpoint: epSettingsUser,
		name:     "settings_user",
		method:   http.MethodGet,
		url:      backendAPI + "/wham/settings/user",
		ua:       uaDesktopFull,
		extra:    map[string]string{"Cache-Control": "no-cache, no-store"},
	}
}

// analyticsCall — crack/codexapp0.153.4/rows/30-*. No endpoint key: the
// analytics rate slot is reserved by flushAnalytics before the queue is
// drained, so re-checking it here would double-count the floor.
func analyticsCall(body []byte) call {
	return call{
		name:        "analytics_events",
		method:      http.MethodPost,
		url:         backendAPI + "/codex/analytics-events/events",
		ua:          uaDesktopFull,
		contentType: "application/json",
		body:        body,
		extra:       map[string]string{"Originator": mimicry.CodexDesktopOriginator},
	}
}

// =============================================================================
// ps/mcp — the plugin-store MCP channel
// =============================================================================

const (
	mcpAccept      = "text/event-stream, application/json"
	mcpClientName  = "codex-mcp-client"
	mcpClientTitle = "Codex"
)

// jsonrpcRequest is written as a struct, not a map, because the captured key
// order is jsonrpc, id, method, params — and encoding/json sorts map keys,
// which would emit id first.
type jsonrpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

// jsonrpcNotification has no id at all — not id:null.
type jsonrpcNotification struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
}

type mcpInitializeParams struct {
	ProtocolVersion string         `json:"protocolVersion"`
	Capabilities    map[string]any `json:"capabilities"`
	ClientInfo      mcpClientInfo  `json:"clientInfo"`
}

type mcpClientInfo struct {
	Name    string `json:"name"`
	Title   string `json:"title"`
	Version string `json:"version"`
}

type mcpProgressParams struct {
	Meta mcpProgressMeta `json:"_meta"`
}

type mcpProgressMeta struct {
	ProgressToken int `json:"progressToken"`
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		// Every value marshalled here is a literal struct of scalars; a
		// failure would be a programming error, not a runtime condition.
		return []byte("{}")
	}
	return b
}

// mcpCall builds one ps/mcp POST. withProtocolHeader is false only for
// initialize, which negotiates the version it later echoes.
func mcpCall(name string, body []byte, withProtocolHeader bool) call {
	extra := map[string]string{"X-Openai-Product-Sku": "codex"}
	if withProtocolHeader {
		extra["Mcp-Protocol-Version"] = mcpProtocolVersion
	}
	return call{
		endpoint:    epMCP,
		name:        name,
		method:      http.MethodPost,
		url:         backendAPI + "/ps/mcp",
		ua:          uaMCPClient,
		accept:      mcpAccept,
		contentType: "application/json",
		body:        body,
		extra:       extra,
	}
}

// mcpInitializeCall — rows/40-post-ps-mcp-initialize.json. jsonrpc id 0.
func mcpInitializeCall() call {
	return mcpCall("mcp_initialize", mustJSON(jsonrpcRequest{
		JSONRPC: "2.0",
		ID:      0,
		Method:  "initialize",
		Params: mcpInitializeParams{
			ProtocolVersion: mcpProtocolVersion,
			// The capture advertises elicitation and nothing else.
			Capabilities: map[string]any{"elicitation": map[string]any{}},
			ClientInfo: mcpClientInfo{
				Name:    mcpClientName,
				Title:   mcpClientTitle,
				Version: desktopVersion,
			},
		},
	}), false)
}

// mcpInitializedCall — rows/40-post-ps-mcp-notifications-initialized.json.
// A notification: no id, and the server answers 204.
func mcpInitializedCall() call {
	return mcpCall("mcp_initialized", mustJSON(jsonrpcNotification{
		JSONRPC: "2.0",
		Method:  "notifications/initialized",
	}), true)
}

// mcpToolsListCall — rows/40-post-ps-mcp-tools-list.json. id 1, progress 0.
func mcpToolsListCall() call {
	return mcpCall("mcp_tools_list", mustJSON(jsonrpcRequest{
		JSONRPC: "2.0", ID: 1, Method: "tools/list",
		Params: mcpProgressParams{Meta: mcpProgressMeta{ProgressToken: 0}},
	}), true)
}

// mcpResourcesListCall — rows/40-post-ps-mcp-resources-list.json. id 2,
// progress 1.
func mcpResourcesListCall() call {
	return mcpCall("mcp_resources_list", mustJSON(jsonrpcRequest{
		JSONRPC: "2.0", ID: 2, Method: "resources/list",
		Params: mcpProgressParams{Meta: mcpProgressMeta{ProgressToken: 1}},
	}), true)
}

// mcpResourceTemplatesCall — rows/40-post-ps-mcp-resources-templates-list.json.
// id 3, progress 2.
func mcpResourceTemplatesCall() call {
	return mcpCall("mcp_resource_templates_list", mustJSON(jsonrpcRequest{
		JSONRPC: "2.0", ID: 3, Method: "resources/templates/list",
		Params: mcpProgressParams{Meta: mcpProgressMeta{ProgressToken: 2}},
	}), true)
}
