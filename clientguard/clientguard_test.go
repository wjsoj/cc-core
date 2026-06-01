package clientguard

import (
	"net/http"
	"testing"
)

func TestInspectUA_AllowsInteractiveClients(t *testing.T) {
	g := NewDefault()
	allowed := []string{
		"claude-cli/2.1.158 (external, cli)",
		"claude-code/2.1.158",
		"claude-code/2.1.158 (vscode)",
		"Claude/1.2.3 Chrome/120 Electron/28 Safari/537.36", // Claude Desktop-ish
		"Cursor/0.42.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
		"axios/1.7.2",  // not blocked by default (Electron false-positive risk)
		"node-fetch/2", // not blocked by default
	}
	for _, ua := range allowed {
		if d := g.InspectUA(ua); d.Blocked {
			t.Errorf("UA %q should be allowed, got blocked: %s", ua, d.Reason)
		}
	}
}

func TestInspectUA_BlocksAbuseClients(t *testing.T) {
	g := NewDefault()
	blocked := []string{
		"python-requests/2.31.0",
		"python-httpx/0.27.0",
		"Anthropic/Python 0.40.0", // stainless python SDK default UA
		"Anthropic/JS 0.40.0",     // stainless JS SDK default UA (raw, not CC)
		"OpenAI/Python 1.30.0",
		"OpenAI/NodeJS 4.52.0",
		"litellm/1.50.0 anthropic/0.40.0",
		"litellm/1.40.0",
		"LiteLLM/1.40.0", // case-insensitive
		"curl/8.4.0",
		"Wget/1.21",
		"Go-http-client/2.0",
		"okhttp/4.12.0",
		"PostmanRuntime/7.36.0",
		"Apifox/1.0.0 (https://apifox.com)",
		"HTTPie/3.2.2",
	}
	for _, ua := range blocked {
		d := g.InspectUA(ua)
		if !d.Blocked {
			t.Errorf("UA %q should be blocked", ua)
		}
		if d.Matched == "" {
			t.Errorf("UA %q blocked but no Matched fragment recorded", ua)
		}
	}
}

func TestInspectUA_EmptyUA(t *testing.T) {
	if d := NewDefault().InspectUA(""); !d.Blocked {
		t.Error("empty UA should be blocked by default")
	}
	if d := NewDefault().InspectUA("   "); !d.Blocked {
		t.Error("whitespace-only UA should be blocked by default")
	}
	if d := New(nil, false).InspectUA(""); d.Blocked {
		t.Error("empty UA should be allowed when blockEmptyUA is false")
	}
}

func TestNew_ExtraSubstrings(t *testing.T) {
	g := New([]string{"axios/", "Node-Fetch"}, true)
	if d := g.InspectUA("axios/1.7.2"); !d.Blocked {
		t.Error("axios/ should be blocked when added as extra")
	}
	if d := g.InspectUA("node-fetch/2"); !d.Blocked {
		t.Error("node-fetch should be blocked when added as extra (case-insensitive)")
	}
	// Defaults still apply alongside extras.
	if d := g.InspectUA("curl/8.4.0"); !d.Blocked {
		t.Error("default blocklist should still apply when extras are added")
	}
}

func TestInspect_ReadsUserAgentHeader(t *testing.T) {
	h := http.Header{}
	h.Set("User-Agent", "python-requests/2.31.0")
	if d := NewDefault().Inspect(h); !d.Blocked {
		t.Error("Inspect should read the User-Agent header and block")
	}
}
