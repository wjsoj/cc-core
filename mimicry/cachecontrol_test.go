package mimicry

import (
	"encoding/json"
	"strings"
	"testing"
)

// thirdPartyGenuineBody mirrors crack/thirdparty/rows/01-v1_messages.json: the
// billing block with no breakpoint, then two blocks carrying the bare
// {"type":"ephemeral"} a custom-base-url client is limited to. Written as a
// literal, not built from a map, so the key order under test is the captured
// one rather than whatever encoding/json happens to emit.
func thirdPartyGenuineBody(t *testing.T) []byte {
	t.Helper()
	uid, err := json.Marshal(buildJSONUserID("downstream-device", "", policySourceSession))
	if err != nil {
		t.Fatal(err)
	}
	return []byte(`{"model":"claude-sonnet-5",` +
		`"messages":[{"role":"user","content":"hello"}],` +
		`"system":[` +
		`{"type":"text","text":"x-anthropic-billing-header: cc_version=2.1.226.ab9; cc_entrypoint=cli;"},` +
		`{"type":"text","text":"` + ClaudeCodeSystemPrompt + `","cache_control":{"type":"ephemeral"}},` +
		`{"type":"text","text":"long env prompt","cache_control":{"type":"ephemeral"}}],` +
		`"metadata":{"user_id":` + string(uid) + `},` +
		`"stream":true}`)
}

func systemCachePattern(t *testing.T, body []byte) []string {
	t.Helper()
	var obj struct {
		System []struct {
			CacheControl *struct {
				Type  string `json:"type"`
				TTL   string `json:"ttl"`
				Scope string `json:"scope"`
			} `json:"cache_control"`
		} `json:"system"`
	}
	if err := json.Unmarshal(body, &obj); err != nil {
		t.Fatalf("parse system: %v", err)
	}
	out := make([]string, 0, len(obj.System))
	for _, block := range obj.System {
		if block.CacheControl == nil {
			out = append(out, "-")
			continue
		}
		got := block.CacheControl.Type
		if block.CacheControl.TTL != "" {
			got += "+" + block.CacheControl.TTL
		}
		if block.CacheControl.Scope != "" {
			got += "+" + block.CacheControl.Scope
		}
		out = append(out, got)
	}
	return out
}

// The headline case: the captured inbound breakpoint layout becomes the
// captured OAuth one on the last two blocks (crack/thirdparty/SPEC.md §2c).
func TestGenuineRewriteRestoresCacheBreakpoints(t *testing.T) {
	result := mustTransform(t, thirdPartyGenuineBody(t), testID(), GenuineRequestRewrite)

	got := strings.Join(systemCachePattern(t, result.Body()), " | ")
	want := "- | ephemeral+1h+global | ephemeral+1h"
	if got != want {
		t.Fatalf("cache pattern = %q, want %q", got, want)
	}
	// Field order is part of the shape: capture shows {"type","ttl","scope"},
	// which a map-based encoder would have sorted to {"scope","ttl","type"}.
	if !strings.Contains(string(result.Body()), `"cache_control":{"type":"ephemeral","ttl":"1h","scope":"global"}`) {
		t.Errorf("cache_control field order does not match capture:\n%s", result.Body())
	}
}

// A first-party body already carries correct breakpoints, so the repair must be
// a no-op there — and must not touch a ttl the client deliberately chose.
func TestGenuineRewriteLeavesNonBareCacheControlAlone(t *testing.T) {
	body := []byte(strings.Replace(
		string(thirdPartyGenuineBody(t)),
		`"text":"long env prompt","cache_control":{"type":"ephemeral"}`,
		`"text":"long env prompt","cache_control":{"type":"ephemeral","ttl":"5m"}`,
		1))
	result := mustTransform(t, body, testID(), GenuineRequestRewrite)

	pattern := systemCachePattern(t, result.Body())
	if pattern[len(pattern)-1] != "ephemeral+5m" {
		t.Errorf("client-chosen ttl was overwritten: %v", pattern)
	}
}

// No breakpoints in, no breakpoints out. The captured title request has none on
// either path, so inventing one would be a divergence, not a repair.
func TestGenuineRewriteDoesNotAddCacheBreakpoints(t *testing.T) {
	body := []byte(strings.ReplaceAll(
		string(thirdPartyGenuineBody(t)), `,"cache_control":{"type":"ephemeral"}`, ""))
	result := mustTransform(t, body, testID(), GenuineRequestRewrite)

	for i, got := range systemCachePattern(t, result.Body()) {
		if got != "-" {
			t.Errorf("system[%d] gained a breakpoint: %s", i, got)
		}
	}
}

func TestSetJSONObjectMemberPreservesOrder(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"appends last", `{"type":"text","text":"x"}`, `{"type":"text","text":"x","cache_control":{"type":"ephemeral","ttl":"1h"}}`},
		{"replaces in place", `{"cache_control":{"type":"ephemeral"},"type":"text"}`, `{"cache_control":{"type":"ephemeral","ttl":"1h"},"type":"text"}`},
		{"empty object", `{}`, `{"cache_control":{"type":"ephemeral","ttl":"1h"}}`},
		{"whitespace tolerated", ` { "type" : "text" } `, `{ "type" : "text" ,"cache_control":{"type":"ephemeral","ttl":"1h"}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := setJSONObjectMember(json.RawMessage(tc.in), "cache_control", claudeSystemCacheControl(false))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Errorf("got  %s\nwant %s", got, tc.want)
			}
		})
	}
}

func TestDeleteJSONObjectMember(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"first", `{"cache_control":{"type":"ephemeral"},"type":"text","text":"x"}`, `{"type":"text","text":"x"}`},
		{"middle", `{"type":"text","cache_control":{"type":"ephemeral"},"text":"x"}`, `{"type":"text","text":"x"}`},
		{"last", `{"type":"text","text":"x","cache_control":{"type":"ephemeral"}}`, `{"type":"text","text":"x"}`},
		{"only", `{"cache_control":{"type":"ephemeral"}}`, `{}`},
		{"absent", `{"type":"text"}`, `{"type":"text"}`},
		{"whitespace", `{"type":"text" , "cache_control" : {"type":"ephemeral"} }`, `{"type":"text" }`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := deleteJSONObjectMember(json.RawMessage(tc.in), "cache_control")
			if err != nil {
				t.Fatal(err)
			}
			if !json.Valid(got) {
				t.Fatalf("produced invalid JSON: %s", got)
			}
			if string(got) != tc.want {
				t.Errorf("got  %s\nwant %s", got, tc.want)
			}
		})
	}
}

// A value that merely looks like a key must not confuse the backward walk.
func TestDeleteJSONObjectMemberIgnoresLookalikeValues(t *testing.T) {
	in := `{"text":"cache_control: not a key","cache_control":{"type":"ephemeral"}}`
	got, err := deleteJSONObjectMember(json.RawMessage(in), "cache_control")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"text":"cache_control: not a key"}` {
		t.Errorf("got %s", got)
	}
}

func TestIsBareEphemeral(t *testing.T) {
	cases := map[string]bool{
		`{"type":"ephemeral"}`:                  true,
		`{"type":"ephemeral","ttl":"1h"}`:       false,
		`{"type":"ephemeral","scope":"global"}`: false,
		`{"type":"persistent"}`:                 false,
		`{}`:                                    false,
		`null`:                                  false,
		`{"type":"ephemeral","ttl":"1h","x":"extra"}`: false,
	}
	for in, want := range cases {
		if got := isBareEphemeral(json.RawMessage(in)); got != want {
			t.Errorf("isBareEphemeral(%s) = %v, want %v", in, got, want)
		}
	}
}
