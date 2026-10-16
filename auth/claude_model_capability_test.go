package auth

import (
	"testing"
	"time"
)

func TestClaudeModelUnsupportedUsesStaticScopedCapabilities(t *testing.T) {
	limited := AuthInfo{Kind: KindAPIKey, Provider: ProviderAnthropic, AllowedModels: []string{"claude-sonnet-5"}}
	wildcard := AuthInfo{Kind: KindAPIKey, Provider: ProviderAnthropic}
	oauth := AuthInfo{Kind: KindOAuth, Provider: ProviderAnthropic}
	foreign := wildcard
	foreign.Group = "other"
	foreignOAuth := oauth
	foreignOAuth.Group = "other"
	disabled := oauth
	disabled.Disabled = true
	codex := oauth
	codex.Provider = ProviderOpenAI
	paused := limited
	paused.QuotaResetAt = time.Now().Add(time.Hour)
	paused.QuarantineUntil = paused.QuotaResetAt
	paused.HardFailureAt = time.Now()
	mapped := limited
	mapped.ModelMap = map[string]string{"claude-sonnet-5": "vendor-model"}
	private := limited
	private.Group = "backup"
	shared := wildcard
	shared.Group = "new"
	cases := []struct {
		name   string
		creds  []AuthInfo
		groups []string
		model  string
		want   bool
	}{
		{"absent", []AuthInfo{limited}, nil, "claude-sonnet-5-5", true},
		{"present", []AuthInfo{limited}, nil, "claude-sonnet-5", false},
		{"paused-present", []AuthInfo{paused}, nil, "claude-sonnet-5", false},
		{"paused-absent", []AuthInfo{paused}, nil, "claude-sonnet-5-5", true},
		{"empty-allowlist", []AuthInfo{limited, wildcard}, nil, "claude-sonnet-5-5", false},
		{"oauth-unknown", []AuthInfo{limited, oauth}, nil, "claude-sonnet-5-5", false},
		{"disabled-oauth", []AuthInfo{limited, disabled}, nil, "claude-sonnet-5-5", true},
		{"other-provider", []AuthInfo{limited, codex}, nil, "claude-sonnet-5-5", true},
		{"other-group-wildcard", []AuthInfo{limited, foreign}, []string{"mine"}, "claude-sonnet-5-5", true},
		{"other-group-oauth", []AuthInfo{limited, foreignOAuth}, []string{"mine"}, "claude-sonnet-5-5", true},
		{"authorized-secondary-group-present", []AuthInfo{private}, []string{"primary", "backup"}, "claude-sonnet-5", false},
		{"authorized-secondary-group", []AuthInfo{private}, []string{"primary", "backup"}, "claude-sonnet-5-5", true},
		{"shared-new", []AuthInfo{limited, shared}, []string{"mine"}, "claude-sonnet-5-5", false},
		{"explicit-map", []AuthInfo{mapped}, nil, "claude-sonnet-5", false},
		{"map-does-not-bypass-allowlist", []AuthInfo{mapped}, nil, "vendor-model", true},
		{"empty-fleet", nil, nil, "claude-sonnet-5-5", false},
		{"only-inaccessible", []AuthInfo{foreign}, []string{"mine"}, "claude-sonnet-5-5", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			statuses := make([]Status, len(tc.creds))
			for i, credential := range tc.creds {
				statuses[i] = Status{Auth: credential}
			}
			if got := ClaudeModelUnsupported(statuses, tc.groups, tc.model); got != tc.want {
				t.Fatalf("unsupported = %v, want %v", got, tc.want)
			}
		})
	}
}
