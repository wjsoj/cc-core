package auth

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRetiredClaudeIdentityModeIsIgnoredAndRemovedOnInstall(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "claude-user.json")
	data := []byte(`{"type":"claude","provider":"anthropic","access_token":"token","refresh_token":"refresh","email":"legacy@example.com","claude_identity_mode":{"obsolete":true},"unknown_keep":"yes"}`)
	if _, err := ParseFile(path, data); err != nil {
		t.Fatalf("retired mode should not affect credential loading: %v", err)
	}
	if _, err := InstallCredentialFile(path, data); err != nil {
		t.Fatal(err)
	}

	installed, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(installed, &raw); err != nil {
		t.Fatal(err)
	}
	if _, exists := raw["claude_identity_mode"]; exists {
		t.Fatalf("retired mode survived install: %v", raw)
	}
	if raw["unknown_keep"] != "yes" {
		t.Fatalf("install removed unrelated fields: %v", raw)
	}
}

func TestAnthropicReloginRemovesRetiredIdentityMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "claude-user.json")
	old := `{"type":"claude","provider":"anthropic","access_token":"old-token","refresh_token":"old-refresh","email":"user@example.com","account_uuid":"account-1","claude_identity_mode":"preserve"}`
	if err := os.WriteFile(path, []byte(old), 0600); err != nil {
		t.Fatal(err)
	}
	raw := map[string]any{
		"type":                 "claude",
		"provider":             ProviderAnthropic,
		"access_token":         "new-token",
		"refresh_token":        "new-refresh",
		"email":                "user@example.com",
		"account_uuid":         "account-1",
		"claude_identity_mode": "preserve",
	}
	a, err := writeAnthropicLoginCredential(path, raw)
	if err != nil {
		t.Fatal(err)
	}
	token, _ := a.Credentials()
	if token != "new-token" {
		t.Fatalf("relogin retained stale token: %q", token)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var installed map[string]any
	if err := json.Unmarshal(data, &installed); err != nil {
		t.Fatal(err)
	}
	if _, exists := installed["claude_identity_mode"]; exists {
		t.Fatalf("relogin retained retired mode: %v", installed)
	}
}

func TestAnthropicReloginRejectsDifferentAccountOverwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "claude-user.json")
	old := []byte(`{"type":"claude","provider":"anthropic","access_token":"old-token","refresh_token":"old-refresh","email":"old@example.com","account_uuid":"account-old"}`)
	if err := os.WriteFile(path, old, 0600); err != nil {
		t.Fatal(err)
	}
	_, err := writeAnthropicLoginCredential(path, map[string]any{
		"type":          "claude",
		"provider":      ProviderAnthropic,
		"access_token":  "new-token",
		"refresh_token": "new-refresh",
		"email":         "new@example.com",
		"account_uuid":  "account-new",
	})
	if !errors.Is(err, ErrCredentialFileAccountMismatch) {
		t.Fatalf("different account overwrite: %v", err)
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	a, parseErr := ParseFile(path, data)
	if parseErr != nil {
		t.Fatal(parseErr)
	}
	token, _ := a.Credentials()
	if token != "old-token" || a.AccountUUIDValue() != "account-old" {
		t.Fatalf("original credential was overwritten: token=%q account=%q", token, a.AccountUUIDValue())
	}
}

func TestDuplicateClaudeAccountUUIDRejectedOnLoadAndAdd(t *testing.T) {
	dir := t.TempDir()
	for name := range map[string]bool{"one.json": true, "two.json": true} {
		body := []byte(`{"type":"claude","provider":"anthropic","access_token":"token-` + name + `","refresh_token":"refresh","account_uuid":"same-account"}`)
		if err := os.WriteFile(filepath.Join(dir, name), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := LoadAuthDir(dir); !errors.Is(err, ErrDuplicateClaudeAccountUUID) {
		t.Fatalf("duplicate load: %v", err)
	}

	one := &Auth{ID: "one.json", Kind: KindOAuth, Provider: ProviderAnthropic, AccountUUID: "same-account"}
	two := &Auth{ID: "two.json", Kind: KindOAuth, Provider: ProviderAnthropic, AccountUUID: "same-account"}
	p := NewPool([]*Auth{one}, nil, time.Hour, false, "")
	if err := p.AddOAuth(two); !errors.Is(err, ErrDuplicateClaudeAccountUUID) {
		t.Fatalf("duplicate add: %v", err)
	}
	if p.FindByID(two.ID) != nil {
		t.Fatal("duplicate credential was published")
	}
}
