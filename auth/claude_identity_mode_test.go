package auth

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestClaudeIdentityModePersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "claude-user.json")
	initial := `{"type":"claude","provider":"anthropic","access_token":"token","refresh_token":"refresh","email":"user@example.com","account_uuid":"account-1","unknown_keep":"yes"}`
	if err := os.WriteFile(path, []byte(initial), 0600); err != nil {
		t.Fatal(err)
	}

	load := func() *Auth {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		a, err := ParseFile(path, data)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}

	a := load()
	if got := a.ClaudeIdentityModeValue(); got != ClaudeIdentityModePreserve {
		t.Fatalf("legacy default: got %q", got)
	}
	if got := a.Snapshot().ClaudeIdentityMode; got != ClaudeIdentityModePreserve {
		t.Fatalf("snapshot default: got %q", got)
	}
	if err := a.UpdateClaudeIdentityMode(ClaudeIdentityModeRewriteStripCCH); err != nil {
		t.Fatal(err)
	}

	b := load()
	if got := b.ClaudeIdentityModeValue(); got != ClaudeIdentityModeRewriteStripCCH {
		t.Fatalf("rewrite_strip did not round-trip: %q", got)
	}
	data, _ := os.ReadFile(path)
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if raw["claude_identity_mode"] != "rewrite_strip" || raw["unknown_keep"] != "yes" {
		t.Fatalf("persisted JSON lost fields: %v", raw)
	}

	if err := b.UpdateClaudeIdentityMode(ClaudeIdentityModePreserve); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(path)
	raw = nil
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if _, exists := raw["claude_identity_mode"]; exists {
		t.Fatalf("preserve should use the absent-key default: %v", raw)
	}
	if got := load().ClaudeIdentityModeValue(); got != ClaudeIdentityModePreserve {
		t.Fatalf("preserve did not round-trip: %q", got)
	}
}

func TestClaudeIdentityModeRejectsInvalidInput(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"unknown":      `{"type":"claude","access_token":"token","refresh_token":"refresh","claude_identity_mode":"rewrite_keep"}`,
		"number":       `{"type":"claude","access_token":"token","refresh_token":"refresh","claude_identity_mode":1}`,
		"missing_uuid": `{"type":"claude","access_token":"token","refresh_token":"refresh","email":"legacy@example.com","claude_identity_mode":"rewrite_strip"}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name+".json")
			if _, err := ParseFile(path, []byte(body)); err == nil {
				t.Fatal("invalid mode was accepted")
			}
		})
	}

	apiKey := &Auth{Kind: KindAPIKey, Provider: ProviderAnthropic}
	if err := apiKey.SetClaudeIdentityMode(ClaudeIdentityModeRewriteStripCCH); err == nil {
		t.Fatal("API key accepted a Claude identity mode")
	}
	if got := apiKey.ClaudeIdentityModeValue(); got != "" {
		t.Fatalf("API key mode should be inapplicable, got %q", got)
	}
	codex := &Auth{Kind: KindOAuth, Provider: ProviderOpenAI}
	if err := codex.SetClaudeIdentityMode(ClaudeIdentityModeRewriteStripCCH); err == nil {
		t.Fatal("OpenAI OAuth accepted a Claude identity mode")
	}
	legacy := &Auth{Kind: KindOAuth, Provider: ProviderAnthropic, Email: "legacy@example.com"}
	if err := legacy.SetClaudeIdentityMode(ClaudeIdentityModeRewriteStripCCH); !errors.Is(err, ErrClaudeIdentityModeMissingAccountUUID) {
		t.Fatalf("legacy credential accepted rewrite_strip: %v", err)
	}
}

func TestPreservedClaudeIdentityModeOnRelogin(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "claude-user.json")
	body := `{"type":"claude","email":"user@example.com","account_uuid":"account-1","claude_identity_mode":"rewrite_strip"}`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	if got, ok := preservedClaudeIdentityMode(path, "user@example.com", "account-1"); !ok || got != ClaudeIdentityModeRewriteStripCCH {
		t.Fatalf("same account did not retain mode: got=%q ok=%v", got, ok)
	}
	if _, ok := preservedClaudeIdentityMode(path, "user@example.com", "different-account"); ok {
		t.Fatal("mismatched account UUID retained old mode")
	}
	if _, ok := preservedClaudeIdentityMode(path, "other@example.com", ""); ok {
		t.Fatal("mismatched email retained old mode")
	}
	if _, ok := preservedClaudeIdentityMode(path, "user@example.com", ""); ok {
		t.Fatal("replacement without UUID retained UUID-bound mode by email")
	}
}

func TestAnthropicReloginReturnsObjectWithPreservedMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "claude-user.json")
	old := `{"type":"claude","provider":"anthropic","access_token":"old-token","refresh_token":"old-refresh","email":"user@example.com","account_uuid":"account-1","claude_identity_mode":"rewrite_strip"}`
	if err := os.WriteFile(path, []byte(old), 0600); err != nil {
		t.Fatal(err)
	}
	raw := map[string]any{
		"type":          "claude",
		"provider":      ProviderAnthropic,
		"access_token":  "new-token",
		"refresh_token": "new-refresh",
		"email":         "user@example.com",
		"account_uuid":  "account-1",
	}
	a, err := writeAnthropicLoginCredential(path, "user@example.com", "account-1", raw)
	if err != nil {
		t.Fatal(err)
	}
	if got := a.ClaudeIdentityModeValue(); got != ClaudeIdentityModeRewriteStripCCH {
		t.Fatalf("replacement object lost mode: %q", got)
	}
	token, _ := a.Credentials()
	if token != "new-token" {
		t.Fatalf("replacement object retained stale token: %q", token)
	}
}

func TestPoolIdentityModeSwitchRequiresDrainedDisabledCredential(t *testing.T) {
	a := &Auth{
		ID:          "claude-account",
		Kind:        KindOAuth,
		Provider:    ProviderAnthropic,
		Email:       "user@example.com",
		AccountUUID: "account-1",
		AccessToken: "token",
	}
	p := NewPool([]*Auth{a}, nil, time.Hour, false, "")
	if err := p.UpdateClaudeIdentityMode(a.ID, ClaudeIdentityModeRewriteStripCCH); !errors.Is(err, ErrClaudeIdentityModeCredentialEnabled) {
		t.Fatalf("enabled credential: %v", err)
	}

	a.SetDisabled(true)
	p.sessions[slotKey(ProviderAnthropic, "client", "session")] = &session{
		clientToken: "client",
		sessionID:   "session",
		provider:    ProviderAnthropic,
		authID:      a.ID,
		kind:        KindOAuth,
		lastSeen:    time.Now(),
	}
	if err := p.UpdateClaudeIdentityMode(a.ID, ClaudeIdentityModeRewriteStripCCH); !errors.Is(err, ErrClaudeIdentityModeCredentialActive) {
		t.Fatalf("active credential: %v", err)
	}

	p.sessions = make(map[string]*session)
	if err := p.UpdateClaudeIdentityMode(a.ID, ClaudeIdentityModeRewriteStripCCH); err != nil {
		t.Fatal(err)
	}
	if got := a.ClaudeIdentityModeValue(); got != ClaudeIdentityModeRewriteStripCCH {
		t.Fatalf("mode not updated: %q", got)
	}
}

func TestPoolOAuthReplacementKeepsLatestModeForSameAccount(t *testing.T) {
	current := &Auth{
		ID:                 "claude-account",
		Kind:               KindOAuth,
		Provider:           ProviderAnthropic,
		Email:              "user@example.com",
		AccountUUID:        "account-1",
		claudeIdentityMode: ClaudeIdentityModeRewriteStripCCH,
	}
	p := NewPool([]*Auth{current}, nil, time.Hour, false, "")
	staleReplacement := &Auth{
		ID:          current.ID,
		Kind:        KindOAuth,
		Provider:    ProviderAnthropic,
		Email:       current.Email,
		AccountUUID: current.AccountUUID,
	}
	if err := p.AddOAuth(staleReplacement); err != nil {
		t.Fatal(err)
	}
	if got := p.FindByID(current.ID).ClaudeIdentityModeValue(); got != ClaudeIdentityModeRewriteStripCCH {
		t.Fatalf("same-account replacement lost latest mode: %q", got)
	}
	missingUUIDReplacement := &Auth{
		ID:       current.ID,
		Kind:     KindOAuth,
		Provider: ProviderAnthropic,
		Email:    current.Email,
	}
	if err := p.AddOAuth(missingUUIDReplacement); err != nil {
		t.Fatal(err)
	}
	if got := p.FindByID(current.ID).ClaudeIdentityModeValue(); got != ClaudeIdentityModePreserve {
		t.Fatalf("replacement without UUID inherited rewrite mode: %q", got)
	}

	differentAccount := &Auth{
		ID:          current.ID,
		Kind:        KindOAuth,
		Provider:    ProviderAnthropic,
		Email:       current.Email,
		AccountUUID: "account-2",
	}
	if err := p.AddOAuth(differentAccount); err != nil {
		t.Fatal(err)
	}
	if got := p.FindByID(current.ID).ClaudeIdentityModeValue(); got != ClaudeIdentityModePreserve {
		t.Fatalf("different account inherited prior mode: %q", got)
	}
}

func TestPoolRewriteRequiresAccountUUID(t *testing.T) {
	a := &Auth{ID: "legacy", Kind: KindOAuth, Provider: ProviderAnthropic, Email: "legacy@example.com", Disabled: true}
	p := NewPool([]*Auth{a}, nil, time.Hour, false, "")
	if err := p.UpdateClaudeIdentityMode(a.ID, ClaudeIdentityModeRewriteStripCCH); !errors.Is(err, ErrClaudeIdentityModeMissingAccountUUID) {
		t.Fatalf("missing UUID: %v", err)
	}
}

func TestStaleIdentityModeUpdateCannotOverwriteReplacedAccount(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "claude-user.json")
	oldData := []byte(`{"type":"claude","provider":"anthropic","access_token":"old-token","refresh_token":"old-refresh","email":"old@example.com","account_uuid":"account-old","disabled":true}`)
	if err := os.WriteFile(path, oldData, 0600); err != nil {
		t.Fatal(err)
	}
	stale, err := ParseFile(path, oldData)
	if err != nil {
		t.Fatal(err)
	}
	newData := []byte(`{"type":"claude","provider":"anthropic","access_token":"new-token","refresh_token":"new-refresh","email":"new@example.com","account_uuid":"account-new","disabled":true}`)
	installed, err := InstallCredentialFile(path, newData)
	if err != nil {
		t.Fatal(err)
	}
	if err := stale.UpdateClaudeIdentityMode(ClaudeIdentityModeRewriteStripCCH); !errors.Is(err, ErrCredentialFileAccountMismatch) {
		t.Fatalf("stale mode update: %v", err)
	}
	reloadedData, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err := ParseFile(path, reloadedData)
	if err != nil {
		t.Fatal(err)
	}
	token, _ := reloaded.Credentials()
	if token != "new-token" || reloaded.AccountUUIDValue() != "account-new" {
		t.Fatalf("replacement was clobbered: token=%q account=%q", token, reloaded.AccountUUIDValue())
	}
	if reloaded.ClaudeIdentityModeValue() != ClaudeIdentityModePreserve || installed.ClaudeIdentityModeValue() != ClaudeIdentityModePreserve {
		t.Fatal("different account inherited rewrite mode")
	}
}

func TestConcurrentInstallAndIdentityModeUpdateNeverMixAccounts(t *testing.T) {
	for i := 0; i < 64; i++ {
		dir := t.TempDir()
		path := filepath.Join(dir, "claude-user.json")
		oldData := []byte(`{"type":"claude","provider":"anthropic","access_token":"old-token","refresh_token":"old-refresh","account_uuid":"account-old","disabled":true}`)
		if err := os.WriteFile(path, oldData, 0600); err != nil {
			t.Fatal(err)
		}
		stale, err := ParseFile(path, oldData)
		if err != nil {
			t.Fatal(err)
		}
		newData := []byte(`{"type":"claude","provider":"anthropic","access_token":"new-token","refresh_token":"new-refresh","account_uuid":"account-new","disabled":true}`)
		start := make(chan struct{})
		errCh := make(chan error, 2)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			errCh <- stale.UpdateClaudeIdentityMode(ClaudeIdentityModeRewriteStripCCH)
		}()
		go func() {
			defer wg.Done()
			<-start
			_, installErr := InstallCredentialFile(path, newData)
			errCh <- installErr
		}()
		close(start)
		wg.Wait()
		close(errCh)
		for operationErr := range errCh {
			if operationErr != nil && !errors.Is(operationErr, ErrCredentialFileAccountMismatch) {
				t.Fatalf("iteration %d: unexpected operation error: %v", i, operationErr)
			}
		}
		finalData, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		final, err := ParseFile(path, finalData)
		if err != nil {
			t.Fatal(err)
		}
		token, _ := final.Credentials()
		if token != "new-token" || final.AccountUUIDValue() != "account-new" ||
			final.ClaudeIdentityModeValue() != ClaudeIdentityModePreserve {
			t.Fatalf("iteration %d mixed credential state: token=%q account=%q mode=%q", i, token, final.AccountUUIDValue(), final.ClaudeIdentityModeValue())
		}
	}
}

func TestConcurrentSameAccountReplacementAndPoolModeUpdateStayConsistent(t *testing.T) {
	for i := 0; i < 32; i++ {
		dir := t.TempDir()
		path := filepath.Join(dir, "claude-user.json")
		oldData := []byte(`{"type":"claude","provider":"anthropic","access_token":"old-token","refresh_token":"old-refresh","account_uuid":"account-1","disabled":true}`)
		if err := os.WriteFile(path, oldData, 0600); err != nil {
			t.Fatal(err)
		}
		current, err := ParseFile(path, oldData)
		if err != nil {
			t.Fatal(err)
		}
		p := NewPool([]*Auth{current}, nil, time.Hour, false, "")
		newData := []byte(`{"type":"claude","provider":"anthropic","access_token":"new-token","refresh_token":"new-refresh","account_uuid":"account-1","disabled":true}`)
		replacement, err := InstallCredentialFile(path, newData)
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		errCh := make(chan error, 2)
		go func() {
			<-start
			errCh <- p.UpdateClaudeIdentityMode(current.ID, ClaudeIdentityModeRewriteStripCCH)
		}()
		go func() {
			<-start
			errCh <- p.AddOAuth(replacement)
		}()
		close(start)
		for j := 0; j < 2; j++ {
			if operationErr := <-errCh; operationErr != nil {
				t.Fatalf("iteration %d: %v", i, operationErr)
			}
		}
		published := p.FindByID(current.ID)
		if published == nil || published.ClaudeIdentityModeValue() != ClaudeIdentityModeRewriteStripCCH {
			t.Fatalf("iteration %d: pool mode=%v", i, published)
		}
		finalData, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		final, err := ParseFile(path, finalData)
		if err != nil {
			t.Fatal(err)
		}
		token, _ := final.Credentials()
		if token != "new-token" || final.ClaudeIdentityModeValue() != ClaudeIdentityModeRewriteStripCCH {
			t.Fatalf("iteration %d: disk token=%q mode=%q", i, token, final.ClaudeIdentityModeValue())
		}
	}
}

func TestInstallSameAccountPreservesIdentityMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "claude-user.json")
	oldData := []byte(`{"type":"claude","provider":"anthropic","access_token":"old-token","refresh_token":"old-refresh","email":"user@example.com","account_uuid":"account-1","disabled":true,"claude_identity_mode":"rewrite_strip"}`)
	if err := os.WriteFile(path, oldData, 0600); err != nil {
		t.Fatal(err)
	}
	newData := []byte(`{"type":"claude","provider":"anthropic","access_token":"new-token","refresh_token":"new-refresh","email":"user@example.com","account_uuid":"account-1","disabled":true}`)
	installed, err := InstallCredentialFile(path, newData)
	if err != nil {
		t.Fatal(err)
	}
	if installed.ClaudeIdentityModeValue() != ClaudeIdentityModeRewriteStripCCH {
		t.Fatalf("same account lost mode: %q", installed.ClaudeIdentityModeValue())
	}
	token, _ := installed.Credentials()
	if token != "new-token" {
		t.Fatalf("same-account install retained stale token: %q", token)
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
