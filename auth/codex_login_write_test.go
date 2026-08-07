package auth

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func codexRaw(accountID, email, token string) map[string]any {
	return map[string]any{
		"type":          "codex",
		"provider":      ProviderOpenAI,
		"access_token":  token,
		"refresh_token": "refresh-" + token,
		"email":         email,
		"account_id":    accountID,
		"plan_type":     "plus",
		"expired":       time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		"last_refresh":  time.Now().UTC().Format(time.RFC3339),
		"label":         email,
	}
}

// A re-login for the same ChatGPT account replaces the file in place.
func TestCodexLoginOverwritesSameAccount(t *testing.T) {
	path := filepath.Join(t.TempDir(), "codex-a@example.com-plus.json")

	if _, err := writeCodexLoginCredential(path, codexRaw("acct-1", "a@example.com", "old")); err != nil {
		t.Fatalf("initial write: %v", err)
	}
	a, err := writeCodexLoginCredential(path, codexRaw("acct-1", "a@example.com", "new"))
	if err != nil {
		t.Fatalf("re-login for the same account must be allowed: %v", err)
	}
	if tok, _ := a.Credentials(); tok != "new" {
		t.Fatalf("access token = %q, want the freshly minted one", tok)
	}
}

// A login landing on a file that belongs to a different ChatGPT account must be
// refused, not silently overwritten — the same rule Anthropic logins follow.
// Two accounts can collide on one filename when they share an email (the name is
// built from email+plan), and clobbering the loser costs a live credential.
func TestCodexLoginRefusesDifferentAccountOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "codex-a@example.com-plus.json")

	if _, err := writeCodexLoginCredential(path, codexRaw("acct-1", "a@example.com", "first")); err != nil {
		t.Fatalf("initial write: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}

	_, err = writeCodexLoginCredential(path, codexRaw("acct-2", "a@example.com", "second"))
	if !errors.Is(err, ErrCredentialFileAccountMismatch) {
		t.Fatalf("error = %v, want ErrCredentialFileAccountMismatch", err)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after refusal: %v", err)
	}
	if string(after) != string(before) {
		t.Fatalf("refused login still modified the credential file")
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temp file left behind after a refused login")
	}
}

// Older Codex credential files predate the chatgpt_account_id claim; email is
// the fallback identity so those files stay re-loginable.
func TestCodexLoginFallsBackToEmailWhenAccountIDMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "codex-a@example.com.json")

	if _, err := writeCodexLoginCredential(path, codexRaw("", "a@example.com", "old")); err != nil {
		t.Fatalf("initial write: %v", err)
	}
	if _, err := writeCodexLoginCredential(path, codexRaw("", "a@example.com", "new")); err != nil {
		t.Fatalf("same-email re-login must be allowed: %v", err)
	}
	if _, err := writeCodexLoginCredential(path, codexRaw("", "b@example.com", "other")); !errors.Is(err, ErrCredentialFileAccountMismatch) {
		t.Fatalf("different-email overwrite: err = %v, want ErrCredentialFileAccountMismatch", err)
	}
}

// A file that doesn't exist yet, or one too corrupt to parse, is not a mismatch
// — the login must still be able to install a working credential.
func TestCodexLoginWritesOverUnparseableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "codex-a@example.com-plus.json")
	if err := os.WriteFile(path, []byte("{not json"), 0600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := writeCodexLoginCredential(path, codexRaw("acct-1", "a@example.com", "tok")); err != nil {
		t.Fatalf("unparseable existing file must not block a login: %v", err)
	}
}
