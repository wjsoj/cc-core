package auth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func codexAuthWithExpiry(remaining, earliestIn time.Duration) *Auth {
	a := &Auth{
		ID:           "codex-test.json",
		Kind:         KindOAuth,
		Provider:     ProviderOpenAI,
		AccessToken:  "at",
		RefreshToken: "rt",
		ExpiresAt:    time.Now().Add(remaining),
	}
	if earliestIn != 0 {
		a.EarliestRefreshAt = time.Now().Add(earliestIn)
	}
	return a
}

// The whole point of the change: a token 5 days from expiry is inside our
// MinRefreshLeeway, but the server said it will not mint a replacement for
// another 4 days. We wait.
func TestEarliestRefreshAtDefersScheduledRefresh(t *testing.T) {
	// 10-day token, day 5 — earliest_refresh_at is at day 9, i.e. 4 days out.
	a := codexAuthWithExpiry(5*24*time.Hour, 4*24*time.Hour)
	if a.needsRefresh(a.MinRefreshLeeway()) {
		t.Fatal("refreshed before earliest_refresh_at; the server's embargo must win over MinRefreshLeeway")
	}
}

// Past the embargo, the ordinary leeway takes over again.
func TestRefreshResumesAfterEarliestRefreshAt(t *testing.T) {
	a := codexAuthWithExpiry(24*time.Hour, -time.Minute) // embargo lifted a minute ago
	if !a.needsRefresh(a.MinRefreshLeeway()) {
		t.Fatal("earliest_refresh_at has passed and the token is inside the leeway; refresh must proceed")
	}
}

// A credential file written before the field existed carries no embargo and
// must behave exactly as it did before.
func TestNoEarliestRefreshAtKeepsLegacyBehaviour(t *testing.T) {
	a := codexAuthWithExpiry(5*24*time.Hour, 0)
	if !a.needsRefresh(a.MinRefreshLeeway()) {
		t.Fatal("without earliest_refresh_at the 5-day leeway must still fire")
	}
}

// The escape hatch: an embargo that outlasts the token would strand the
// credential, so inside refreshEmbargoFloor we refresh anyway.
func TestNearExpiryOverridesEarliestRefreshAt(t *testing.T) {
	// 30 minutes of life left, embargo claims another 2 days.
	a := codexAuthWithExpiry(30*time.Minute, 48*time.Hour)
	if !a.needsRefresh(a.MinRefreshLeeway()) {
		t.Fatal("a token inside refreshEmbargoFloor must refresh regardless of the embargo")
	}
}

// A forced refresh (upstream 401 said the token is dead; operator pressed
// "refresh now") passes a leeway far beyond MinRefreshLeeway and must not be
// held back by the embargo — in exactly that case the backend has already
// contradicted its own timetable.
func TestForcedRefreshIgnoresEarliestRefreshAt(t *testing.T) {
	a := codexAuthWithExpiry(9*24*time.Hour, 8*24*time.Hour)
	if a.needsRefresh(a.MinRefreshLeeway()) {
		t.Fatal("precondition: a scheduled check must be embargoed here")
	}
	if !a.needsRefresh(time.Duration(1<<63 - 1)) {
		t.Fatal("a forced refresh must ignore earliest_refresh_at")
	}
}

// Well outside both the leeway and the embargo, nothing happens.
func TestFreshTokenNeedsNoRefresh(t *testing.T) {
	a := codexAuthWithExpiry(9*24*time.Hour, 8*24*time.Hour)
	if a.needsRefresh(5 * time.Minute) {
		t.Fatal("a token 9 days from expiry must not refresh on a 5-minute leeway")
	}
}

// The credential file must round-trip both new fields, and must still load
// when they are absent (append-only convention).
func TestCodexCredentialFileRoundTripsRefreshFields(t *testing.T) {
	dir := t.TempDir()

	t.Run("absent", func(t *testing.T) {
		path := filepath.Join(dir, "codex-legacy.json")
		data := []byte(`{"type":"codex","access_token":"at","refresh_token":"rt"}`)
		a, err := parseFile(path, data)
		if err != nil {
			t.Fatalf("a credential file without the new fields must still load: %v", err)
		}
		if !a.EarliestRefreshAt.IsZero() {
			t.Errorf("EarliestRefreshAt = %v, want zero", a.EarliestRefreshAt)
		}
		if a.OAIIS != "" {
			t.Errorf("OAIIS = %q, want empty", a.OAIIS)
		}
	})

	t.Run("present", func(t *testing.T) {
		path := filepath.Join(dir, "codex-new.json")
		earliest := time.Now().Add(72 * time.Hour).Truncate(time.Second)
		raw := map[string]any{
			"type":                "codex",
			"access_token":        "at",
			"refresh_token":       "rt",
			"earliest_refresh_at": earliest.Unix(),
			"oai_is":              "ois1.token",
		}
		data, err := json.Marshal(raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		a, err := parseFile(path, data)
		if err != nil {
			t.Fatalf("parseFile: %v", err)
		}
		if !a.EarliestRefreshAt.Equal(earliest) {
			t.Errorf("EarliestRefreshAt = %v, want %v", a.EarliestRefreshAt, earliest)
		}
		if a.OAIIS != "ois1.token" {
			t.Errorf("OAIIS = %q, want ois1.token", a.OAIIS)
		}

		// And back out to disk.
		a.FilePath = path
		if err := saveAuth(a); err != nil {
			t.Fatalf("saveAuth: %v", err)
		}
		out, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var back map[string]any
		if err := json.Unmarshal(out, &back); err != nil {
			t.Fatal(err)
		}
		if v, _ := back["earliest_refresh_at"].(float64); int64(v) != earliest.Unix() {
			t.Errorf("persisted earliest_refresh_at = %v, want %d", back["earliest_refresh_at"], earliest.Unix())
		}
		if back["oai_is"] != "ois1.token" {
			t.Errorf("persisted oai_is = %v, want ois1.token", back["oai_is"])
		}
	})
}

// The response decoder must pick up both fields from a real-shaped body.
func TestCodexTokenResponseParsesNewFields(t *testing.T) {
	body := []byte(`{"access_token":"at","token_type":"Bearer","expires_in":864000,` +
		`"scope":"openid profile email offline_access","id_token":"idt",` +
		`"earliest_refresh_at":1789547129,"refresh_token":"rt","oai_is":"ois1.jwt"}`)
	var tr codexTokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		t.Fatal(err)
	}
	if tr.ExpiresIn != 864000 {
		t.Errorf("ExpiresIn = %d, want 864000 (10 days, not the ~30 the old comment claimed)", tr.ExpiresIn)
	}
	if got := tr.EarliestRefresh(); got.Unix() != 1789547129 {
		t.Errorf("EarliestRefresh() = %v, want unix 1789547129", got)
	}
	if tr.OAIIS != "ois1.jwt" {
		t.Errorf("OAIIS = %q, want ois1.jwt", tr.OAIIS)
	}

	var missing codexTokenResponse
	if err := json.Unmarshal([]byte(`{"access_token":"at"}`), &missing); err != nil {
		t.Fatal(err)
	}
	if !missing.EarliestRefresh().IsZero() {
		t.Error("an absent earliest_refresh_at must decode to the zero time, not the unix epoch")
	}
}
