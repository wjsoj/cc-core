package auth

import (
	"os"
	"path/filepath"
	"testing"
)

// TestProfileForDeterministic: same account anchor always resolves to the same
// host (so one OAuth account routed through N client tokens looks like one
// machine), and the field set is always fully populated.
func TestProfileForDeterministic(t *testing.T) {
	for _, key := range []string{"acct-uuid-1", "alice@example.com", "id-only"} {
		a := ProfileFor(key)
		b := ProfileFor(key)
		if a != b {
			t.Fatalf("ProfileFor(%q) not deterministic: %+v vs %+v", key, a, b)
		}
		if a.DistroID == "" || a.Kernel == "" || a.Terminal == "" || a.Shell == "" {
			t.Errorf("ProfileFor(%q) returned incomplete profile: %+v", key, a)
		}
	}
}

// TestProfileForSpread: a population of accounts must NOT all land on one host —
// that is the whole point of the feature. Expect several distinct distros.
func TestProfileForSpread(t *testing.T) {
	d := map[string]bool{}
	for i := 0; i < 500; i++ {
		d[ProfileFor("spread-key-"+itoa(i)).DistroID] = true
	}
	if len(d) < 4 {
		t.Errorf("expected accounts spread across ≥4 distros, got %d: %v", len(d), d)
	}
}

// TestHostProfilePoolPlausible: every pool entry uses a TERM_PROGRAM-setting
// terminal and a real $SHELL basename — implausible values are a stronger fake
// signal than uniformity.
func TestHostProfilePoolPlausible(t *testing.T) {
	okTerm := map[string]bool{"vscode": true, "tmux": true, "konsole": true, "ghostty": true, "WezTerm": true}
	okShell := map[string]bool{"bash": true, "zsh": true, "fish": true}
	for _, e := range hostProfilePool {
		if e.w <= 0 {
			t.Errorf("pool entry %+v has non-positive weight", e.p)
		}
		if !okTerm[e.p.Terminal] {
			t.Errorf("pool entry %+v: terminal %q does not set TERM_PROGRAM", e.p, e.p.Terminal)
		}
		if !okShell[e.p.Shell] {
			t.Errorf("pool entry %+v: implausible shell %q", e.p, e.p.Shell)
		}
	}
}

// TestEnsureHostProfilePersistRoundTrip: first touch pins a profile to the
// credential file; reloading the file yields the same profile (stable across
// restarts and pool growth).
func TestEnsureHostProfilePersistRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "claude-acct.json")
	seed := `{"type":"claude","access_token":"sk-ant-oat01-x","refresh_token":"sk-ant-ort01-x","account_uuid":"acct-uuid-persist","organization_uuid":"org-uuid-persist"}`
	if err := os.WriteFile(path, []byte(seed), 0600); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	a, err := parseFile(path, data)
	if err != nil {
		t.Fatalf("parseFile: %v", err)
	}
	if !a.HostProfile.IsZero() {
		t.Fatalf("fresh credential should have no host_profile yet, got %+v", a.HostProfile)
	}
	if err := a.EnsureHostProfile(); err != nil {
		t.Fatalf("EnsureHostProfile: %v", err)
	}
	want := ProfileFor("acct-uuid-persist")
	if a.HostProfile != want {
		t.Errorf("in-memory profile %+v != derived %+v", a.HostProfile, want)
	}
	// Reload from disk: the pinned profile must survive verbatim.
	data2, _ := os.ReadFile(path)
	a2, err := parseFile(path, data2)
	if err != nil {
		t.Fatalf("reparse: %v", err)
	}
	if a2.HostProfile != want {
		t.Errorf("persisted profile %+v != %+v", a2.HostProfile, want)
	}
}

// itoa avoids importing strconv for one call.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
