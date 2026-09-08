package mimicry

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The model fetch has its own identity, and it is NOT the same rule for both
// clients: codex-tui sends the codex-rs library's originator because that
// request is made by the library, while Desktop sends its own originator and
// merely drops the build parenthetical from its User-Agent.
//
// This is pinned against the captures because it was a single shared constant
// until the default profile flipped to Desktop, at which point the manifest
// request would have gone out with a Desktop client_version under a codex-tui
// User-Agent — a pairing neither capture contains. A shared constant looks
// correct for exactly as long as only one profile is ever used.
func TestModelsIdentityMatchesCapturedRows(t *testing.T) {
	for _, tc := range []struct {
		name    string
		profile CodexClientProfile
		row     string
	}{
		{"desktop", CodexDesktopClientProfile(), "../crack/codexapp0.153.4/rows/12-get-codex-models.json"},
		{"cli", CodexTUIClientProfile(), "../crack/codexv0.153.4/rows/01-get-codex-models.json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := os.ReadFile(filepath.FromSlash(tc.row))
			if err != nil {
				t.Skipf("capture row unavailable (%v); parity check skipped", err)
			}
			var row struct {
				URL        string            `json:"url"`
				ReqHeaders map[string]string `json:"req_headers"`
			}
			if err := json.Unmarshal(b, &row); err != nil {
				t.Fatalf("capture row is not valid JSON: %v", err)
			}

			if got, want := tc.profile.ModelsOriginator, row.ReqHeaders["originator"]; got != want {
				t.Errorf("models originator = %q, capture has %q", got, want)
			}
			if got, want := tc.profile.ModelsUserAgent, row.ReqHeaders["user-agent"]; got != want {
				t.Errorf("models user-agent = %q, capture has %q", got, want)
			}
			if got, want := tc.profile.ModelsClientVersion, row.ReqHeaders["version"]; got != want {
				t.Errorf("models client version = %q, capture's version header has %q", got, want)
			}
			// The query parameter and the Version header are the same value in
			// both captures; a client_version that disagrees with the header it
			// travels with is a one-comparison tell.
			if want := "client_version=" + tc.profile.ModelsClientVersion; !strings.Contains(row.URL, want) {
				t.Errorf("captured URL %q does not carry %q", row.URL, want)
			}
		})
	}
}

// The models UA must be the handshake UA with a suffix removed, never a
// separately typed string — that is what stops a version bump moving one and
// leaving the other stale.
func TestDesktopModelsUserAgentIsDerivedFromTheFullOne(t *testing.T) {
	full := CodexDesktopClientProfile().UserAgent
	base := CodexDesktopClientProfile().ModelsUserAgent
	if base == full {
		t.Fatal("Desktop models UA is identical to the handshake UA; the capture drops the build parenthetical")
	}
	if !strings.HasPrefix(full, base) {
		t.Fatalf("Desktop models UA %q is not a prefix of the full UA %q — they have drifted apart", base, full)
	}
}
