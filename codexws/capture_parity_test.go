package codexws

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wjsoj/cc-core/mimicry"
)

// The handshake this package synthesizes is checked against the captured one in
// crack/, rather than against constants copied out of it by hand. Copying is how
// the two drifted the last time: codexws asserted "no routing hint on the
// upgrade" for two releases after the capture that would have contradicted it
// was taken, because nothing read the capture.
//
// This test reads the row. If a future capture changes the wire shape, this
// fails without anyone having to remember which constants encode it.
const capturedHandshakeRow = "../crack/codexv0.153.4/rows/10-ws-handshake-codex-responses.json"

type capturedRow struct {
	ReqHeaders     map[string]string `json:"req_headers"`
	ReqHeaderOrder []string          `json:"req_header_order"`
}

// dialerOwnedHeaders are written by gorilla and by the TLS layer, not by
// BuildUpstreamHeaders, so the captured row carries them and we must not.
var dialerOwnedHeaders = map[string]bool{
	"Host": true, "Connection": true, "Upgrade": true,
	"Sec-WebSocket-Version": true, "Sec-WebSocket-Key": true,
	"sec-websocket-extensions": true,
}

func loadCapturedRow(t *testing.T, path string) capturedRow {
	t.Helper()
	b, err := os.ReadFile(filepath.FromSlash(path))
	if err != nil {
		t.Skipf("capture row unavailable (%v); parity check skipped", err)
	}
	var row capturedRow
	if err := json.Unmarshal(b, &row); err != nil {
		t.Fatalf("capture row is not valid JSON: %v", err)
	}
	return row
}

// parityProfiles pairs each client identity with the captured upgrade it must
// reproduce. Both are pinned, not just the default one: the default is a
// deployment choice that has now flipped twice, and a parity suite that only
// covered whichever profile happened to be default would go quiet on the other
// exactly when someone flips it.
func parityProfiles() []struct {
	name    string
	profile mimicry.CodexClientProfile
	row     string
} {
	return []struct {
		name    string
		profile mimicry.CodexClientProfile
		row     string
	}{
		{"desktop", mimicry.CodexDesktopClientProfile(), capturedDesktopOrdinaryRow},
		{"cli", mimicry.CodexTUIClientProfile(), capturedHandshakeRow},
	}
}

func buildParityHeadersFor(profile mimicry.CodexClientProfile) map[string][]string {
	// Pinned to the host every capture was taken on. The header builder now
	// binds a profile to the account's machine, so without this the comparison
	// would be against whichever machine the literal "acct-uuid" happens to
	// hash to — and would fail or pass for reasons that have nothing to do with
	// the parity being asserted.
	profile = profile.WithHost(mimicry.CodexCapturedHostProfile)
	return BuildUpstreamHeadersWithOptions(UpstreamHeaderOptions{
		Profile:     &profile,
		AccessToken: "tok",
		AccountID:   "acct-uuid",
		SessionID:   "01a06fa9-a7f8-7811-8a75-3dccb3ea9a71",
		Model:       "gpt-5.6-sol",
		// Passed explicitly: the tier is not defaulted, because a hint that
		// claims a tier the request did not ask for is billed as standard and
		// served as priority. The captured account did request it.
		ServiceTier: "priority",
	})
}

// TestHandshakeMatchesCapturedHeaderOrder pins the wire order against the
// capture, minus the headers the dialer owns.
func TestHandshakeMatchesCapturedHeaderOrder(t *testing.T) {
	for _, tc := range parityProfiles() {
		t.Run(tc.name, func(t *testing.T) { assertHeaderOrderParity(t, tc.profile, tc.row) })
	}
}

func assertHeaderOrderParity(t *testing.T, profile mimicry.CodexClientProfile, rowPath string) {
	t.Helper()
	row := loadCapturedRow(t, rowPath)
	h := buildParityHeadersFor(profile)

	var want []string
	for _, name := range row.ReqHeaderOrder {
		if !dialerOwnedHeaders[name] {
			want = append(want, name)
		}
	}
	var got []string
	for _, name := range HandshakeHeaderOrder() {
		if _, ok := h[name]; ok {
			got = append(got, name)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("emit %d headers %v, capture has %d %v", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("header %d = %q, capture has %q\n  ours    %v\n  capture %v", i, got[i], want[i], got, want)
		}
	}
}

// TestHandshakeMatchesCapturedIdentityHeaders pins the values that are constants
// rather than per-session ids.
func TestHandshakeMatchesCapturedIdentityHeaders(t *testing.T) {
	for _, tc := range parityProfiles() {
		t.Run(tc.name, func(t *testing.T) { assertIdentityParity(t, tc.profile, tc.row) })
	}
}

func assertIdentityParity(t *testing.T, profile mimicry.CodexClientProfile, rowPath string) {
	t.Helper()
	row := loadCapturedRow(t, rowPath)
	h := buildParityHeadersFor(profile)

	for _, name := range []string{"user-agent", "originator", "version", "x-codex-beta-features", "openai-beta"} {
		want := row.ReqHeaders[name]
		if want == "" {
			t.Fatalf("capture has no %q — the row shape changed", name)
		}
		got := ""
		if v, ok := h[name]; ok && len(v) > 0 {
			got = v[0]
		}
		if got != want {
			t.Errorf("%s = %q, capture has %q", name, got, want)
		}
	}
	// The hint's model and tier are per-request — the CLI row asked for
	// priority, the Desktop row named a model alone — so only OUR format is
	// comparable, not the captured value.
	if got := h[mimicry.CodexRoutingHintHeader]; len(got) == 0 || got[0] != "model=gpt-5.6-sol;tier=priority" {
		t.Errorf("x-codex-routing-hint = %v, want model=gpt-5.6-sol;tier=priority (capture: %q)",
			got, row.ReqHeaders[mimicry.CodexRoutingHintHeader])
	}
}

// TestHandshakeMetadataMatchesCapturedShape pins the turn-metadata key SET, its
// ORDER, and each value's JSON TYPE against the capture. Types matter on their
// own: window_number is a number and the three flags are booleans, and quoting
// any of them is a one-character tell.
func TestHandshakeMetadataMatchesCapturedShape(t *testing.T) {
	for _, tc := range parityProfiles() {
		t.Run(tc.name, func(t *testing.T) { assertMetadataShapeParity(t, tc.profile, tc.row) })
	}
}

func assertMetadataShapeParity(t *testing.T, profile mimicry.CodexClientProfile, rowPath string) {
	t.Helper()
	row := loadCapturedRow(t, rowPath)
	h := buildParityHeadersFor(profile)

	ours, ok := h["x-codex-turn-metadata"]
	if !ok || len(ours) == 0 {
		t.Fatal("no x-codex-turn-metadata emitted")
	}
	gotKeys, gotTypes := decodeOrderedJSON(t, ours[0])
	wantKeys, wantTypes := decodeOrderedJSON(t, row.ReqHeaders["x-codex-turn-metadata"])

	if len(gotKeys) != len(wantKeys) {
		t.Fatalf("emit %d metadata keys %v, capture has %d %v",
			len(gotKeys), gotKeys, len(wantKeys), wantKeys)
	}
	for i := range wantKeys {
		if gotKeys[i] != wantKeys[i] {
			t.Fatalf("metadata key %d = %q, capture has %q\n  ours    %v\n  capture %v",
				i, gotKeys[i], wantKeys[i], gotKeys, wantKeys)
		}
		if gotTypes[i] != wantTypes[i] {
			t.Errorf("metadata %q is %s, capture has %s", wantKeys[i], gotTypes[i], wantTypes[i])
		}
	}
}

// decodeOrderedJSON returns a flat JSON object's keys in document order and the
// Go type each value decodes to. json.Unmarshal into a map would sort the keys,
// which is exactly what this has to detect, so it streams tokens instead.
func decodeOrderedJSON(t *testing.T, raw string) (keys, types []string) {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(raw))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		t.Fatalf("metadata is not a JSON object: %v (%v)", err, tok)
	}
	for dec.More() {
		k, err := dec.Token()
		if err != nil {
			t.Fatalf("reading metadata key: %v", err)
		}
		name, _ := k.(string)
		var v any
		if err := dec.Decode(&v); err != nil {
			t.Fatalf("reading value of %q: %v", name, err)
		}
		keys = append(keys, name)
		switch v.(type) {
		case string:
			types = append(types, "string")
		case float64:
			types = append(types, "number")
		case bool:
			types = append(types, "bool")
		case nil:
			types = append(types, "null")
		default:
			types = append(types, "other")
		}
	}
	return keys, types
}

// capturedDesktopOrdinaryRow is an ORDINARY-thread WebSocket upgrade from the
// Codex Desktop app, captured against the same backend two days after the CLI
// row above.
const capturedDesktopOrdinaryRow = "../crack/codexapp0.153.4/rows/10-ws-handshake-desktop.json"

// TestOrdinaryDesktopHandshakeMatchesCLIShape pins the fact this whole package
// rests on: there is ONE handshake shape, not one per client.
//
// It was briefly believed that Codex Desktop sent a different, 18-header
// upgrade, and a profile-switched header set and order were built for it. That
// reading was wrong. All 19 upgrades in crack/codexapp0.153.4 carry originator
// "Codex Desktop" — there is no codex-tui row in that capture to contrast with
// — and the ordinary-thread ones match the codex-tui upgrade exactly. The
// 18-header shape belongs to an auto-review GUARDIAN subagent running
// Responses-Lite, a connection kind a proxy never has; see
// crack/codexapp0.153.4/SPEC.md §3.
//
// If this test ever fails, the two clients have genuinely diverged and
// handshakeHeaderOrder can no longer serve both. That is the trigger to
// reintroduce a per-profile shape — and not before.
func TestOrdinaryDesktopHandshakeMatchesCLIShape(t *testing.T) {
	cli := loadCapturedRow(t, capturedHandshakeRow)
	desktop := loadCapturedRow(t, capturedDesktopOrdinaryRow)

	// Sanity: they really are the two different clients.
	if got := cli.ReqHeaders["originator"]; got != mimicry.CodexOriginator {
		t.Fatalf("CLI row originator = %q, want %q — wrong row?", got, mimicry.CodexOriginator)
	}
	if got := desktop.ReqHeaders["originator"]; got != mimicry.CodexDesktopOriginator {
		t.Fatalf("Desktop row originator = %q, want %q — wrong row?", got, mimicry.CodexDesktopOriginator)
	}

	if len(cli.ReqHeaderOrder) != len(desktop.ReqHeaderOrder) {
		t.Fatalf("header counts differ: CLI %d %v, Desktop %d %v",
			len(cli.ReqHeaderOrder), cli.ReqHeaderOrder,
			len(desktop.ReqHeaderOrder), desktop.ReqHeaderOrder)
	}
	for i := range cli.ReqHeaderOrder {
		if cli.ReqHeaderOrder[i] != desktop.ReqHeaderOrder[i] {
			t.Fatalf("header %d differs: CLI %q, Desktop %q\n  CLI     %v\n  Desktop %v",
				i, cli.ReqHeaderOrder[i], desktop.ReqHeaderOrder[i],
				cli.ReqHeaderOrder, desktop.ReqHeaderOrder)
		}
	}

	// And neither ordinary upgrade carries the guardian/Responses-Lite markers.
	for _, row := range []capturedRow{cli, desktop} {
		for _, name := range []string{mimicry.CodexResponsesLiteHeader, "x-openai-subagent"} {
			if _, ok := row.ReqHeaders[name]; ok {
				t.Errorf("an ordinary upgrade must not carry %q", name)
			}
		}
	}
}
