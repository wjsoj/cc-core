package auth

import (
	"encoding/json"
	"strings"
	"testing"
)

// The refresh_token grant body is JSON with exactly three fields in the order
// client_id, grant_type, refresh_token — crack/codexapp0.153.4/rows/01.
//
// Asserted on the raw bytes, not on a decoded map: order is the whole point,
// and decoding throws it away. A map-based builder would emit the same three
// fields alphabetised (client_id, grant_type, refresh_token happens to survive
// that, which is exactly why this test must check bytes and must also check
// that no fourth field exists to be sorted).
func TestCodexRefreshBodyShape(t *testing.T) {
	got := string(buildCodexRefreshBody("rt.1.SECRET"))

	want := `{"client_id":"` + openaiClientID + `","grant_type":"refresh_token","refresh_token":"rt.1.SECRET"}`
	if got != want {
		t.Errorf("refresh body =\n  %s\nwant\n  %s", got, want)
	}

	// The trap SPEC §2 calls out first: cc-core used to send
	// scope="openid profile email"; the real client sends no scope at all.
	if strings.Contains(got, "scope") {
		t.Errorf("refresh body must not carry a scope:\n%s", got)
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(got), &fields); err != nil {
		t.Fatalf("refresh body is not valid JSON: %v", err)
	}
	if len(fields) != 3 {
		t.Errorf("refresh body has %d fields, want exactly 3: %s", len(fields), got)
	}
}

// The authorization_code body's field order is grant_type, code, redirect_uri,
// client_id, code_verifier — crack/codexapp0.153.4/rows/02. url.Values.Encode
// would sort it into client_id, code, code_verifier, grant_type, redirect_uri,
// an order no genuine client emits.
func TestCodexAuthCodeBodyFieldOrder(t *testing.T) {
	got := buildCodexAuthCodeBody("ac_CODE", "VERIFIER")

	want := "grant_type=authorization_code" +
		"&code=ac_CODE" +
		"&redirect_uri=" + "http%3A%2F%2Flocalhost%3A1455%2Fauth%2Fcallback" +
		"&client_id=" + openaiClientID +
		"&code_verifier=VERIFIER"
	if got != want {
		t.Errorf("auth-code body =\n  %s\nwant\n  %s", got, want)
	}

	// Guard the specific regression: the alphabetised form.
	if strings.HasPrefix(got, "client_id=") {
		t.Errorf("auth-code body looks alphabetised (url.Values.Encode):\n%s", got)
	}

	var order []string
	for _, pair := range strings.Split(got, "&") {
		order = append(order, strings.SplitN(pair, "=", 2)[0])
	}
	wantOrder := []string{"grant_type", "code", "redirect_uri", "client_id", "code_verifier"}
	if len(order) != len(wantOrder) {
		t.Fatalf("field count = %d, want %d: %v", len(order), len(wantOrder), order)
	}
	for i := range wantOrder {
		if order[i] != wantOrder[i] {
			t.Errorf("field %d = %q, want %q (full order %v)", i, order[i], wantOrder[i], order)
		}
	}
}

// The redirect_uri must be percent-encoded in the body, as the capture shows.
func TestCodexAuthCodeBodyEscapesValues(t *testing.T) {
	got := buildCodexAuthCodeBody("a+b/c", "v=1&x")
	if strings.Contains(got, "a+b/c") || strings.Contains(got, "v=1&x") {
		t.Errorf("values were not percent-encoded:\n%s", got)
	}
}
