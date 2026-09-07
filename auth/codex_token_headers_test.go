package auth

import (
	"bytes"
	"net/http"
	"strings"
	"testing"

	"github.com/wjsoj/cc-core/mimicry"
)

// wireOf serializes a request the way net/http will actually put it on the
// wire. These tests assert against that rather than the header map, because the
// map is not where this goes wrong: net/http fills a User-Agent from a
// dedicated slot in Request.Write whenever the canonical key is ABSENT, so
// Header.Del and Set("User-Agent", "") both still emit "Go-http-client/1.1".
// Only a present-but-nil entry suppresses it.
func wireOf(t *testing.T, req *http.Request) string {
	t.Helper()
	var buf bytes.Buffer
	if err := req.Write(&buf); err != nil {
		t.Fatalf("req.Write: %v", err)
	}
	return buf.String()
}

// The form-encoded grants (authorization_code, RFC 8693 token-exchange) send no
// User-Agent and no originator at all — crack/codexapp0.153.4/rows/02 and /04.
func TestCodexFormGrantSendsNoIdentityHeaders(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, openaiTokenURL,
		strings.NewReader("grant_type=authorization_code"))
	if err != nil {
		t.Fatal(err)
	}
	applyCodexFormGrantHeaders(req)
	wire := wireOf(t, req)

	if strings.Contains(wire, "Go-http-client") {
		t.Errorf("net/http's default User-Agent reached the wire:\n%s", wire)
	}
	if strings.Contains(strings.ToLower(wire), "user-agent:") {
		t.Errorf("the form-encoded grants send no User-Agent:\n%s", wire)
	}
	if strings.Contains(strings.ToLower(wire), "originator:") {
		t.Errorf("the form-encoded grants send no originator:\n%s", wire)
	}
	if got := req.Header.Get("Accept"); got != "*/*" {
		t.Errorf("Accept = %q, want */* (the captured value)", got)
	}
	if got := req.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q, want application/x-www-form-urlencoded", got)
	}
}

// The refresh_token grant is the one that DOES identify itself: JSON body,
// Desktop originator, Desktop UA — crack/codexapp0.153.4/rows/01.
func TestCodexRefreshGrantIdentifiesItselfAsTheActiveClient(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, openaiTokenURL,
		bytes.NewReader(buildCodexRefreshBody("rt.1.test")))
	if err != nil {
		t.Fatal(err)
	}
	applyCodexRefreshGrantHeaders(req)

	if got := req.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json (the refresh grant is JSON)", got)
	}
	if got := req.Header.Get("Accept"); got != "*/*" {
		t.Errorf("Accept = %q, want */*", got)
	}

	// The row that established this grant's shape is a Codex Desktop capture,
	// so an earlier version of this test pinned the Desktop constants. What the
	// row actually establishes is that this grant — alone of the three —
	// identifies itself at all. WHICH client it names has to follow the profile
	// we present everywhere else, or one credential forwards traffic as
	// codex-tui and refreshes as Codex Desktop.
	profile := mimicry.DefaultCodexProfile()
	if got := req.Header.Get("Originator"); got != profile.Originator {
		t.Errorf("Originator = %q, want the active profile's %q", got, profile.Originator)
	}
	if got := req.Header.Get("User-Agent"); got != profile.UserAgent {
		t.Errorf("User-Agent = %q, want the active profile's %q", got, profile.UserAgent)
	}
	// Whichever profile is active, the UA must be the full form — both
	// endpoints that never vary in the capture use it (SPEC §1).
	if got := req.Header.Get("User-Agent"); !strings.HasSuffix(got, ")") {
		t.Errorf("User-Agent %q is not the full form; the token endpoint sends the full UA", got)
	}
}

func TestHeaderDelDoesNotSuppressGoUserAgent(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, openaiTokenURL, strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Del("User-Agent")

	if !strings.Contains(wireOf(t, req), "Go-http-client") {
		t.Skip("net/http no longer substitutes a default User-Agent; " +
			"applyCodexFormGrantHeaders can be simplified")
	}
}
