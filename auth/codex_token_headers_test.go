package auth

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
)

// The captured POST auth.openai.com/oauth/token sends no User-Agent at all.
//
// This asserts against the real serializer rather than the header map, because
// the map is not where this goes wrong: net/http fills a User-Agent from a
// dedicated slot in Request.Write whenever the canonical key is ABSENT, so
// Header.Del and Set("User-Agent", "") both still put "Go-http-client/1.1" on
// the wire. Only a present-but-nil entry suppresses it.
func TestCodexTokenEndpointSendsNoUserAgent(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, openaiTokenURL,
		strings.NewReader("grant_type=refresh_token"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	applyCodexTokenEndpointHeaders(req)

	var buf bytes.Buffer
	if err := req.Write(&buf); err != nil {
		t.Fatalf("req.Write: %v", err)
	}
	wire := buf.String()

	if strings.Contains(wire, "Go-http-client") {
		t.Errorf("net/http's default User-Agent reached the wire:\n%s", wire)
	}
	if strings.Contains(strings.ToLower(wire), "user-agent:") {
		t.Errorf("no User-Agent may be sent to the token endpoint:\n%s", wire)
	}
	if got := req.Header.Get("Accept"); got != "*/*" {
		t.Errorf("Accept = %q, want */* (the captured value)", got)
	}
	if !strings.Contains(wire, "Content-Type: application/x-www-form-urlencoded") {
		t.Errorf("Content-Type lost:\n%s", wire)
	}
}

// Deleting the key is the intuitive fix and is WRONG — this pins the reason so
// nobody "simplifies" applyCodexTokenEndpointHeaders into a Del.
func TestHeaderDelDoesNotSuppressGoUserAgent(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, openaiTokenURL, strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Del("User-Agent")

	var buf bytes.Buffer
	if err := req.Write(&buf); err != nil {
		t.Fatalf("req.Write: %v", err)
	}
	if !strings.Contains(buf.String(), "Go-http-client") {
		t.Skip("net/http no longer substitutes a default User-Agent; " +
			"applyCodexTokenEndpointHeaders can be simplified")
	}
}
