package kiroauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// PKCE holds a verifier+challenge pair (S256) used in the
// app.kiro.dev/signin authorization-code flow.
type PKCE struct {
	Verifier  string // raw, 43-char base64url, kept secret on client
	Challenge string // base64url(sha256(verifier)), 43-char, sent in the browser URL
	State     string // 10-char URL-safe random, returned verbatim by the IdP for CSRF
}

// NewPKCE generates a fresh verifier+challenge+state suitable for Kiro login.
func NewPKCE() (PKCE, error) {
	verifierRaw := make([]byte, 32)
	if _, err := rand.Read(verifierRaw); err != nil {
		return PKCE{}, fmt.Errorf("kiroauth: rand verifier: %w", err)
	}
	verifier := base64.RawURLEncoding.EncodeToString(verifierRaw)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	stateRaw := make([]byte, 8) // 8 random bytes → ~10-11 chars after base64url
	if _, err := rand.Read(stateRaw); err != nil {
		return PKCE{}, fmt.Errorf("kiroauth: rand state: %w", err)
	}
	state := base64.RawURLEncoding.EncodeToString(stateRaw)
	if len(state) > 10 {
		state = state[:10]
	}
	return PKCE{Verifier: verifier, Challenge: challenge, State: state}, nil
}

// SignInURL builds the browser-side login URL.
//
// redirectURI must be a URL the CLI can listen on for the OAuth callback
// (typically http://localhost:3128). The caller is responsible for spinning
// up an HTTP listener at that URL and waiting for /oauth/callback?code=…&state=…
func SignInURL(p PKCE, redirectURI string) string {
	return "https://app.kiro.dev/signin" +
		"?state=" + urlEscape(p.State) +
		"&code_challenge=" + urlEscape(p.Challenge) +
		"&code_challenge_method=S256" +
		"&redirect_uri=" + urlEscape(redirectURI) +
		"&redirect_from=kirocli"
}

// urlEscape is the subset of url.QueryEscape needed here — we avoid pulling
// net/url just for one helper, but keep the same character set.
func urlEscape(s string) string {
	const safe = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~"
	var out []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isSafe(c, safe) {
			out = append(out, c)
		} else {
			const hex = "0123456789ABCDEF"
			out = append(out, '%', hex[c>>4], hex[c&0x0f])
		}
	}
	return string(out)
}

func isSafe(c byte, safe string) bool {
	for i := 0; i < len(safe); i++ {
		if safe[i] == c {
			return true
		}
	}
	return false
}
