package auth

import (
	"context"
	"net/http"

	log "github.com/sirupsen/logrus"

	"github.com/wjsoj/cc-core/mimicry"
)

// Auxiliary login-phase endpoints. Real Claude Code fires these around the
// token exchange on every fresh `/login` — captured from a live 2.1.191 OAuth
// session (crack/cc2191/rows/{01,03,04,05,06}). Doing only the bare token
// exchange leaves a lone POST with none of the surrounding probes, which is
// itself a "not the official client" signal at Anthropic's edge. We replay
// them best-effort so an operator-driven login produces the same traffic
// footprint as the vendor CLI.
const (
	anthropicHelloURL    = "https://platform.claude.com/v1/oauth/hello"
	anthropicAPIHelloURL = "https://api.anthropic.com/api/hello"
	anthropicProfileURL  = "https://api.anthropic.com/api/oauth/profile"
	anthropicRolesURL    = "https://api.anthropic.com/api/oauth/claude_cli/roles"
	anthropicSettingsURL = "https://api.anthropic.com/api/oauth/account/settings"
	anthropicOAuthBeta   = "oauth-2025-04-20"
)

// doLoginProbe fires a single best-effort GET mirroring one of the auxiliary
// login requests the official CLI makes. ua selects the client identity that
// real CC uses for that endpoint (claude-cli vs axios). accessToken and beta
// are set only when non-empty. The header set matches the live capture exactly.
// The response body is drained (connection reuse + realistic byte counts) and
// discarded — we already have account/org/email from the token response.
func doLoginProbe(ctx context.Context, client *http.Client, urlStr, ua, accessToken, beta string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Encoding", "gzip, br")
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Connection", "close")
	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}
	if beta != "" {
		req.Header.Set("anthropic-beta", beta)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	_, _ = readAxiosOAuthBody(resp)
	_ = resp.Body.Close()
	return nil
}

// performPreLoginProbes replays the two unauthenticated connectivity probes
// (`/v1/oauth/hello` on platform.claude.com + `/api/hello` on api.anthropic.com)
// the CLI fires before the token exchange. Both use the main claude-cli UA.
// Best-effort: failures are logged at debug and never abort the login.
func performPreLoginProbes(ctx context.Context, client *http.Client) {
	ua := mimicry.ClaudeCLIUserAgent
	for _, u := range []string{anthropicHelloURL, anthropicAPIHelloURL} {
		if err := doLoginProbe(ctx, client, u, ua, "", ""); err != nil {
			log.Debugf("oauth login pre-probe %s: %v", u, err)
		}
	}
}

// performPostLoginProbes replays the authenticated probes the CLI fires right
// after the token exchange: profile + roles (axios UA), then account/settings
// (claude-cli UA + the oauth beta) — the exact (endpoint, UA, beta) tuples seen
// in the live 2.1.191 login. All carry the freshly-minted Bearer token.
// Best-effort: failures are logged at debug and never abort the login.
func performPostLoginProbes(ctx context.Context, client *http.Client, accessToken string) {
	cli := mimicry.ClaudeCLIUserAgent
	probes := []struct{ url, ua, beta string }{
		{anthropicProfileURL, anthropicOAuthUA, ""},
		{anthropicRolesURL, anthropicOAuthUA, ""},
		{anthropicSettingsURL, cli, anthropicOAuthBeta},
	}
	for _, p := range probes {
		if err := doLoginProbe(ctx, client, p.url, p.ua, accessToken, p.beta); err != nil {
			log.Debugf("oauth login post-probe %s: %v", p.url, err)
		}
	}
}
