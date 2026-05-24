// Package kiroauth handles Kiro credential lifecycle: PKCE login,
// token refresh, logout, and on-disk credential storage.
//
// Three credential kinds are supported, matching the kiro.rs / kiro-cli model:
//
//   - Social — OAuth via app.kiro.dev/signin (GitHub / Google / Builder ID),
//     refreshed at POST /refreshToken with body {refreshToken}.
//   - IdC — AWS Identity Center (SSO OIDC), refreshed at the oidc.<region>.amazonaws.com
//     /token endpoint with {client_id, client_secret, grant_type, refresh_token}.
//   - APIKey — Kiro headless API key (ksk_…), used directly as Bearer; never refreshed.
//
// All HTTP shapes match the captures under crack/kiro/login/.
package kiroauth

// Kiro auth-region endpoint hosts.
//
// The "social" tier uses Kiro's own server in us-east-1. Both /oauth/token,
// /refreshToken and /logout are served from this host.
const (
	// DefaultAuthRegion is the region used when no per-credential region is set.
	DefaultAuthRegion = "us-east-1"

	// SharedProfileARN is the AWS profile every Kiro Free / Pro account shares.
	// Re-verified on every kiro-cli release; if it changes, update here.
	SharedProfileARN = "arn:aws:codewhisperer:us-east-1:699475941385:profile/EHGA3GRVQMUK"
)

// AuthHost returns the Kiro auth server hostname for the given region.
// E.g. "us-east-1" → "prod.us-east-1.auth.desktop.kiro.dev".
func AuthHost(region string) string {
	if region == "" {
		region = DefaultAuthRegion
	}
	return "prod." + region + ".auth.desktop.kiro.dev"
}

// AuthBaseURL returns the https:// base URL for the auth server.
func AuthBaseURL(region string) string {
	return "https://" + AuthHost(region)
}

// IdCOIDCHost returns the AWS Identity Center OIDC hostname for the given region.
// E.g. "us-east-1" → "oidc.us-east-1.amazonaws.com".
func IdCOIDCHost(region string) string {
	if region == "" {
		region = DefaultAuthRegion
	}
	return "oidc." + region + ".amazonaws.com"
}
