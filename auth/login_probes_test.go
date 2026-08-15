package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/wjsoj/cc-core/mimicry"
)

type probeRecord struct {
	path    string
	ua      string
	beta    string
	authz   string
	ctype   string
	cache   string
	accept  string
	acceptE string
}

// probeServer records every probe request so a test can assert the exact
// header set per endpoint.
func probeServer(t *testing.T) (*httptest.Server, func() []probeRecord) {
	t.Helper()
	var mu sync.Mutex
	var got []probeRecord
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = append(got, probeRecord{
			path:    r.URL.Path,
			ua:      r.Header.Get("User-Agent"),
			beta:    r.Header.Get("Anthropic-Beta"),
			authz:   r.Header.Get("Authorization"),
			ctype:   r.Header.Get("Content-Type"),
			cache:   r.Header.Get("Cache-Control"),
			accept:  r.Header.Get("Accept"),
			acceptE: r.Header.Get("Accept-Encoding"),
		})
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)
	return srv, func() []probeRecord {
		mu.Lock()
		defer mu.Unlock()
		out := make([]probeRecord, len(got))
		copy(out, got)
		return out
	}
}

// The post-login probes are NOT header-identical. Real CC 2.1.220 sends
// Content-Type + Cache-Control: no-cache on /api/oauth/profile and neither on
// /api/oauth/claude_cli/roles. Emitting one uniform header set for both is a
// fingerprint tell. (crack/claudev2.1.220/SPEC.md §2.)
func TestLoginProbeHeadersPerEndpoint(t *testing.T) {
	srv, records := probeServer(t)

	cases := []struct {
		name       string
		extra      map[string]string
		wantCType  string
		wantCache  string
		ua         string
		beta       string
		wantBearer bool
	}{
		{
			name: "profile carries content-type and no-cache",
			extra: map[string]string{
				"Content-Type":  "application/json",
				"Cache-Control": "no-cache",
			},
			wantCType:  "application/json",
			wantCache:  "no-cache",
			ua:         anthropicOAuthUA,
			wantBearer: true,
		},
		{
			name:       "roles carries neither",
			extra:      nil,
			wantCType:  "",
			wantCache:  "",
			ua:         anthropicOAuthUA,
			wantBearer: true,
		},
		{
			name:       "account settings carries the oauth beta",
			extra:      nil,
			ua:         mimicry.ClaudeCLIUserAgent,
			beta:       anthropicOAuthBeta,
			wantBearer: true,
		},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := doLoginProbe(context.Background(), srv.Client(),
				srv.URL+"/probe", tc.ua, "tok-123", tc.beta, tc.extra)
			if err != nil {
				t.Fatalf("doLoginProbe: %v", err)
			}
			rec := records()[i]

			if rec.ctype != tc.wantCType {
				t.Errorf("Content-Type = %q, want %q", rec.ctype, tc.wantCType)
			}
			if rec.cache != tc.wantCache {
				t.Errorf("Cache-Control = %q, want %q", rec.cache, tc.wantCache)
			}
			if rec.ua != tc.ua {
				t.Errorf("User-Agent = %q, want %q", rec.ua, tc.ua)
			}
			if rec.beta != tc.beta {
				t.Errorf("Anthropic-Beta = %q, want %q", rec.beta, tc.beta)
			}
			if tc.wantBearer && rec.authz != "Bearer tok-123" {
				t.Errorf("Authorization = %q, want Bearer tok-123", rec.authz)
			}
			// Shared across every probe, captured verbatim from axios.
			if rec.accept != "application/json, text/plain, */*" {
				t.Errorf("Accept = %q", rec.accept)
			}
			if rec.acceptE != "gzip, br" {
				t.Errorf("Accept-Encoding = %q", rec.acceptE)
			}
		})
	}
}

// An unauthenticated pre-probe must not leak an Authorization header.
func TestLoginPreProbeSendsNoBearer(t *testing.T) {
	srv, records := probeServer(t)

	err := doLoginProbe(context.Background(), srv.Client(),
		srv.URL+"/v1/oauth/hello", mimicry.ClaudeCLIUserAgent, "", "", nil)
	if err != nil {
		t.Fatalf("doLoginProbe: %v", err)
	}
	rec := records()[0]
	if rec.authz != "" {
		t.Errorf("pre-probe must be unauthenticated, got Authorization %q", rec.authz)
	}
	if !strings.HasPrefix(rec.ua, "claude-cli/") {
		t.Errorf("pre-probe UA = %q, want claude-cli/*", rec.ua)
	}
}
