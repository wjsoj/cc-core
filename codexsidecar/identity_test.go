package codexsidecar

import (
	"strings"
	"testing"

	"github.com/wjsoj/cc-core/mimicry"
)

// TestIdentityDelegatesToMimicry — the sidecar and the forward path must
// present one process to the backend. Any local re-declaration of the version,
// build or User-Agent would let a bump move one and leave the other stale,
// which is a contradiction visible in a single join.
func TestIdentityDelegatesToMimicry(t *testing.T) {
	if desktopVersion != mimicry.CodexDesktopVersion {
		t.Errorf("desktopVersion=%q, mimicry=%q", desktopVersion, mimicry.CodexDesktopVersion)
	}
	if desktopBuild != mimicry.CodexDesktopBuild {
		t.Errorf("desktopBuild=%q, mimicry=%q", desktopBuild, mimicry.CodexDesktopBuild)
	}
	if desktopUAFull != mimicry.CodexDesktopUserAgent {
		t.Errorf("desktopUAFull=%q, mimicry=%q", desktopUAFull, mimicry.CodexDesktopUserAgent)
	}
	if desktopUABase != mimicry.CodexDesktopBaseUserAgent {
		t.Errorf("desktopUABase=%q, mimicry=%q", desktopUABase, mimicry.CodexDesktopBaseUserAgent)
	}
	// The base form must genuinely be a prefix of the full one; if that ever
	// stops holding, one of the two was written out by hand.
	if !strings.HasPrefix(desktopUAFull, desktopUABase) {
		t.Errorf("base UA %q is not a prefix of full UA %q", desktopUABase, desktopUAFull)
	}
	// The version in the UA's leading segment must be the version header's.
	if !strings.HasPrefix(desktopUAFull, mimicry.CodexDesktopOriginator+"/"+desktopVersion+" ") {
		t.Errorf("UA %q does not lead with %s/%s", desktopUAFull, mimicry.CodexDesktopOriginator, desktopVersion)
	}
	// The build appears only in the full form's trailing parenthetical.
	if strings.Contains(desktopUABase, desktopBuild) {
		t.Errorf("base UA %q leaked the build number", desktopUABase)
	}
	// The MCP client's version tracks codex-rs, per rows/40-*.
	if mcpClientUA != "codex-mcp-client/"+desktopVersion {
		t.Errorf("mcpClientUA=%q", mcpClientUA)
	}
	// The exporter UA and the telemetry.sdk.version resource attribute are one
	// value: an exporter advertising 0.31.0 in its UA and something else in
	// its own resource block is a contradiction in one request.
	if !strings.HasSuffix(otlpExporterUA, "/"+otlpSDKVersion) {
		t.Errorf("otlpExporterUA=%q does not carry sdk version %q", otlpExporterUA, otlpSDKVersion)
	}
	if otlpSDKVersion == desktopVersion {
		t.Error("the OTLP SDK version must not be the Codex version")
	}
}

// TestUserAgentForMapping pins the enum, including its zero value: a call
// struct that forgets to set ua must claim the app's canonical identity, never
// one of the two per-component forms.
func TestUserAgentForMapping(t *testing.T) {
	cases := map[uaKind]string{
		uaDesktopFull:  desktopUAFull,
		uaDesktopBare:  desktopUABase,
		uaMCPClient:    mcpClientUA,
		uaOTLPExporter: otlpExporterUA,
	}
	for k, want := range cases {
		if got := userAgentFor(k); got != want {
			t.Errorf("userAgentFor(%d)=%q, want %q", k, got, want)
		}
	}
	var zero uaKind
	if userAgentFor(zero) != desktopUAFull {
		t.Errorf("zero uaKind resolves to %q, want the full Desktop UA", userAgentFor(zero))
	}
	if got := userAgentFor(uaKind(99)); got != desktopUAFull {
		t.Errorf("unknown uaKind resolves to %q", got)
	}
}
