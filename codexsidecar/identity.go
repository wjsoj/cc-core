package codexsidecar

import (
	"strings"

	"github.com/wjsoj/cc-core/auth"
	"github.com/wjsoj/cc-core/mimicry"
)

// Codex Desktop identity, taken from mimicry rather than re-declared.
//
// mimicry/codex_identity.go is the single source of truth for the Desktop
// version / build / User-Agent triple (crack/codexapp0.153.4/ §1), and its
// own doc is explicit that a caller needing the base UA form must take it from
// there rather than re-deriving it locally. Re-declaring any of these here
// would let a version bump move the forward path and leave the sidecar stale —
// which is a self-contradiction the backend can see in a single join, since
// both streams come from what upstream believes is one process.
const (
	// desktopVersion is codex-rs's own version — the `version` header on
	// codex/models, the client_version query parameter, the MCP clientInfo
	// version, and runtime.codex_rs_version in the analytics body.
	desktopVersion = mimicry.CodexDesktopVersion

	// desktopBuild is the Desktop app build number. It appears ONLY in the
	// User-Agent's trailing parenthetical and as app_server_client.client_version
	// in the analytics body. It is not a semver and is not desktopVersion.
	desktopBuild = mimicry.CodexDesktopBuild

	// desktopUAFull is the complete Desktop User-Agent.
	desktopUAFull = mimicry.CodexDesktopUserAgent

	// mcpClientUA is the third User-Agent form: the plugin-store MCP channel
	// identifies itself as its own client, not as the app
	// (crack/codexapp0.153.4/rows/40-*).
	mcpClientUA = "codex-mcp-client/" + desktopVersion

	// otlpSDKVersion is the opentelemetry Rust SDK's version, NOT the Codex
	// version. It appears both in the exporter UA and as
	// telemetry.sdk.version in the OTLP resource block, and the two must agree
	// (crack/codexapp0.153.4/rows/50).
	otlpSDKVersion = "0.31.0"
	// otlpExporterUA is the fourth User-Agent form.
	otlpExporterUA = "OTel-OTLP-Exporter-Rust/" + otlpSDKVersion

	// mcpProtocolVersion is the MCP revision the client negotiates. Sent as
	// the mcp-protocol-version header on every ps/mcp call AFTER initialize,
	// and as params.protocolVersion inside initialize itself.
	mcpProtocolVersion = "2025-06-18"

	// statsigAPIKey is the publishable Statsig client key the OTLP exporter
	// authenticates with. It is kept verbatim in the archive because it is a
	// fingerprint, not a secret — there is no Authorization header on the
	// OTLP endpoint at all.
	statsigAPIKey = "client-MkRuleRQBd6qakfnDYqJVR9JuXcY57Ljly3vi5JVUIO"
)

// desktopUABase is the full UA minus the trailing "(Codex Desktop; <build>)".
// A var rather than a const because mimicry derives it by trimming the full
// form, which is the property that keeps the two from drifting apart.
var desktopUABase = mimicry.CodexDesktopBaseUserAgent

// uaKind selects which of the four coexisting User-Agent forms an endpoint
// uses. They are per-component inside one process; pairing an originator with
// the wrong UA is a one-header tell, so this is a closed enumeration rather
// than a string on each step.
type uaKind int

const (
	// uaDesktopFull is desktopUAFull. It is deliberately the ZERO value: a
	// call struct that forgets to set ua then claims the app's canonical
	// identity rather than silently falling into a rarer form.
	uaDesktopFull uaKind = iota
	// uaDesktopBare is desktopUABase — no build parenthetical. Retained
	// because the form is real and attested; nothing selects it today (see
	// the note below on why the Desktop calls all use the full form).
	uaDesktopBare
	// uaMCPClient is codex-mcp-client/<ver>.
	uaMCPClient
	// uaOTLPExporter is OTel-OTLP-Exporter-Rust/<sdk ver>.
	uaOTLPExporter
)

// userAgentFor renders a uaKind.
func userAgentFor(k uaKind) string {
	switch k {
	case uaDesktopBare:
		return desktopUABase
	case uaMCPClient:
		return mcpClientUA
	case uaOTLPExporter:
		return otlpExporterUA
	case uaDesktopFull:
		return desktopUAFull
	default:
		return desktopUAFull
	}
}

// WHICH DESKTOP UA FORM — and why this is not a per-endpoint table.
//
// Two of the four forms are unambiguously per-component and are wired that
// way above: `codex-mcp-client/<ver>` appears on ps/mcp and nowhere else, and
// `OTel-OTLP-Exporter-Rust/<ver>` on ab.chatgpt.com/otlp/v1/metrics and
// nowhere else. Crossing either of those is a one-header tell.
//
// The remaining two — the full Desktop UA and the same string minus the
// trailing "(Codex Desktop; <build>)" — do NOT split by endpoint.
// crack/codexapp0.153.4/SPEC.md §1 is explicit about it, and explicit that an
// earlier draft of that section (and the single representative row per
// endpoint in rows/) made it look like they did: across the full dump,
// codex/models, plugins/featured, ps/plugins/installed and
// ps/plugins/suggested each appear with BOTH forms. The likeliest reading is
// that the app-server and the codex-rs core reach the same endpoints under the
// same originator with slightly different UA construction, and this capture
// cannot separate them.
//
// So this package sends the FULL form on every Desktop-component call:
//
//   - It is attested on every one of those endpoints (each appears with both).
//   - The two endpoints whose form never varies — oauth/token and the
//     WebSocket upgrade — both use the full form, which makes it the client's
//     canonical string rather than an unusual one.
//   - The alternative would be to reproduce a full-vs-base MIX, and the
//     archive gives no ratio to reproduce. Guessing one would be inventing a
//     distribution, which is the failure mode the repo rule about matching
//     crack/ exists to prevent.
//
// If a future capture separates the two components, this becomes a
// per-component choice — never a per-endpoint one.

// osAttrs is the (os, os_version) pair reported in the OTLP resource block.
// The capture shows "Arch_Linux" / "Rolling_Release" — sysinfo's System::name()
// and System::os_version() with spaces replaced by underscores.
type osAttrs struct {
	Name    string
	Version string
}

// osAttrsPool maps each auth.HostProfile distro id to the (name, version) pair
// sysinfo reports on that distro. Only the seven ids auth.hostProfilePool can
// produce are covered; anything else falls back to the captured Arch pair.
//
// This is the one place this package varies host identity per account, and it
// is a considered exception to the rule in mimicry/codex_identity.go that
// per-account variation of the Codex client identity is NOT done because
// os_type/os_version per distro would be invented. The distinction:
//
//   - The User-Agent stays uniform. It is cross-validated against originator
//     and version, its terminal segment (Konsole/260800) has a version number
//     no capture backs for any other terminal, and a malformed UA is a
//     one-header tell. Nothing here touches it.
//   - The OTLP resource block is not cross-validated against anything, and
//     shipping ONE identical blob for every credential is itself the failure
//     mode the archive calls out (SPEC §4.3). The values below are the
//     distributions' own os-release NAME/VERSION_ID strings — public facts
//     about the distro, not guesses about the client.
//
// Versions track the same mid-2026 vintage as the kernels in
// auth.hostProfilePool, so a host advertising kernel 6.8.0-51-generic and
// Ubuntu 24.04 is internally consistent. APPEND only; changing an existing
// row remaps every account already on it.
var osAttrsPool = map[string]osAttrs{
	"ubuntu":              {"Ubuntu", "24.04"},
	"debian":              {"Debian_GNU/Linux", "12"},
	"fedora":              {"Fedora_Linux", "42"},
	"linuxmint":           {"Linux_Mint", "22"},
	"pop":                 {"Pop!_OS", "22.04"},
	"arch":                {"Arch_Linux", "Rolling_Release"},
	"opensuse-tumbleweed": {"openSUSE_Tumbleweed", "20260901"},
}

// osAttrsFor resolves the OTLP host attributes for one credential from its
// persisted (or deterministically derived) auth.HostProfile, so two accounts
// routed through this proxy do not advertise one identical machine.
func osAttrsFor(a *auth.Auth) osAttrs {
	if a == nil {
		return osAttrsPool["arch"]
	}
	hp := a.HostProfileOrDefault()
	if v, ok := osAttrsPool[strings.TrimSpace(hp.DistroID)]; ok {
		return v
	}
	return osAttrsPool["arch"]
}

// installationIDFor is the per-account installation id shared by the analytics
// bodies and (upstream, in the forward path) x-codex-turn-metadata. It is
// keyed on the ACCOUNT, not the client token: one upstream account is one
// installation. Delegated to mimicry so both paths cannot drift.
func installationIDFor(a *auth.Auth) string {
	if a == nil {
		return ""
	}
	return mimicry.CodexInstallationIDFor(a.AccountKey())
}
