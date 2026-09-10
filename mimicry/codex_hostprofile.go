package mimicry

import (
	"crypto/sha256"
	"encoding/binary"
	"strings"
)

// The machine a Codex client claims to run on.
//
// # Why this exists
//
// A Codex User-Agent carries real machine detail — OS name and version, CPU
// architecture, terminal emulator and its version:
//
//	Codex Desktop/0.153.4 (Arch Linux Rolling Release; x86_64) Konsole/260800 (Codex Desktop; 26.901.51231)
//	                       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^
//
// Every account routed through a proxy that pins one constant therefore
// advertises the same machine, which reads as many subscriptions sharing one
// rare host. That is the signal auth.HostProfile defuses on the Anthropic side
// — and it is sharper here, because the Anthropic CLI's User-Agent carries no
// machine detail at all (`claude-cli/2.1.224 (external, cli)`), so there is
// nothing there to be uniform ABOUT.
//
// # Why the pool holds one entry
//
// Because inventing the others is worse than uniformity. An os_type string, an
// arch token and a terminal version have client-specific formatting that only a
// capture can settle; a malformed one is a STRONGER tell than a repeated
// correct one. So this file ships the mechanism — a per-account deterministic
// pick — with exactly the profile the archive backs, and adding a second entry
// is a data change once a capture (or the client's own source) settles its
// fields. See crack/codexv0.153.4/ and crack/codexapp0.153.4/.
type CodexHostProfile struct {
	// OS is the os_type/os_version segment, e.g. "Arch Linux Rolling Release".
	OS string
	// Arch is the architecture token, e.g. "x86_64".
	Arch string
	// Terminal is the terminal_ua segment, e.g. "Konsole/260800".
	//
	// Never empty. codex-rs builds the User-Agent with a fixed format string in
	// which this segment always occupies a slot, and its detector falls all the
	// way through to the literal "unknown" when no terminal can be identified
	// (codex-rs/terminal-detection/src/lib.rs). Omitting it produces a shape the
	// client cannot emit; codexUserAgent substitutes "unknown" rather than
	// dropping it.
	Terminal string
}

// CodexCapturedHostProfile is the host every archived Codex capture was taken
// on. It is the default, and the value the byte-parity tests pin.
var CodexCapturedHostProfile = CodexHostProfile{
	OS:       "Arch Linux Rolling Release",
	Arch:     "x86_64",
	Terminal: "Konsole/260800",
}

type weightedCodexHost struct {
	h CodexHostProfile
	w int
}

// codexHostPool is the set a per-account pick draws from, weighted toward
// real-world frequency.
//
// EVERY FIELD OF EVERY ENTRY HAS A SOURCE. That is the bar, because a
// malformed os_version or an impossible terminal token is a sharper tell than
// a repeated correct one — the backend can cross-check these against each
// other, and only a real client produces a self-consistent triple.
//
//	Arch Linux Rolling Release / x86_64 / Konsole/260800
//	    Our own capture, crack/codexv0.153.4 and crack/codexapp0.153.4.
//	    os_info renders a rolling distro's version as the literal
//	    "Rolling Release"; 260800 is $KONSOLE_VERSION (KDE Gear 26.08.00).
//	Windows 10.0.26100 / x86_64 / WindowsTerminal
//	    Whole string from a third-party capture of a genuine client. os_info's
//	    Type::Windows renders as the bare word "Windows" — never "Windows 11" —
//	    and its version is Semantic(major, minor, BUILD), so 10.0.26100 is
//	    Windows 11 24H2. The WT_SESSION branch of terminal-detection emits
//	    "WindowsTerminal" with no version, which is why none appears here.
//	Windows 10.0.22631 / x86_64 / WindowsTerminal
//	    Same shape, 23H2's public build number.
//	Mac OS 26.2.0 / arm64 / xterm-256color
//	    Whole string from a third-party capture. Apple Silicon reports "arm64",
//	    NOT "aarch64" — macOS uname -m says arm64 while Windows and Linux say
//	    aarch64 on the same silicon, so this axis must never be unified.
//	    xterm-256color is the $TERM fallback branch, reached when no terminal
//	    program identifies itself.
//	Mac OS 15.6.1 / arm64 / xterm-256color
//	    Same shape; the official user-agent test in codex-rs pins the macOS
//	    version segment as three numeric parts, which 15.6.1 satisfies.
//
// Weights lean toward macOS and Windows because that is where this client's
// users are; the Arch/Konsole host that every capture came from is a rare
// developer machine and is weighted accordingly.
//
// Deliberately absent: any non-Arch LINUX distro. os_info's rendering of a
// point-release VERSION_ID (does Ubuntu's "24.04" become "24.04" or "24.4.0"?)
// is unverified, and guessing it would put a string no client emits on the
// wire.
var codexHostPool = []weightedCodexHost{
	{CodexCapturedHostProfile, 1},
	{CodexHostProfile{OS: "Windows 10.0.26100", Arch: "x86_64", Terminal: "WindowsTerminal"}, 3},
	{CodexHostProfile{OS: "Windows 10.0.22631", Arch: "x86_64", Terminal: "WindowsTerminal"}, 2},
	{CodexHostProfile{OS: "Mac OS 26.2.0", Arch: "arm64", Terminal: "xterm-256color"}, 3},
	{CodexHostProfile{OS: "Mac OS 15.6.1", Arch: "arm64", Terminal: "xterm-256color"}, 2},
}

// CodexHostProfileFor picks the machine an account claims, deterministically.
//
// Keyed on the ACCOUNT, like CodexInstallationIDFor and for the same reason:
// one upstream subscription is one machine. Deriving it per downstream client
// token would present a single account as N machines, which is the inverse of
// the shape a real user produces. Being a hash rather than a counter is what
// keeps it stable across restarts, credential-file rotation and re-logins —
// a machine that changes its OS between turns is a worse tell than a shared one.
func CodexHostProfileFor(accountKey string) CodexHostProfile {
	if len(codexHostPool) == 1 || accountKey == "" {
		return codexHostPool[0].h
	}
	total := 0
	for _, e := range codexHostPool {
		total += e.w
	}
	if total <= 0 {
		return codexHostPool[0].h
	}
	sum := sha256.Sum256([]byte("cc-core-codex-host/" + accountKey))
	n := int(binary.BigEndian.Uint32(sum[:4]) % uint32(total))
	for _, e := range codexHostPool {
		if n < e.w {
			return e.h
		}
		n -= e.w
	}
	return codexHostPool[len(codexHostPool)-1].h
}

// codexUserAgent renders the User-Agent for a client on a host.
//
// The template is the captured one, and both archived clients fit it:
//
//	codex-tui/0.153.4 (Arch Linux Rolling Release; x86_64) Konsole/260800 (codex-tui; 0.153.4)
//	Codex Desktop/0.153.4 (Arch Linux Rolling Release; x86_64) Konsole/260800 (Codex Desktop; 26.901.51231)
//
// The trailing parenthetical repeats the originator and carries the build —
// which for the CLI is just its version again, and for Desktop is a separate
// build number. An empty build omits the parenthetical, which is the "base"
// shape the model fetch uses.
func codexUserAgent(originator, version string, host CodexHostProfile, build string) string {
	var b strings.Builder
	b.WriteString(originator)
	b.WriteByte('/')
	b.WriteString(version)
	b.WriteString(" (")
	b.WriteString(host.OS)
	b.WriteString("; ")
	b.WriteString(host.Arch)
	b.WriteByte(')')
	b.WriteByte(' ')
	if host.Terminal == "" {
		b.WriteString(codexUnknownTerminal)
	} else {
		b.WriteString(host.Terminal)
	}
	if build != "" {
		b.WriteString(" (")
		b.WriteString(originator)
		b.WriteString("; ")
		b.WriteString(build)
		b.WriteByte(')')
	}
	return b.String()
}

// codexUnknownTerminal is what codex-rs emits when every terminal probe fails.
// It is a real value the client produces, not a placeholder we invented.
const codexUnknownTerminal = "unknown"

// WithHost returns p re-rendered as if it ran on host. Only the User-Agent
// fields change; version, originator and beta features describe the CLIENT, not
// the machine, and are untouched.
func (p CodexClientProfile) WithHost(host CodexHostProfile) CodexClientProfile {
	build := p.Version
	if p.Originator == CodexDesktopOriginator {
		build = CodexDesktopBuild
	}
	p.UserAgent = codexUserAgent(p.Originator, p.Version, host, build)
	if p.ModelsUserAgent != "" {
		// The model fetch keeps the CLIENT's name in the User-Agent and drops
		// only the trailing build parenthetical — it does NOT adopt
		// ModelsOriginator's name. That split is real and deliberate: the CLI
		// sends originator `codex_cli_rs` (the codex-rs library default, since
		// the fetch is made by the library rather than the TUI) alongside a
		// User-Agent that still says `codex-tui`. Rendering the UA from the
		// models originator instead produced `codex_cli_rs/0.153.4 …`, a string
		// no capture contains — caught by the byte-parity test above.
		p.ModelsUserAgent = codexUserAgent(p.Originator, p.ModelsClientVersion, host, "")
	}
	return p
}

// CodexProfileFor is the default client identity bound to the machine this
// account claims. It is what every upstream call site should use: the client
// (originator, version, beta features) is a property of the software, the host
// is a property of the account, and only the second may vary.
//
// Anchored on the ChatGPT account id — the same value each call site already
// derives its installation_id from — so one account presents one machine AND
// one installation. Deriving the two from different anchors would let a
// credential's machine and its install disagree, which no real client does.
func CodexProfileFor(accountID string) CodexClientProfile {
	return DefaultCodexProfile().WithHost(CodexHostProfileFor(accountID))
}
