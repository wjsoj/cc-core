package mimicry

import (
	"regexp"
	"strings"
	"testing"
)

// The renderer has to reproduce BOTH archived User-Agents byte for byte on the
// captured host. Without this the template is just a plausible-looking string
// builder, and a single wrong space or parenthesis is a fingerprint.
func TestRendererReproducesTheCapturedUserAgents(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  string
		want string
	}{
		{"Desktop", CodexDesktopClientProfile().WithHost(CodexCapturedHostProfile).UserAgent, CodexDesktopUserAgent},
		{"CLI", CodexTUIClientProfile().WithHost(CodexCapturedHostProfile).UserAgent, CodexCLIUserAgent},
		{"Desktop models", CodexDesktopClientProfile().WithHost(CodexCapturedHostProfile).ModelsUserAgent, CodexDesktopBaseUserAgent},
		{"CLI models", CodexTUIClientProfile().WithHost(CodexCapturedHostProfile).ModelsUserAgent, CodexModelsUserAgent},
	} {
		if tc.got != tc.want {
			t.Errorf("%s User-Agent\n got %q\nwant %q", tc.name, tc.got, tc.want)
		}
	}
}

// Every pool entry has to be a shape codex-rs can actually emit. These are the
// rules the client's own source imposes, and a violation is a sharper tell than
// the uniformity this pool exists to remove.
func TestEveryPoolEntryIsAShapeTheClientCanEmit(t *testing.T) {
	for _, e := range codexHostPool {
		h := e.h
		if h.OS == "" || h.Arch == "" {
			t.Errorf("%+v: os and arch always occupy their slots", h)
		}
		if h.Terminal == "" {
			t.Errorf("%+v: the terminal segment is never empty; the client falls through to %q", h, codexUnknownTerminal)
		}
		if e.w <= 0 {
			t.Errorf("%+v: a zero weight is an entry that can never be picked", h)
		}
		// macOS says arm64; Windows and Linux say aarch64 on the same silicon.
		// Unifying them is the single easiest way to produce an impossible host.
		if strings.HasPrefix(h.OS, "Mac OS") && h.Arch == "aarch64" {
			t.Errorf("%+v: macOS reports arm64, never aarch64", h)
		}
		if !strings.HasPrefix(h.OS, "Mac OS") && h.Arch == "arm64" {
			t.Errorf("%+v: only macOS reports arm64; Windows and Linux report aarch64", h)
		}
		// os_info renders Type::Windows as the bare word, and its version as
		// major.minor.build — "Windows 11" is a string the client cannot produce.
		if strings.HasPrefix(h.OS, "Windows") && !windowsVersionRe.MatchString(h.OS) {
			t.Errorf("%+v: Windows renders as `Windows <major>.<minor>.<build>`", h)
		}
		if strings.HasPrefix(h.OS, "Mac OS") && !macVersionRe.MatchString(h.OS) {
			t.Errorf("%+v: macOS renders as `Mac OS <x>.<y>.<z>`", h)
		}
	}
}

var (
	windowsVersionRe = regexp.MustCompile(`^Windows \d+\.\d+\.\d+$`)
	macVersionRe     = regexp.MustCompile(`^Mac OS \d+\.\d+\.\d+$`)
)

// The captured host must stay in the pool: it is the one the byte-parity tests
// pin, and dropping it would leave nothing verifiable to compare against.
func TestCapturedHostStaysInThePool(t *testing.T) {
	for _, e := range codexHostPool {
		if e.h == CodexCapturedHostProfile {
			return
		}
	}
	t.Fatal("the captured host left the pool; the parity tests now compare against nothing real")
}

// The pick must be stable for an account and spread across the pool. Exercised
// against a local pool so the property is pinned now rather than the day a
// second entry lands.
func TestPickIsStablePerAccountAndSpreads(t *testing.T) {
	saved := codexHostPool
	t.Cleanup(func() { codexHostPool = saved })
	codexHostPool = []weightedCodexHost{
		{CodexHostProfile{OS: "A", Arch: "x86_64"}, 1},
		{CodexHostProfile{OS: "B", Arch: "arm64"}, 1},
		{CodexHostProfile{OS: "C", Arch: "x86_64"}, 1},
	}

	seen := map[string]int{}
	for _, acct := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l"} {
		first := CodexHostProfileFor(acct)
		for i := 0; i < 5; i++ {
			if again := CodexHostProfileFor(acct); again != first {
				t.Fatalf("account %q moved between machines: %+v then %+v", acct, first, again)
			}
		}
		seen[first.OS]++
	}
	if len(seen) < 2 {
		t.Fatalf("twelve accounts landed on %d machine(s): %v — the spread is the whole point", len(seen), seen)
	}
}

// The terminal segment is never dropped.
//
// This test asserted the opposite when it was written, on nothing but
// plausibility. codex-rs settles it: get_codex_user_agent() uses one fixed
// format string in which the segment always occupies a slot, and
// terminal-detection falls through thirteen probes to the literal "unknown".
// A User-Agent with the segment missing is a shape the real client cannot
// produce — which is a sharper tell than any repeated-but-correct value.
func TestUndetectedTerminalRendersAsUnknownNotAsNothing(t *testing.T) {
	got := codexUserAgent("codex-tui", "0.153.4", CodexHostProfile{OS: "Mac OS 15.6.1", Arch: "arm64"}, "0.153.4")
	want := "codex-tui/0.153.4 (Mac OS 15.6.1; arm64) unknown (codex-tui; 0.153.4)"
	if got != want {
		t.Fatalf("\n got %q\nwant %q", got, want)
	}
}
