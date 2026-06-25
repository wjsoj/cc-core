package auth

import (
	"crypto/sha256"
	"encoding/binary"
)

// HostProfile is the per-account "client machine" fingerprint surfaced in the
// sidecar telemetry bodies (event_logging env block + datadog flat event).
// Without it, every OAuth account routed through the
// proxy reports the SAME machine (the one we captured: Arch / konsole / zsh) —
// "many different users on one identical, and rare, machine" is itself a
// detection signal. Each account instead gets a stable, internally-consistent
// Linux host picked from hostProfilePool.
//
// SCOPE — Linux only, and deliberately narrow:
//   - platform/os, arch (x64), and the Node/Bun runtime bundle
//     (node_version + is_running_with_bun + the Bun/<ver> sidecar UA) stay
//     FIXED. We have exactly one ground-truth capture (Arch/x64/node v26.3.0,
//     running under Bun 1.4.0); the runtime values move together with the CC
//     release, and we have no macOS/Windows capture to model their different
//     env-block *structure* (mac has no linux_kernel, etc.). Inventing that
//     structure would be a worse fingerprint than uniformity.
//   - Only distro_id, kernel, terminal, and shell vary. These have identical
//     field structure across all Linux hosts (only the values differ), so
//     varying them needs no new capture evidence.
//
// terminal values are restricted to strings that the terminal actually sets in
// TERM_PROGRAM (vscode/tmux/konsole/ghostty/WezTerm) — emulators that don't set
// it (gnome-terminal, xterm, alacritty, kitty) would make CC report a different
// or empty value, so including them would be implausible.
type HostProfile struct {
	DistroID string `json:"distro_id"`
	Kernel   string `json:"kernel"`
	Terminal string `json:"terminal"`
	Shell    string `json:"shell"`
}

// IsZero reports whether the profile is unset (no distro selected yet).
func (p HostProfile) IsZero() bool { return p.DistroID == "" }

type weightedHostProfile struct {
	p HostProfile
	w int
}

// hostProfilePool is a curated set of plausible developer Linux hosts, weighted
// toward real-world frequency (Ubuntu/Debian/Fedora common; Pop/Mint moderate;
// Arch/openSUSE rare). Kernel strings use each distro's exact uname -r format
// and are current as of mid-2026 — a malformed kernel string for a claimed
// distro is a STRONGER "fake" signal than uniformity, so these are kept real:
//
//	ubuntu      X.Y.0-NN-generic            (GA/HWE)
//	debian      X.Y.0-NN-amd64 / X.Y.Z-amd64
//	fedora      X.Y.Z-NNN.fcXX.x86_64
//	linuxmint   X.Y.0-NN-generic            (ubuntu base)
//	pop         X.Y.Z-7606NNNN-generic      (System76)
//	arch        X.Y.Z-arch1-1               (rolling; matches our capture)
//	opensuse    X.Y.Z-N-default             (Tumbleweed)
//
// NOTE: arch (x64), platform=linux, node_version, is_running_with_bun, the
// runtimes list and package_managers stay FIXED in the sidecar — they are not
// part of this profile (see the SCOPE note above). When growing this pool,
// APPEND only and prefer persisted profiles (EnsureHostProfile) so existing
// accounts keep their host — re-weighting/reordering would remap many accounts
// at once ("every machine changed distro overnight"), itself a signal.
var hostProfilePool = []weightedHostProfile{
	{HostProfile{"ubuntu", "6.8.0-51-generic", "vscode", "bash"}, 6},
	{HostProfile{"ubuntu", "6.14.0-32-generic", "tmux", "zsh"}, 4},
	{HostProfile{"ubuntu", "6.8.0-79-generic", "vscode", "zsh"}, 4},
	{HostProfile{"debian", "6.1.0-37-amd64", "tmux", "bash"}, 3},
	{HostProfile{"debian", "6.12.48-amd64", "vscode", "zsh"}, 2},
	{HostProfile{"fedora", "6.15.10-200.fc42.x86_64", "vscode", "bash"}, 3},
	{HostProfile{"fedora", "6.16.3-200.fc42.x86_64", "ghostty", "zsh"}, 2},
	{HostProfile{"linuxmint", "6.8.0-51-generic", "vscode", "bash"}, 2},
	{HostProfile{"pop", "6.12.10-76061203-generic", "WezTerm", "zsh"}, 2},
	{HostProfile{"arch", "7.0.11-arch1-1", "konsole", "zsh"}, 1},
	{HostProfile{"arch", "7.0.11-arch1-1", "ghostty", "fish"}, 1},
	{HostProfile{"opensuse-tumbleweed", "6.16.3-1-default", "konsole", "bash"}, 1},
}

var hostProfileTotalWeight = func() int {
	t := 0
	for _, e := range hostProfilePool {
		t += e.w
	}
	return t
}()

// ProfileFor deterministically maps an account anchor to one host profile.
// Same accountKey → same profile, always (sha256-anchored, mirroring
// DeviceIDFor in mimicry), so an account routed through N client tokens looks
// like one machine. The pick is weighted by each entry's frequency weight.
func ProfileFor(accountKey string) HostProfile {
	sum := sha256.Sum256([]byte("cpa-claude-hostprofile/" + accountKey))
	if hostProfileTotalWeight <= 0 {
		return hostProfilePool[0].p
	}
	r := int(binary.BigEndian.Uint64(sum[:8]) % uint64(hostProfileTotalWeight))
	for _, e := range hostProfilePool {
		if r < e.w {
			return e.p
		}
		r -= e.w
	}
	return hostProfilePool[len(hostProfilePool)-1].p
}

// HostProfileOrDefault returns the account's persisted host profile, falling
// back to the deterministic ProfileFor(accountKey) if none has been persisted
// yet. Always returns a usable profile, so callers (sidecar body builders)
// never need to handle the unset case.
func (a *Auth) HostProfileOrDefault() HostProfile {
	a.mu.RLock()
	hp := a.HostProfile
	a.mu.RUnlock()
	if !hp.IsZero() {
		return hp
	}
	return ProfileFor(a.AccountKey())
}

// EnsureHostProfile pins the account's host profile to the credential file on
// first touch, so it stays stable even if hostProfilePool grows later. Mirrors
// UpdateSubscriptionInfo: mutate under lock, persist only on change. Safe to
// call repeatedly; a no-op once the profile is set. Idempotent and concurrency-
// safe across the N client tokens that may share one OAuth account.
func (a *Auth) EnsureHostProfile() error {
	// Resolve the anchor BEFORE locking: AccountKey() takes a.mu.RLock and the
	// mutex is not reentrant, so calling it while holding a.mu.Lock would
	// deadlock — and worse, freeze every other reader of a.mu.
	key := a.AccountKey()
	a.mu.Lock()
	if !a.HostProfile.IsZero() {
		a.mu.Unlock()
		return nil
	}
	a.HostProfile = ProfileFor(key)
	a.mu.Unlock()
	return saveAuth(a)
}
