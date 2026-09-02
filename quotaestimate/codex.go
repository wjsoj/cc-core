package quotaestimate

import (
	"time"

	"github.com/wjsoj/cc-core/auth"
)

// Codex window keys. ChatGPT names its windows by role rather than length:
// wham/usage reports a primary and a secondary window and states each one's
// length (limit_window_seconds) — the primary was 5h until 2026-07 and is a
// 7-day window since, so the length is read from the payload, never assumed.
const (
	WindowCodexPrimary   = "primary"
	WindowCodexSecondary = "secondary"
)

// FromCodexUsage extracts the windows from a wham/usage snapshot
// (auth.FetchCodexUsage). used_percent is 0..100; reset_at is epoch seconds,
// with reset_after_seconds relative to now as the fallback. Windows with no
// stated length or no placeable reset are dropped, as for Anthropic. Output
// is ordered primary then secondary.
func FromCodexUsage(info *auth.CodexUsageInfo, now time.Time) []Window {
	if info == nil || info.RateLimit == nil {
		return nil
	}
	var out []Window
	add := func(key string, w *auth.CodexUsageRateWindow) {
		if w == nil || w.LimitWindowSeconds <= 0 {
			return
		}
		var resetsAt time.Time
		switch {
		case w.ResetAt > 0:
			resetsAt = time.Unix(w.ResetAt, 0)
		case w.ResetAfterSeconds > 0:
			resetsAt = now.Add(time.Duration(w.ResetAfterSeconds) * time.Second)
		default:
			return
		}
		out = append(out, Window{
			Key:         key,
			Length:      time.Duration(w.LimitWindowSeconds) * time.Second,
			ResetsAt:    resetsAt,
			Utilization: NormalizeUtilization(w.UsedPercent),
		})
	}
	add(WindowCodexPrimary, info.RateLimit.PrimaryWindow)
	add(WindowCodexSecondary, info.RateLimit.SecondaryWindow)
	return out
}

// ForCodexCredential is ForCredential for an OpenAI OAuth credential: project
// every window the wham/usage snapshot reports, anchored on the credential's
// last usage_limit_reached rejection, falling back to the window that
// rejection reconstructs when there is no snapshot. Returns nil when there is
// nothing to say.
func ForCodexCredential(info *auth.CodexUsageInfo, hit auth.QuotaHit, spend SpendFunc, now time.Time) []Estimate {
	windows := FromCodexUsage(info, now)
	if len(windows) == 0 {
		w, ok := FromHit(hit)
		if !ok {
			return nil
		}
		windows = []Window{w}
	}
	out := make([]Estimate, 0, len(windows))
	for _, w := range windows {
		out = append(out, Project(w, hit, spend, now))
	}
	return out
}
