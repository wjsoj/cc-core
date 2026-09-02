package quotaestimate

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// DefaultHistoryKeep is how many measurements History retains per credential
// when the caller passes 0. A few weeks is what "has this account's
// allotment shrunk?" needs; the ledger keeps the rows if more is wanted.
const DefaultHistoryKeep = 8

// Measurement is one settled, rejection-anchored estimate: what a window was
// worth the time it filled. Only BasisQuotaHit estimates become
// measurements — a scaled projection is a guess that changes every poll,
// and the operator asked for the record of windows that actually ran to
// 100%.
type Measurement struct {
	Window        string    `json:"window"`
	WindowHours   float64   `json:"window_hours"`
	WindowStart   time.Time `json:"window_start"`
	ResetAt       time.Time `json:"reset_at"`
	HitAt         time.Time `json:"hit_at"`
	ObservedHours float64   `json:"observed_hours"`
	// Spend is the whole window (== the observed spend under a rejection).
	Spend Spend `json:"spend"`
	// RecordedAt is when the measurement settled into the history.
	RecordedAt time.Time `json:"recorded_at"`
}

// History persists the last few measurements per credential to a JSON file,
// so "what did the last N full windows cost" survives restarts, credential
// re-logins and log retention. The zero value is usable as an in-memory
// history; OpenHistory gives it a file. Writes are atomic (temp + rename)
// and errors are returned to the caller, never fatal to a request.
type History struct {
	mu      sync.Mutex
	path    string
	keep    int
	entries map[string][]Measurement // authID → newest first
}

// OpenHistory loads (or creates) the history file at path. keep <= 0 means
// DefaultHistoryKeep. A missing file is an empty history; a malformed file
// is an error, since silently starting over would erase the very record the
// file exists to keep.
func OpenHistory(path string, keep int) (*History, error) {
	h := &History{path: path, keep: keep}
	if h.keep <= 0 {
		h.keep = DefaultHistoryKeep
	}
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		h.entries = map[string][]Measurement{}
		return h, nil
	case err != nil:
		return nil, err
	}
	var file struct {
		Entries map[string][]Measurement `json:"entries"`
	}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &file); err != nil {
			return nil, err
		}
	}
	if file.Entries == nil {
		file.Entries = map[string][]Measurement{}
	}
	h.entries = file.Entries
	return h, nil
}

// Record stores a settled rejection-anchored estimate for authID. Estimates
// with any other basis, or with a ledger error, are ignored. A measurement
// of a window already on record (same reset stamp) replaces the old one
// rather than duplicating it — the ledger may have settled further since.
// Returns whether the history changed on disk.
func (h *History) Record(authID string, est Estimate, now time.Time) (bool, error) {
	if h == nil || authID == "" || est.Basis != BasisQuotaHit || est.SpendError != "" || est.FullWindow == nil || est.QuotaHitAt == nil {
		return false, nil
	}
	m := Measurement{
		Window:        est.Window,
		WindowHours:   est.WindowHours,
		WindowStart:   est.WindowStart,
		ResetAt:       est.WindowResetsAt,
		HitAt:         *est.QuotaHitAt,
		ObservedHours: est.ObservedHours,
		Spend:         *est.FullWindow,
		RecordedAt:    now,
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.entries == nil {
		h.entries = map[string][]Measurement{}
	}
	if h.keep <= 0 {
		h.keep = DefaultHistoryKeep
	}
	list := h.entries[authID]
	replaced := false
	for i := range list {
		if sameWindow(list[i].ResetAt, m.ResetAt) {
			if list[i].Spend == m.Spend && list[i].HitAt.Equal(m.HitAt) {
				return false, nil
			}
			m.RecordedAt = list[i].RecordedAt
			list[i] = m
			replaced = true
			break
		}
	}
	if !replaced {
		list = append(list, m)
	}
	sort.SliceStable(list, func(i, j int) bool { return list[i].HitAt.After(list[j].HitAt) })
	if len(list) > h.keep {
		list = list[:h.keep]
	}
	h.entries[authID] = list
	return true, h.saveLocked()
}

// For returns the credential's measurements, newest first. The slice is a
// copy.
func (h *History) For(authID string) []Measurement {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	list := h.entries[authID]
	if len(list) == 0 {
		return nil
	}
	out := make([]Measurement, len(list))
	copy(out, list)
	return out
}

// Forget drops a credential's measurements (on credential removal).
func (h *History) Forget(authID string) error {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.entries[authID]; !ok {
		return nil
	}
	delete(h.entries, authID)
	return h.saveLocked()
}

func (h *History) saveLocked() error {
	if h.path == "" {
		return nil
	}
	out, err := json.MarshalIndent(struct {
		Entries map[string][]Measurement `json:"entries"`
	}{h.entries}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(h.path), 0o755); err != nil {
		return err
	}
	tmp := h.path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, h.path)
}

// sameWindow mirrors auth.sameQuotaWindow: two reset stamps within a minute
// name one upstream window.
func sameWindow(a, b time.Time) bool {
	if a.IsZero() || b.IsZero() {
		return false
	}
	d := a.Sub(b)
	if d < 0 {
		d = -d
	}
	return d <= time.Minute
}
