// Package clienttoken is the runtime store of client access tokens that
// the proxy accepts in Authorization: Bearer.
//
// Tokens live in a single file, tokens.json, sitting next to state.json.
// The admin panel owns full CRUD.
//
// # Token shape
//
// Each Token carries the bearer string itself plus per-token policy:
// concurrency cap, per-minute rate cap, optional weekly USD budget, and
// a credential group label. SaaS-tier extensions (e.g. user binding,
// wallet balance) belong in a wrapper struct in the SaaS layer, not here.
//
// # Lookup signature
//
// Lookup returns (Token, bool) — the whole entry by value — instead of a
// tuple of named returns. This is intentional: future Token fields don't
// break callers, and consumers can read any subset of fields without
// shotgun-modifying the signature.
package clienttoken

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/wjsoj/cc-core/auth"
)

// Token is one client access token. SaaS-side data (wallet balance,
// user binding, payment history) belongs in a separate layer.
//
// Group vs Groups:
//
//   - Group (legacy, scalar): single credential group scope. Empty = public.
//   - Groups (priority-ordered list): zero or more groups tried in order
//     by Pool.AcquireMulti — fallthrough happens when no healthy credential
//     exists in the current group. Empty Groups + non-empty Group is
//     auto-promoted to a single-element Groups (back-compat).
//
// Use EffectiveGroups() to read whichever is populated.
type Token struct {
	Token         string    `json:"token"`
	Name          string    `json:"name"`
	WeeklyUSD     float64   `json:"weekly_usd,omitempty"`     // 0 = no per-token weekly cap
	MaxConcurrent int       `json:"max_concurrent,omitempty"` // 0 = use global default
	RPM           int       `json:"rpm,omitempty"`            // 0 = use global default
	Group         string    `json:"group,omitempty"`          // legacy single-group; promoted to Groups when set alone
	Groups        []string  `json:"groups,omitempty"`         // priority-ordered group fallthrough list
	Providers     []string  `json:"providers,omitempty"`      // allow-list of canonical providers this token may use; empty = all
	CreatedAt     time.Time `json:"created_at,omitempty"`
}

// AllowsProvider reports whether this token may route to the given provider.
// An empty Providers list means unrestricted (any provider). Comparison is
// done through auth.NormalizeProvider so friendly aliases ("claude", "codex")
// match their canonical ids.
func (t *Token) AllowsProvider(p string) bool {
	if len(t.Providers) == 0 {
		return true
	}
	p = auth.NormalizeProvider(p)
	for _, x := range t.Providers {
		if auth.NormalizeProvider(x) == p {
			return true
		}
	}
	return false
}

// EffectiveGroups returns the priority-ordered group list to try. If Groups
// is set it is returned verbatim; otherwise Group is promoted to a single-
// element slice; otherwise []string{""} so callers default to the public pool.
func (t *Token) EffectiveGroups() []string {
	if len(t.Groups) > 0 {
		return t.Groups
	}
	if t.Group != "" {
		return []string{t.Group}
	}
	return []string{""}
}

// View is the API representation returned to the admin panel.
type View struct {
	Token         string    `json:"token"`
	Name          string    `json:"name"`
	WeeklyUSD     float64   `json:"weekly_usd,omitempty"`
	MaxConcurrent int       `json:"max_concurrent,omitempty"`
	RPM           int       `json:"rpm,omitempty"`
	Group         string    `json:"group,omitempty"`
	Groups        []string  `json:"groups,omitempty"`
	Providers     []string  `json:"providers,omitempty"`
	CreatedAt     time.Time `json:"created_at,omitempty"`
}

type Store struct {
	mu     sync.RWMutex
	tokens []Token
	path   string
}

// OpenInMemory returns a Store with no file persistence. Saves are no-ops.
// Intended for tests and ephemeral processes.
func OpenInMemory() *Store {
	return &Store{}
}

// Open loads tokens.json (if it exists). path may be "" to disable
// persistence (tokens stay in memory only).
func Open(path string) (*Store, error) {
	s := &Store{path: path}

	if path == "" {
		return s, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return s, nil
		}
		return nil, err
	}
	var file struct {
		Tokens []Token `json:"tokens"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	for _, t := range file.Tokens {
		t.Token = strings.TrimSpace(t.Token)
		if t.Token == "" {
			continue
		}
		t.Group = auth.NormalizeGroup(t.Group)
		t.Groups = normalizeGroups(t.Groups)
		t.Providers = normalizeProviders(t.Providers)
		if t.WeeklyUSD < 0 {
			t.WeeklyUSD = 0
		}
		s.tokens = append(s.tokens, t)
	}
	return s, nil
}

// normalizeGroups deduplicates + normalizes a group slice, preserving order.
// Empty entries and dupes drop out.
func normalizeGroups(groups []string) []string {
	if len(groups) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(groups))
	out := make([]string, 0, len(groups))
	for _, g := range groups {
		g = auth.NormalizeGroup(g)
		if g == "" || seen[g] {
			continue
		}
		seen[g] = true
		out = append(out, g)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// normalizeProviders canonicalizes a provider allow-list, dropping unknown /
// empty entries and dupes while preserving order. nil out = unrestricted.
func normalizeProviders(providers []string) []string {
	if len(providers) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(providers))
	out := make([]string, 0, len(providers))
	for _, p := range providers {
		p = auth.NormalizeProvider(p)
		if !auth.IsKnownProvider(p) || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// Lookup reports whether tok is a known client token. The returned Token
// is a copy — callers should not modify it.
//
// Future Token fields (e.g. additional caps, billing flags) won't change
// this signature; consumers read whatever they need from the returned value.
func (s *Store) Lookup(tok string) (Token, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, t := range s.tokens {
		if t.Token == tok {
			return t, true
		}
	}
	return Token{}, false
}

// RPM returns the per-token RPM override if one is configured. Returns
// (0, false) when the token is unknown or has no override set.
func (s *Store) RPM(tok string) (int, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, t := range s.tokens {
		if t.Token == tok {
			return t.RPM, true
		}
	}
	return 0, false
}

// Empty reports whether the proxy should run in open mode.
func (s *Store) Empty() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.tokens) == 0
}

// List returns every token as a View. Safe to serialize to the admin
// panel; do not leak to unauthenticated callers.
func (s *Store) List() []View {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]View, 0, len(s.tokens))
	for _, t := range s.tokens {
		out = append(out, View{
			Token: t.Token, Name: t.Name, WeeklyUSD: t.WeeklyUSD,
			MaxConcurrent: t.MaxConcurrent, RPM: t.RPM,
			Group: t.Group, Groups: append([]string(nil), t.Groups...),
			Providers: append([]string(nil), t.Providers...),
			CreatedAt: t.CreatedAt,
		})
	}
	return out
}

// Add creates a new token. Fails if one with the same value already exists.
func (s *Store) Add(t Token) error {
	t.Token = strings.TrimSpace(t.Token)
	if t.Token == "" {
		return fmt.Errorf("token required")
	}
	if t.WeeklyUSD < 0 {
		t.WeeklyUSD = 0
	}
	t.Name = strings.TrimSpace(t.Name)
	t.Group = auth.NormalizeGroup(t.Group)
	t.Groups = normalizeGroups(t.Groups)
	t.Providers = normalizeProviders(t.Providers)
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.tokens {
		if existing.Token == t.Token {
			return fmt.Errorf("token already exists")
		}
	}
	s.tokens = append(s.tokens, t)
	return s.saveLocked()
}

// Update patches an existing token. nil fields mean "no change".
// Passing groups != nil REPLACES the Groups slice (use []string{} to clear).
// Passing providers != nil REPLACES the Providers allow-list (use []string{}
// to clear / unrestrict).
func (s *Store) Update(token string, name *string, weekly *float64, maxConc *int, rpm *int, group *string, groups *[]string, providers *[]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.tokens {
		if s.tokens[i].Token == token {
			if name != nil {
				s.tokens[i].Name = strings.TrimSpace(*name)
			}
			if weekly != nil {
				w := *weekly
				if w < 0 {
					w = 0
				}
				s.tokens[i].WeeklyUSD = w
			}
			if maxConc != nil {
				mc := *maxConc
				if mc < 0 {
					mc = 0
				}
				s.tokens[i].MaxConcurrent = mc
			}
			if rpm != nil {
				r := *rpm
				if r < 0 {
					r = 0
				}
				s.tokens[i].RPM = r
			}
			if group != nil {
				s.tokens[i].Group = auth.NormalizeGroup(*group)
			}
			if groups != nil {
				s.tokens[i].Groups = normalizeGroups(*groups)
			}
			if providers != nil {
				s.tokens[i].Providers = normalizeProviders(*providers)
			}
			return s.saveLocked()
		}
	}
	return fmt.Errorf("token not found")
}

// Reset swaps the token string of an existing entry while keeping all
// other fields (name, weekly limit, group, created_at). Useful for
// rotating a leaked secret without losing the row's identity. Refuses
// to clobber another existing token.
func (s *Store) Reset(oldToken, newToken string) error {
	newToken = strings.TrimSpace(newToken)
	if newToken == "" {
		return fmt.Errorf("new token required")
	}
	if oldToken == newToken {
		return fmt.Errorf("new token must differ from old")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := -1
	for i, t := range s.tokens {
		if t.Token == oldToken {
			idx = i
		}
		if t.Token == newToken {
			return fmt.Errorf("new token already exists")
		}
	}
	if idx < 0 {
		return fmt.Errorf("token not found")
	}
	s.tokens[idx].Token = newToken
	return s.saveLocked()
}

// Delete removes a token.
func (s *Store) Delete(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, t := range s.tokens {
		if t.Token == token {
			s.tokens = append(s.tokens[:i], s.tokens[i+1:]...)
			return s.saveLocked()
		}
	}
	return fmt.Errorf("token not found")
}

func (s *Store) saveLocked() error {
	if s.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	payload := struct {
		Tokens []Token `json:"tokens"`
	}{Tokens: s.tokens}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// Generate returns a fresh token in the form sk-<48 alphanumerics>.
func Generate() (string, error) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	const n = 48
	max := big.NewInt(int64(len(alphabet)))
	b := make([]byte, n)
	for i := 0; i < n; i++ {
		v, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		b[i] = alphabet[v.Int64()]
	}
	return "sk-" + string(b), nil
}
