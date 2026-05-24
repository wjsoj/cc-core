package kiroauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// AuthMethod is the credential flavor.
type AuthMethod string

const (
	AuthSocial AuthMethod = "social"
	AuthIdC    AuthMethod = "idc"
	AuthAPIKey AuthMethod = "api_key"
)

// canonicalizeAuthMethod normalizes legacy / case variants.
// builder-id / iam → idc ; apikey / API_KEY → api_key.
func canonicalizeAuthMethod(s string) AuthMethod {
	low := strings.ToLower(strings.TrimSpace(s))
	switch low {
	case "builder-id", "builderid", "iam":
		return AuthIdC
	case "apikey", "api-key", "api_key":
		return AuthAPIKey
	case "":
		return ""
	default:
		return AuthMethod(low)
	}
}

// Credentials is one Kiro credential record. Fields use kiro.rs's camelCase
// on-disk schema so credentials.json files are byte-compatible.
type Credentials struct {
	ID              uint64     `json:"id,omitempty"`
	AccessToken     string     `json:"accessToken,omitempty"`
	RefreshToken    string     `json:"refreshToken,omitempty"`
	ProfileARN      string     `json:"profileArn,omitempty"`
	ExpiresAt       string     `json:"expiresAt,omitempty"` // RFC3339
	AuthMethod      AuthMethod `json:"authMethod,omitempty"`
	ClientID        string     `json:"clientId,omitempty"`     // IdC
	ClientSecret    string     `json:"clientSecret,omitempty"` // IdC
	Priority        uint32     `json:"priority,omitempty"`
	Region          string     `json:"region,omitempty"`
	AuthRegion      string     `json:"authRegion,omitempty"`
	APIRegion       string     `json:"apiRegion,omitempty"`
	MachineID       string     `json:"machineId,omitempty"`
	Email           string     `json:"email,omitempty"`
	SubscriptionTier string    `json:"subscriptionTitle,omitempty"`
	ProxyURL        string     `json:"proxyUrl,omitempty"`
	ProxyUsername   string     `json:"proxyUsername,omitempty"`
	ProxyPassword   string     `json:"proxyPassword,omitempty"`
	Disabled        bool       `json:"disabled,omitempty"`
	KiroAPIKey      string     `json:"kiroApiKey,omitempty"`
	Endpoint        string     `json:"endpoint,omitempty"`
}

// IsAPIKey reports whether this credential is the headless ksk_ flavor.
func (c *Credentials) IsAPIKey() bool {
	if c.KiroAPIKey != "" {
		return true
	}
	return c.AuthMethod == AuthAPIKey
}

// Method returns the canonicalized auth method, defaulting to Social if unset.
func (c *Credentials) Method() AuthMethod {
	if c.IsAPIKey() {
		return AuthAPIKey
	}
	m := canonicalizeAuthMethod(string(c.AuthMethod))
	if m == "" {
		return AuthSocial
	}
	return m
}

// EffectiveAuthRegion returns the region used for token refresh, falling back
// through authRegion → region → fallback (typically DefaultAuthRegion).
func (c *Credentials) EffectiveAuthRegion(fallback string) string {
	if c.AuthRegion != "" {
		return c.AuthRegion
	}
	if c.Region != "" {
		return c.Region
	}
	if fallback != "" {
		return fallback
	}
	return DefaultAuthRegion
}

// EffectiveAPIRegion returns the region used for q.<region>.amazonaws.com API
// calls, falling through apiRegion → fallback (NOT region — kiro.rs precedent).
func (c *Credentials) EffectiveAPIRegion(fallback string) string {
	if c.APIRegion != "" {
		return c.APIRegion
	}
	if fallback != "" {
		return fallback
	}
	return DefaultAuthRegion
}

// ExpiresAtTime parses ExpiresAt as RFC3339. Returns zero Time on empty / invalid.
func (c *Credentials) ExpiresAtTime() time.Time {
	if c.ExpiresAt == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, c.ExpiresAt)
	if err != nil {
		return time.Time{}
	}
	return t
}

// SetExpiresIn updates ExpiresAt to now + d seconds (RFC3339, UTC).
func (c *Credentials) SetExpiresIn(d time.Duration) {
	c.ExpiresAt = time.Now().Add(d).UTC().Format(time.RFC3339)
}

// IsExpired returns true if ExpiresAt is in the past, or within skew of now.
// Zero / unparseable ExpiresAt counts as expired (forces refresh).
func (c *Credentials) IsExpired(skew time.Duration) bool {
	t := c.ExpiresAtTime()
	if t.IsZero() {
		return true
	}
	return time.Now().Add(skew).After(t)
}

// SupportsOpus is false only when the subscription tier explicitly says FREE.
// Unknown tier ⇒ permissive (caller will get a real-server denial if wrong).
func (c *Credentials) SupportsOpus() bool {
	tier := strings.ToUpper(c.SubscriptionTier)
	if tier == "" {
		return true
	}
	return !strings.Contains(tier, "FREE")
}

// File is the on-disk shape of credentials.json. Supports both the single-object
// legacy form and the array form for multi-credential setups.
type File struct {
	creds []Credentials
	// raw remembers whether the loaded file was an array (multi) or object (single),
	// so Save preserves that shape unless explicitly changed.
	wasArray bool
}

// NewSingle wraps one credential as a single-form File.
func NewSingle(c Credentials) *File { return &File{creds: []Credentials{c}, wasArray: false} }

// NewMulti wraps zero or more credentials as an array-form File.
func NewMulti(cs []Credentials) *File { return &File{creds: append([]Credentials(nil), cs...), wasArray: true} }

// Load reads credentials.json from path. Missing or empty file → empty multi-form.
func Load(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &File{wasArray: true}, nil
		}
		return nil, fmt.Errorf("kiroauth: read %s: %w", path, err)
	}
	if len(data) == 0 || allWhitespace(data) {
		return &File{wasArray: true}, nil
	}
	return parse(data)
}

func parse(data []byte) (*File, error) {
	// Detect array vs object by first non-whitespace byte.
	for _, b := range data {
		switch b {
		case ' ', '\t', '\r', '\n':
			continue
		case '[':
			var arr []Credentials
			if err := json.Unmarshal(data, &arr); err != nil {
				return nil, fmt.Errorf("kiroauth: parse credentials array: %w", err)
			}
			f := &File{creds: arr, wasArray: true}
			f.canonicalize()
			return f, nil
		case '{':
			var one Credentials
			if err := json.Unmarshal(data, &one); err != nil {
				return nil, fmt.Errorf("kiroauth: parse single credential: %w", err)
			}
			f := &File{creds: []Credentials{one}, wasArray: false}
			f.canonicalize()
			return f, nil
		default:
			return nil, fmt.Errorf("kiroauth: credentials.json must start with '{' or '['; got %q", string(b))
		}
	}
	return &File{wasArray: true}, nil
}

func allWhitespace(b []byte) bool {
	for _, c := range b {
		if c != ' ' && c != '\t' && c != '\r' && c != '\n' {
			return false
		}
	}
	return true
}

func (f *File) canonicalize() {
	for i := range f.creds {
		if f.creds[i].AuthMethod != "" {
			f.creds[i].AuthMethod = canonicalizeAuthMethod(string(f.creds[i].AuthMethod))
		}
	}
}

// Sorted returns credentials sorted by Priority ascending (lower = higher
// priority). Disabled creds are kept in the result; callers filter as needed.
func (f *File) Sorted() []Credentials {
	out := make([]Credentials, len(f.creds))
	copy(out, f.creds)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Priority < out[j].Priority })
	return out
}

// All returns the credentials in their on-disk order (no sorting).
func (f *File) All() []Credentials {
	out := make([]Credentials, len(f.creds))
	copy(out, f.creds)
	return out
}

// IsArray reports whether the file was loaded from (or constructed as) the
// array form. Save preserves this.
func (f *File) IsArray() bool { return f.wasArray }

// Replace overwrites the in-memory list with cs. ConvertToArray controls whether
// to force the array on-disk shape on the next Save (useful when growing from
// 1 → N credentials).
func (f *File) Replace(cs []Credentials, convertToArray bool) {
	f.creds = append([]Credentials(nil), cs...)
	if convertToArray {
		f.wasArray = true
	} else if len(cs) > 1 {
		// More than one credential cannot fit the single-object form.
		f.wasArray = true
	}
}

// Update mutates the credential matching matchID (or, if matchID==nil,
// the one matching matchByRefresh) in place and re-saves to path. Returns
// the updated record. Concurrent callers serialize through the package mutex.
//
// This is the operation kiro.rs calls "writeback" after a refresh succeeded
// and returned a new refresh_token — losing the new refresh_token after the
// server has rotated it means the account is permanently locked out.
func (f *File) Update(updated Credentials, matchByRefresh string) error {
	for i := range f.creds {
		match := false
		if updated.ID != 0 && f.creds[i].ID == updated.ID {
			match = true
		} else if matchByRefresh != "" && f.creds[i].RefreshToken == matchByRefresh {
			match = true
		}
		if match {
			f.creds[i] = updated
			return nil
		}
	}
	// Not found — append (treat as add).
	f.creds = append(f.creds, updated)
	if len(f.creds) > 1 {
		f.wasArray = true
	}
	return nil
}

var saveMu sync.Mutex

// Save atomically writes the credentials to path.
//
// Atomicity: writes to <path>.tmp, fsyncs, then renames over path. A crash
// mid-write leaves the previous file intact.
func (f *File) Save(path string) error {
	saveMu.Lock()
	defer saveMu.Unlock()

	var data []byte
	var err error
	if f.wasArray || len(f.creds) != 1 {
		data, err = json.MarshalIndent(f.creds, "", "  ")
	} else {
		data, err = json.MarshalIndent(f.creds[0], "", "  ")
	}
	if err != nil {
		return fmt.Errorf("kiroauth: marshal: %w", err)
	}
	data = append(data, '\n')

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("kiroauth: mkdir: %w", err)
	}

	tmp := path + ".tmp"
	if err := writeFileSync(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("kiroauth: rename: %w", err)
	}
	return nil
}

func writeFileSync(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return fmt.Errorf("kiroauth: open %s: %w", path, err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("kiroauth: write %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("kiroauth: sync %s: %w", path, err)
	}
	return f.Close()
}
