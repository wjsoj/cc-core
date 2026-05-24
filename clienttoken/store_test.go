package clienttoken

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestAddLookupDeleteRoundTrip(t *testing.T) {
	s := OpenInMemory()
	if !s.Empty() {
		t.Fatal("new store should be Empty")
	}
	if err := s.Add(Token{Token: "sk-aaa", Name: "alice", RPM: 60, WeeklyUSD: 5.0, Group: "private"}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	tok, ok := s.Lookup("sk-aaa")
	if !ok {
		t.Fatal("Lookup miss after Add")
	}
	if tok.Name != "alice" || tok.RPM != 60 || tok.WeeklyUSD != 5.0 || tok.Group != "private" {
		t.Fatalf("Lookup wrong fields: %+v", tok)
	}

	// Duplicate Add should fail.
	if err := s.Add(Token{Token: "sk-aaa"}); err == nil {
		t.Fatal("dup add should fail")
	}

	// Delete.
	if err := s.Delete("sk-aaa"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok := s.Lookup("sk-aaa"); ok {
		t.Fatal("Lookup hit after Delete")
	}
}

func TestUpdateNilSemantics(t *testing.T) {
	s := OpenInMemory()
	_ = s.Add(Token{Token: "sk-bbb", Name: "bob", RPM: 10, WeeklyUSD: 1.0})
	name := "robert"
	weekly := 2.0
	if err := s.Update("sk-bbb", &name, &weekly, nil, nil, nil, nil); err != nil {
		t.Fatalf("Update: %v", err)
	}
	tok, _ := s.Lookup("sk-bbb")
	if tok.Name != "robert" || tok.WeeklyUSD != 2.0 {
		t.Fatalf("Update wrong: %+v", tok)
	}
	if tok.RPM != 10 {
		t.Fatalf("Update should preserve nil-field RPM, got %d", tok.RPM)
	}

	// Negative values get clamped to 0.
	neg := -5.0
	negI := -3
	_ = s.Update("sk-bbb", nil, &neg, &negI, &negI, nil, nil)
	tok, _ = s.Lookup("sk-bbb")
	if tok.WeeklyUSD != 0 || tok.MaxConcurrent != 0 || tok.RPM != 0 {
		t.Fatalf("negative not clamped: %+v", tok)
	}
}

func TestReset(t *testing.T) {
	s := OpenInMemory()
	_ = s.Add(Token{Token: "sk-old", Name: "alice"})
	if err := s.Reset("sk-old", "sk-new"); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if _, ok := s.Lookup("sk-old"); ok {
		t.Fatal("old still present")
	}
	tok, ok := s.Lookup("sk-new")
	if !ok || tok.Name != "alice" {
		t.Fatalf("reset lost identity: %+v", tok)
	}

	// Reset onto existing token should fail.
	_ = s.Add(Token{Token: "sk-other"})
	if err := s.Reset("sk-new", "sk-other"); err == nil {
		t.Fatal("reset onto existing should fail")
	}
}

func TestPersistAndReload(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "tokens.json")
	s1, err := Open(p)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	_ = s1.Add(Token{Token: "sk-persist", Name: "x", WeeklyUSD: 3.14, Group: "g1"})

	s2, err := Open(p)
	if err != nil {
		t.Fatalf("re-Open: %v", err)
	}
	tok, ok := s2.Lookup("sk-persist")
	if !ok || tok.WeeklyUSD != 3.14 || tok.Group != "g1" {
		t.Fatalf("rehydrate wrong: %+v ok=%v", tok, ok)
	}
}

func TestEffectiveGroups(t *testing.T) {
	// Groups set: takes precedence
	tk := Token{Groups: []string{"a", "b"}, Group: "ignored"}
	got := tk.EffectiveGroups()
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("Groups should win: %v", got)
	}
	// Only Group set: promoted
	tk = Token{Group: "legacy"}
	got = tk.EffectiveGroups()
	if len(got) != 1 || got[0] != "legacy" {
		t.Fatalf("Group should be promoted: %v", got)
	}
	// Both empty: public
	tk = Token{}
	got = tk.EffectiveGroups()
	if len(got) != 1 || got[0] != "" {
		t.Fatalf("empty token should yield public: %v", got)
	}
}

func TestNormalizeGroupsDeduplicates(t *testing.T) {
	s := OpenInMemory()
	_ = s.Add(Token{Token: "sk-grp", Groups: []string{"alpha", "", "alpha", "beta", "  alpha  "}})
	tok, _ := s.Lookup("sk-grp")
	if len(tok.Groups) != 2 || tok.Groups[0] != "alpha" || tok.Groups[1] != "beta" {
		t.Fatalf("Groups dedup+normalize wrong: %v", tok.Groups)
	}
}

func TestUpdateGroups(t *testing.T) {
	s := OpenInMemory()
	_ = s.Add(Token{Token: "sk-x", Group: "old"})
	newGroups := []string{"new1", "new2"}
	if err := s.Update("sk-x", nil, nil, nil, nil, nil, &newGroups); err != nil {
		t.Fatal(err)
	}
	tok, _ := s.Lookup("sk-x")
	if len(tok.Groups) != 2 || tok.Groups[0] != "new1" {
		t.Fatalf("Update did not replace Groups: %v", tok.Groups)
	}
	// EffectiveGroups should now use Groups (not the still-set Group).
	if eff := tok.EffectiveGroups(); len(eff) != 2 || eff[0] != "new1" {
		t.Fatalf("EffectiveGroups stale: %v", eff)
	}
	// Pass &[]string{} to clear.
	empty := []string{}
	_ = s.Update("sk-x", nil, nil, nil, nil, nil, &empty)
	tok, _ = s.Lookup("sk-x")
	if len(tok.Groups) != 0 {
		t.Fatalf("Update []string{} should clear Groups, got: %v", tok.Groups)
	}
	// And EffectiveGroups falls back to the still-set Group.
	if eff := tok.EffectiveGroups(); len(eff) != 1 || eff[0] != "old" {
		t.Fatalf("fallback to Group after clear: %v", eff)
	}
}

func TestPersistGroups(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "tokens.json")
	s1, _ := Open(p)
	_ = s1.Add(Token{Token: "sk-multi", Groups: []string{"kiro", "claude"}})
	s2, _ := Open(p)
	tok, ok := s2.Lookup("sk-multi")
	if !ok || len(tok.Groups) != 2 || tok.Groups[0] != "kiro" {
		t.Fatalf("Groups did not persist: %+v ok=%v", tok, ok)
	}
}

func TestGenerateUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		tok, err := Generate()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(tok, "sk-") || len(tok) != 51 {
			t.Fatalf("bad token shape: %q (len=%d)", tok, len(tok))
		}
		if seen[tok] {
			t.Fatal("Generate collision")
		}
		seen[tok] = true
	}
}
