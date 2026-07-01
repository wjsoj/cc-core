package mimicry

import "testing"

func TestNormalizeDateline_AllBeaconVariants(t *testing.T) {
	// 4 apostrophes × 2 separators = the 8 beacon states from odp/qla.
	apos := []string{"'", "’", "ʼ", "ʹ"}
	seps := []string{"-", "/"}
	const canonical = `Today's date is 2026-07-01.`
	for _, a := range apos {
		for _, sep := range seps {
			dated := "2026" + sep + "07" + sep + "01"
			body := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"<system-reminder>\nToday` + a + `s date is ` + dated + `.\n</system-reminder>"}]}]}`)
			out, changed := NormalizeDateline(body)
			isCanonical := a == "'" && sep == "-"
			if isCanonical {
				if changed {
					t.Errorf("canonical (apo=%q sep=%q) should be a no-op", a, sep)
				}
				continue
			}
			if !changed {
				t.Errorf("beacon apo=%q sep=%q not normalized", a, sep)
			}
			if got := string(out); !contains(got, canonical) {
				t.Errorf("apo=%q sep=%q → %q, want canonical %q inside", a, sep, got, canonical)
			}
			// The exotic apostrophe / slash must be gone.
			if a != "'" && contains(string(out), a) {
				t.Errorf("apo=%q survived: %q", a, string(out))
			}
		}
	}
}

func TestNormalizeDateline_NoOpAndBytePreserving(t *testing.T) {
	cases := [][]byte{
		[]byte(`{"messages":[{"role":"user","content":"Today's date is 2026-07-01."}]}`), // already canonical
		[]byte(`{"messages":[{"role":"user","content":"just some text, no dateline"}]}`),
		[]byte(`{"system":"You are Claude Code."}`),
		[]byte(``),
	}
	for _, body := range cases {
		out, changed := NormalizeDateline(body)
		if changed {
			t.Errorf("unexpected change on %q", string(body))
		}
		if string(out) != string(body) {
			t.Errorf("byte identity broken: %q → %q", string(body), string(out))
		}
	}
}

func TestNormalizeDateline_MixedSeparatorNotMatched(t *testing.T) {
	// A user string with a mixed "-" / "/" date must NOT be rewritten
	// (guards against over-eager matching).
	body := []byte(`{"messages":[{"role":"user","content":"Today's date is 2026-07/01."}]}`)
	_, changed := NormalizeDateline(body)
	if changed {
		t.Errorf("mixed-separator date should not match")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
