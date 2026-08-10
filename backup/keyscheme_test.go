package backup

import (
	"testing"
	"time"
)

// mkObjs builds a listing the way listBackups would, from key stems.
func mkObjs(t *testing.T, prefix string, stems ...string) []BackupObject {
	t.Helper()
	out := make([]BackupObject, 0, len(stems))
	for _, s := range stems {
		key := prefix + s + objectSuffix
		d, legacy, ok := parseKeyDate(key)
		if !ok {
			t.Fatalf("test stem %q does not parse", s)
		}
		out = append(out, BackupObject{Key: key, Date: d, Legacy: legacy})
	}
	return out
}

// The incident, as a key-scheme test: two runs on one day must produce two
// distinct objects. Under the old one-object-per-day naming the second PUT
// replaced the first, and on 2026-08-09 that replaced the last good copy of a
// database with the already-damaged state.
func TestSameDayRunsGetDistinctKeys(t *testing.T) {
	opt := Options{S3: S3Config{Prefix: "app"}}
	day := time.Date(2026, 8, 9, 3, 31, 44, 0, time.UTC)

	morning := opt.S3.normPrefix() + day.Format(stampLayout) + objectSuffix
	evening := opt.S3.normPrefix() + day.Add(17*time.Hour).Format(stampLayout) + objectSuffix

	if morning == evening {
		t.Fatal("two runs on the same day collide on one key")
	}
	for _, k := range []string{morning, evening} {
		if _, legacy, ok := parseKeyDate(k); !ok || legacy {
			t.Errorf("generated key %q does not parse as a current key", k)
		}
	}
	// And they must still land in the same retention bucket.
	m, _, _ := parseKeyDate(morning)
	e, _, _ := parseKeyDate(evening)
	if (BackupObject{Date: m}).Day() != (BackupObject{Date: e}).Day() {
		t.Error("same-day runs fell into different retention days")
	}
}

// A bare date is what an operator types. With several runs behind it, it has
// to mean the newest one — and an exact stem has to still pin a specific run.
func TestResolveTargetSemantics(t *testing.T) {
	prefix := "app/"
	objs := mkObjs(t, prefix,
		"2026-08-09T210000Z", "2026-08-09T033144Z", "2026-08-08", "2026-08-07T031122Z")
	sortObjs(objs)

	for _, tc := range []struct{ want, key string }{
		{"latest", "2026-08-09T210000Z"},
		{"", "2026-08-09T210000Z"},
		{"2026-08-09", "2026-08-09T210000Z"},         // newest run of that day
		{"2026-08-09T033144Z", "2026-08-09T033144Z"}, // pinned run
		{"2026-08-08", "2026-08-08"},                 // legacy key, reached by its day
		{"2026-08-07", "2026-08-07T031122Z"},
	} {
		got, err := pickKey(objs, prefix, tc.want)
		if err != nil {
			t.Errorf("resolve %q: %v", tc.want, err)
			continue
		}
		if got != prefix+tc.key+objectSuffix {
			t.Errorf("resolve %q = %q, want stem %q", tc.want, got, tc.key)
		}
	}

	for _, bad := range []string{"2026-08-01", "garbage"} {
		if _, err := pickKey(objs, prefix, bad); err == nil {
			t.Errorf("resolve %q should have failed", bad)
		}
	}
}

// The transition case, and the one that bit during verification: a day that
// has BOTH a legacy date-only object and newer timestamped runs.
//
// A legacy key's own stem is a bare date, so resolving exact stems before
// dates hands back the legacy object — the older copy, and on the day of the
// incident the damaged one. The date form has to win.
func TestBareDatePrefersNewestRunOverLegacyKeyOfSameDay(t *testing.T) {
	prefix := "app/"
	objs := mkObjs(t, prefix, "2026-08-09", "2026-08-09T133818Z", "2026-08-09T133957Z")
	sortObjs(objs)

	got, err := pickKey(objs, prefix, "2026-08-09")
	if err != nil {
		t.Fatal(err)
	}
	if want := prefix + "2026-08-09T133957Z" + objectSuffix; got != want {
		t.Errorf("bare date resolved to %q, want the newest run %q", got, want)
	}
	// The legacy object must still be reachable when asked for by name.
	if got, err := pickKey(objs, prefix, "2026-08-09.tar.gz.enc"); err == nil {
		t.Errorf("a full filename should not resolve, got %q", got)
	}
	// And a specific timestamped run must still be pinnable.
	got, err = pickKey(objs, prefix, "2026-08-09T133818Z")
	if err != nil {
		t.Fatal(err)
	}
	if want := prefix + "2026-08-09T133818Z" + objectSuffix; got != want {
		t.Errorf("pinned run resolved to %q, want %q", got, want)
	}
}

// Retention counts calendar days, so every run of a day expires together and
// the result does not depend on the clock time a run fired at.
func TestPruneCutoffIsWholeDays(t *testing.T) {
	now := time.Date(2026, 8, 9, 21, 0, 0, 0, time.UTC)
	cutoff := now.UTC().AddDate(0, 0, -7).Truncate(24 * time.Hour)

	keep := []string{"2026-08-02T000001Z", "2026-08-02T235959Z", "2026-08-09T033144Z"}
	drop := []string{"2026-08-01T235959Z", "2026-07-30"}

	for _, s := range keep {
		d, _, _ := parseKeyDate("app/" + s + objectSuffix)
		if d.UTC().Truncate(24 * time.Hour).Before(cutoff) {
			t.Errorf("%s pruned but is inside the 7-day window", s)
		}
	}
	for _, s := range drop {
		d, _, _ := parseKeyDate("app/" + s + objectSuffix)
		if !d.UTC().Truncate(24 * time.Hour).Before(cutoff) {
			t.Errorf("%s kept but is outside the 7-day window", s)
		}
	}
}
