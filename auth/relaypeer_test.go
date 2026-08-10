package auth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// relay_peer decides whether a credential is handed the identity of our
// downstream users, so a rewrite that silently dropped it would quietly undo
// the routing it enables — and a rewrite that invented it would start leaking
// that identity to a vendor.
func TestRelayPeerSurvivesRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "apikey-peer.json")
	write := func(v map[string]any) {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	write(map[string]any{
		"type":       "apikey",
		"api_key":    "sk-test",
		"base_url":   "https://relay.example",
		"relay_peer": true,
	})
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	a, err := parseFile(p, data)
	if err != nil {
		t.Fatalf("parseFile: %v", err)
	}
	if !a.RelayPeer {
		t.Fatal("relay_peer was not parsed")
	}

	if err := a.Persist(); err != nil {
		t.Fatalf("persist: %v", err)
	}
	data, err = os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err := parseFile(p, data)
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if !reloaded.RelayPeer {
		t.Error("relay_peer was dropped by the rewrite")
	}
	if !reloaded.Snapshot().RelayPeer {
		t.Error("Snapshot does not carry RelayPeer")
	}

	// Absent means false, and must not be written back as an explicit false —
	// old files stay byte-compatible.
	write(map[string]any{"type": "apikey", "api_key": "sk-test"})
	data, err = os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := parseFile(p, data)
	if err != nil {
		t.Fatalf("parseFile: %v", err)
	}
	if plain.RelayPeer {
		t.Fatal("a file without relay_peer parsed as a relay peer")
	}
	if err := plain.Persist(); err != nil {
		t.Fatalf("persist: %v", err)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if _, present := got["relay_peer"]; present {
		t.Errorf("persist wrote relay_peer into a file that never had it: %s", raw)
	}
}
