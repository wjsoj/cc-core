package checkout

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNetworkBindingSurvivesRestartWithoutCredentials(t *testing.T) {
	for _, selected := range []string{"", "socks5://fixture-user:fixture-secret@proxy.example.invalid:1080"} {
		t.Run(selected[:min(len(selected), 6)], func(t *testing.T) {
			a, q, _, _ := reconciliationFixture(t)
			l := ledgerFor(t)
			pinned := ""
			if selected != "" {
				pinned = "socks5://fixture-user:fixture-secret@8.8.8.8:1080"
			}
			bound := l.WithNetwork(selected, pinned)
			if bound == l || l.network != nil {
				t.Fatal("binding mutated shared ledger")
			}
			if err := bound.BeginAttempt(a, q); err != nil {
				t.Fatal(err)
			}
			reopened, err := NewLedger(l.dir)
			if err != nil {
				t.Fatal(err)
			}
			if reopened.VerifyNetworkSelection(a, q.Session, " "+selected+" ") != nil || reopened.VerifyNetworkEndpoint(a, q.Session, pinned) != nil {
				t.Fatal("original network was not restored")
			}
			if reopened.VerifyNetworkSelection(a, q.Session, selected+"changed") == nil || reopened.VerifyNetworkEndpoint(a, q.Session, pinned+"changed") == nil {
				t.Fatal("accepted a different network")
			}
			foreign := a
			foreign.Token = "foreign_synthetic_token_12345"
			if reopened.VerifyNetworkSelection(foreign, q.Session, selected) == nil {
				t.Fatal("foreign owner recovered binding")
			}
			if reopened.WithNetwork("different", "different").BeginAttempt(a, q) == nil {
				t.Fatal("overwrote durable guard")
			}
			sum := sha256.Sum256([]byte(q.Session.Entity + ":" + q.Session.ID))
			data, err := os.ReadFile(filepath.Join(l.dir, hex.EncodeToString(sum[:])+".json"))
			if err != nil {
				t.Fatal(err)
			}
			for _, secret := range []string{"fixture-user", "fixture-secret", "proxy.example.invalid", "8.8.8.8", a.Token} {
				if strings.Contains(string(data), secret) {
					t.Fatal("persisted plaintext credential or endpoint")
				}
			}
		})
	}
}

func TestLegacyAndMalformedNetworkBindingFailClosed(t *testing.T) {
	for _, value := range []any{nil, map[string]any{"version": 2, "selection_sha256": strings.Repeat("a", 64), "endpoint_sha256": strings.Repeat("b", 64)}, map[string]any{"version": 1, "selection_sha256": "bad", "endpoint_sha256": strings.Repeat("b", 64)}} {
		a, q, l, _ := reconciliationFixture(t)
		sum := sha256.Sum256([]byte(q.Session.Entity + ":" + q.Session.ID))
		path := filepath.Join(l.dir, hex.EncodeToString(sum[:])+".json")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var record map[string]any
		if err := json.Unmarshal(data, &record); err != nil {
			t.Fatal(err)
		}
		record["network"] = value
		data, err = json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		if !l.Owns(a, q.Session) {
			t.Fatal("legacy ownership lost")
		}
		if l.VerifyNetworkSelection(a, q.Session, "") == nil || l.VerifyNetworkEndpoint(a, q.Session, "") == nil {
			t.Fatal("unverifiable network assumed direct")
		}
		if l.WithNetwork("", "").BeginAttempt(a, q) == nil {
			t.Fatal("legacy guard bypassed")
		}
	}
}
