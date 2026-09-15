package auth

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestSubscriptionBrowserCapture199(t *testing.T) {
	r, err := http.NewRequest(http.MethodGet, "https://chatgpt.com/backend-api/accounts/check/v4-2023-04-27", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Authorization", "Bearer fixture_not_real")
	r.Header.Set("Chatgpt-Account-Id", "fixture-account")
	applySubscriptionBrowserHeaders(r, SubscriptionBrowserContext{TimezoneOffsetMinutes: 420})
	if r.URL.Query().Get("timezone_offset_min") != "420" {
		t.Fatal("capture query parameter missing")
	}
	for k, want := range map[string]string{
		"Accept": "*/*", "Oai-Language": "en-US", "Sec-Ch-Ua-Platform": `"macOS"`,
		"Sec-Ch-Ua-Arch": `"arm"`, "Priority": "u=1, i",
		"X-Openai-Target-Path":  "/backend-api/accounts/check/v4-2023-04-27",
		"X-Openai-Target-Route": "/backend-api/accounts/check/{version}",
		"Authorization":         "Bearer fixture_not_real", "Chatgpt-Account-Id": "fixture-account",
	} {
		if r.Header.Get(k) != want {
			t.Errorf("header %s differs", k)
		}
	}
	if !strings.Contains(r.Header.Get("User-Agent"), "Chrome/148.") {
		t.Fatal("wrong capture version")
	}
	for _, k := range []string{"Cookie", "Oai-Device-Id", "Oai-Session-Id", "X-Oai-Is-Client-Observation"} {
		if r.Header.Get(k) != "" {
			t.Errorf("must not fabricate or replay %s", k)
		}
	}
	applySubscriptionBrowserHeaders(r, SubscriptionBrowserContext{TimezoneOffsetMinutes: -480})
	if r.URL.Query().Get("timezone_offset_min") != "-480" {
		t.Fatal("hard-coded captured timezone")
	}
}

func TestSubscriptionBrowserContextValidation(t *testing.T) {
	for _, minutes := range []int{-841, 841} {
		if _, err := subscriptionBrowserContext(context.Background(), []SubscriptionBrowserContext{{TimezoneOffsetMinutes: minutes}}); err == nil {
			t.Fatal("invalid timezone accepted")
		}
	}
}
