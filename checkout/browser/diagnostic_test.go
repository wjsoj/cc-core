package browser

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestRuntimeDiagnosticRejectsProxyBeforeStarting(t *testing.T) {
	if _, err := CheckRuntime(context.Background(), Config{Proxy: "socks5://secret:secret@8.8.8.8:1080"}); err == nil {
		t.Fatal("offline check accepted proxy")
	}
}

func TestChromiumOfflineRuntimeDiagnostic(t *testing.T) {
	path := os.Getenv("GPTPAY_TEST_CHROMIUM")
	if path == "" {
		t.Skip("local Chromium required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	r, err := CheckRuntime(ctx, Config{Executable: path, Locale: "en-US", Timezone: "America/New_York", Lifetime: time.Minute})
	if err != nil || !r.Offline || !r.JavaScript || !r.WebAssembly || r.Product == "" || r.Locale != "en-US" || r.Timezone != "America/New_York" {
		t.Fatalf("diagnostic: %+v %v", r, err)
	}
}
