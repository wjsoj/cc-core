package browser

import (
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

func TestBrowserEnvironmentIsAllowlisted(t *testing.T) {
	values := map[string]string{"PATH": "/unsafe-custom-path", "LANG": "en_US.UTF-8", "TZ": "UTC", "TMPDIR": "/tmp/fixture", "DISPLAY": ":42", "XAUTHORITY": "/tmp/display-authority", "XDG_RUNTIME_DIR": "/tmp/runtime", "GPTPAY_SYNTHETIC_SECRET": "fixture_secret", "HTTP_PROXY": "http://fixture", "SSLKEYLOGFILE": "/tmp/keylog", "LD_PRELOAD": "fixture", "CHROME_LOG_FILE": "/tmp/log", "GOOGLE_API_KEY": "fixture_key", "HOME": "/fixture-home"}
	lookup := func(key string) (string, bool) { value, ok := values[key]; return value, ok }
	want := []string{"PATH=/usr/local/bin:/usr/bin:/bin", "LANG=en_US.UTF-8", "TZ=UTC", "TMPDIR=/tmp/fixture"}
	if got := browserEnvironment(false, lookup); !reflect.DeepEqual(got, want) {
		t.Fatal("headless environment exceeded allowlist")
	}
	wantHeadful := append(append([]string{}, want...), "DISPLAY=:42", "XAUTHORITY=/tmp/display-authority", "XDG_RUNTIME_DIR=/tmp/runtime")
	if got := browserEnvironment(true, lookup); !reflect.DeepEqual(got, wantHeadful) {
		t.Fatal("headful environment did not preserve exactly the allowed display settings")
	}
	if got := browserEnvironment(false, func(string) (string, bool) { return "", true }); !reflect.DeepEqual(got, []string{"PATH=/usr/local/bin:/usr/bin:/bin"}) {
		t.Fatal("empty settings must not replace fixed defaults")
	}
}

func TestIsolatedCommandDoesNotTriggerChromedpEnvironmentMerge(t *testing.T) {
	t.Setenv("GPTPAY_SYNTHETIC_SECRET", "must_not_be_forwarded")
	cmd := exec.Command("/absolute/chromium", "--headless", "--proxy-server=http://127.0.0.1:9000", "about:blank")
	isolatedBrowserCommand(cmd, false)
	if cmd.Env == nil || len(cmd.Env) != 0 || cmd.Path != cleanEnvironmentLauncher {
		t.Fatal("inheriting environment or bypassing launcher")
	}
	for _, arg := range cmd.Args {
		if strings.Contains(arg, "must_not_be_forwarded") || strings.Contains(arg, "GPTPAY_SYNTHETIC_SECRET") {
			t.Fatal("secret in process arguments")
		}
	}
	tail := cmd.Args[len(cmd.Args)-4:]
	if !reflect.DeepEqual(tail, []string{"/absolute/chromium", "--headless", "--proxy-server=http://127.0.0.1:9000", "about:blank"}) {
		t.Fatal("browser flags changed")
	}
}
