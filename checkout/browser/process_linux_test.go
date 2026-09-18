//go:build linux

package browser

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/chromedp/chromedp"
)

func TestIsolatedCommandKeepsParentDeathSignal(t *testing.T) {
	cmd := exec.Command("/absolute/chromium")
	isolatedBrowserCommand(cmd, false)
	if cmd.SysProcAttr == nil || cmd.SysProcAttr.Pdeathsig != syscall.SIGKILL {
		t.Fatal("lost parent-death cleanup")
	}
}

func TestChromiumDoesNotInheritServiceSecrets(t *testing.T) {
	t.Setenv("GPTPAY_SYNTHETIC_SECRET", "synthetic_secret_not_real_12345")
	t.Setenv("HTTPS_PROXY", "http://synthetic_proxy.invalid:1234")
	t.Setenv("SSLKEYLOGFILE", filepath.Join(t.TempDir(), "tls-keys-must-not-exist"))
	t.Setenv("CHROME_LOG_FILE", filepath.Join(t.TempDir(), "chrome-log-must-not-exist"))
	b, _ := fixtureBrowser(t)
	process := chromedp.FromContext(b.ctx).Browser.Process()
	if process == nil {
		t.Fatal("browser process missing")
	}
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(process.Pid), "environ"))
	if err != nil {
		t.Fatal("cannot inspect own fixture process environment")
	}
	for _, entry := range strings.Split(string(data), "\x00") {
		key, value, _ := strings.Cut(entry, "=")
		if key == "GPTPAY_SYNTHETIC_SECRET" || key == "HTTPS_PROXY" || key == "SSLKEYLOGFILE" || key == "CHROME_LOG_FILE" || value == "synthetic_secret_not_real_12345" {
			t.Fatal("service environment leaked to Chromium")
		}
	}
}
