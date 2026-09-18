package browser

import (
	"os"
	"os/exec"
)

// chromedp v0.14.2 appends os.Environ whenever cmd.Env or allocator Env is
// nonempty. A non-nil EMPTY cmd.Env avoids both that merge and os/exec's default
// inheritance. The system env launcher then supplies only approved non-secret
// settings. Do not replace this with chromedp.Env (which would reintroduce all
// service credentials, proxy defaults, TLS key logging and loader variables).
const cleanEnvironmentLauncher = "/usr/bin/env"

func browserEnvironment(headful bool, lookup func(string) (string, bool)) []string {
	env := []string{"PATH=/usr/local/bin:/usr/bin:/bin"}
	keys := []string{"LANG", "LC_ALL", "LC_CTYPE", "TZ", "TMPDIR"}
	if headful {
		keys = append(keys, "DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "XDG_RUNTIME_DIR")
	}
	for _, key := range keys {
		if value, ok := lookup(key); ok && value != "" {
			env = append(env, key+"="+value)
		}
	}
	return env
}

func isolatedBrowserCommand(cmd *exec.Cmd, headful bool) {
	executable := cmd.Path
	args := append([]string{cleanEnvironmentLauncher, "-i", "--"}, browserEnvironment(headful, os.LookupEnv)...)
	args = append(args, executable)
	args = append(args, cmd.Args[1:]...)
	cmd.Path = cleanEnvironmentLauncher
	cmd.Args = args
	cmd.Env = []string{} // nil means inherit; a nonempty slice triggers chromedp's merge
	protectBrowserParent(cmd)
}
