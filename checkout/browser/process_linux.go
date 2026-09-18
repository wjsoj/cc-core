//go:build linux

package browser

import (
	"os/exec"
	"syscall"
)

func protectBrowserParent(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = new(syscall.SysProcAttr)
	}
	// Preserve chromedp's Linux parent-death cleanup when overriding its command
	// hook. exec from /usr/bin/env into Chromium retains the same child process.
	cmd.SysProcAttr.Pdeathsig = syscall.SIGKILL
}
