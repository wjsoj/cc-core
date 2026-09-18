//go:build !linux

package browser

import "os/exec"

func protectBrowserParent(*exec.Cmd) {}
