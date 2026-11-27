//go:build !linux

package scan

import "os/exec"

// dieWithParent: no portable equivalent of Pdeathsig; the browser is closed
// by ShutdownBrowsers on a normal exit and after bidiIdle of inactivity.
func dieWithParent(cmd *exec.Cmd) {}

// processAlive: unknown on this platform — assume alive (never delete).
func processAlive(pid int) bool { return true }
