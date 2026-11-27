//go:build linux

package scan

import (
	"os/exec"
	"syscall"
)

// dieWithParent makes the kernel kill the browser when osint-forge exits for
// any reason — even kill -9 or a crash, when no cleanup code runs — so a
// persistent headless Firefox is never left behind as an orphan.
func dieWithParent(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}

// processAlive reports whether a process with this pid still exists.
func processAlive(pid int) bool {
	return pid > 0 && syscall.Kill(pid, 0) == nil
}
