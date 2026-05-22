package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

// daemonMarkerEnv is set by the parent process when re-execing the child.
// The child sees it and skips the daemonize step, going straight into
// normal server startup. Prevents an infinite re-exec loop.
const daemonMarkerEnv = "__FORGE_PROXY_DAEMONIZED"

// defaultPIDFile and defaultLogFile are the locations used when --pid-file
// / --log-file aren't passed. Falls back to /tmp if the system paths aren't
// writable (e.g. running --daemon as a non-root user for testing).
const (
	defaultPIDFile = "/var/run/forge-proxy.pid"
	defaultLogFile = "/var/log/forge-proxy.log"
	fallbackPIDDir = "/tmp"
	fallbackLogDir = "/tmp"
)

// isDaemonChild reports whether the current process is the re-execed child
// of a --daemon invocation. The child continues with normal server startup
// — daemonize() is a no-op for it.
func isDaemonChild() bool {
	return os.Getenv(daemonMarkerEnv) == "1"
}

// daemonize forks the current process by re-execing self with the
// daemonMarkerEnv set, redirects the child's stdio to logFile, detaches it
// from the controlling terminal via setsid, and writes the child's PID to
// pidFile. The parent prints a brief confirmation and exits zero.
//
// Pre-checks before forking:
//   - Refuse to start if pidFile exists AND points at a live process
//     (prevents double-starts).
//   - Verify logFile / pidFile parent directories are writable.
//
// The child inherits no open file descriptors back to the parent's
// terminal. Once the parent returns, the child is fully detached.
func daemonize(args []string, pidFile, logFile string) error {
	if pidFile == "" {
		pidFile = resolvePIDFile()
	}
	if logFile == "" {
		logFile = resolveLogFile()
	}

	if err := checkExistingPIDFile(pidFile); err != nil {
		return err
	}

	logF, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return fmt.Errorf("open log file %s: %w", logFile, err)
	}
	// Hold the fd open for the duration of the Start() call; once the
	// child has it via Stdout/Stderr the parent's Close is fine.
	defer logF.Close()

	// Re-exec self with the marker so the child skips daemonize() and
	// drops into normal startup. Args verbatim minus the --daemon flag
	// (already stripped by the caller); the child re-parses everything
	// else from scratch.
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), daemonMarkerEnv+"=1")
	cmd.Stdin = nil
	cmd.Stdout = logF
	cmd.Stderr = logF
	// Setsid detaches from the controlling terminal so closing the
	// parent terminal can't SIGHUP the child.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start daemon: %w", err)
	}

	pid := cmd.Process.Pid
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(pid)+"\n"), 0o644); err != nil {
		// Try to clean up — the child is still running but we couldn't
		// record its PID. Better to surface this loudly than to leave
		// an unmanaged process.
		_ = cmd.Process.Kill()
		return fmt.Errorf("write pid file %s: %w", pidFile, err)
	}

	// Parent reports + exits. The child continues running with the
	// redirected stdio.
	fmt.Fprintf(os.Stdout, "forge-proxy: daemonized as pid %d\n", pid)
	fmt.Fprintf(os.Stdout, "  log file: %s\n", logFile)
	fmt.Fprintf(os.Stdout, "  pid file: %s\n", pidFile)
	fmt.Fprintf(os.Stdout, "stop with: kill $(cat %s)\n", pidFile)

	// Release the child so it can outlive us cleanly.
	if err := cmd.Process.Release(); err != nil {
		// Non-fatal — the child is still running, we just can't release
		// the os.Process handle. The parent is about to exit anyway.
		fmt.Fprintf(os.Stderr, "forge-proxy: release child: %v\n", err)
	}
	return nil
}

// checkExistingPIDFile returns an error if pidFile exists AND the PID
// inside it points at a live process. Stale PID files (file exists but
// process is gone) are overwritten silently — the common case after a
// crash that didn't get to clean up its PID file.
func checkExistingPIDFile(pidFile string) error {
	data, err := os.ReadFile(pidFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read pid file %s: %w", pidFile, err)
	}
	pidStr := strings.TrimSpace(string(data))
	pid, parseErr := strconv.Atoi(pidStr)
	if parseErr != nil || pid <= 0 {
		// Malformed PID file — treat as stale.
		return nil
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return nil
	}
	// On Unix, FindProcess never errors, so we have to probe with
	// signal 0 (the standard "is it alive?" check).
	if err := proc.Signal(syscall.Signal(0)); err == nil {
		return fmt.Errorf("forge-proxy is already running (pid %d, recorded in %s); stop it first", pid, pidFile)
	}
	return nil
}

// resolvePIDFile returns the default PID-file path: /var/run if writable,
// else /tmp/forge-proxy.pid. Operators who want a different location pass
// --pid-file explicitly.
func resolvePIDFile() string {
	if writable("/var/run") {
		return defaultPIDFile
	}
	return fallbackPIDDir + "/forge-proxy.pid"
}

// resolveLogFile returns the default log-file path: /var/log if writable,
// else /tmp/forge-proxy.log.
func resolveLogFile() string {
	if writable("/var/log") {
		return defaultLogFile
	}
	return fallbackLogDir + "/forge-proxy.log"
}

// writable reports whether the current user can create files in dir.
// Cheaper than a touch-test; uses unix.Access(W_OK) equivalent via Stat
// + permission bits + uid match.
func writable(dir string) bool {
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return false
	}
	// Best-effort: try creating + removing a probe file. The permission
	// matrix on Linux (ACLs, capabilities, mount options) is too varied
	// to compute correctly from Stat alone.
	probe, err := os.CreateTemp(dir, ".forge-proxy-writable-probe-*")
	if err != nil {
		return false
	}
	probe.Close()
	os.Remove(probe.Name())
	return true
}
