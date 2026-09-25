//go:build !windows

package main

import "os/exec"

// hideWindow - روی سیستم‌های غیر ویندوز کاری نمی‌کند
func hideWindow(cmd *exec.Cmd) {}

// showAlert is a no-op on non-Windows platforms.
//
// The real implementation lives in proc_windows.go and uses MessageBoxW.
// On Linux/macOS the tool runs as a headless local server, so errors
// are surfaced via the web UI rather than a native dialog.
func showAlert(msg string) {}
