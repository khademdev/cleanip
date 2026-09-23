//go:build !windows

package main

import "os/exec"

// hideWindow - روی سیستم‌های غیر ویندوز کاری نمی‌کند
func hideWindow(cmd *exec.Cmd) {}
