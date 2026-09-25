//go:build windows

package main

import (
	"os/exec"
	"syscall"
	"unsafe"
)

// hideWindow - مخفی کردن پنجره کنسول روی ویندوز
func hideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000, // CREATE_NO_WINDOW
	}
}

var (
	user32DLL       = syscall.NewLazyDLL("user32.dll")
	procMessageBoxW = user32DLL.NewProc("MessageBoxW")
)

// showAlert displays a modal message box on Windows.
//
// Uses MessageBoxW directly instead of the previous
// `mshta javascript:alert('...')` approach. The old implementation was
// vulnerable to script injection through user-controlled strings
// (single quotes, backslashes, and other metacharacters could break
// out of the alert() call and execute arbitrary HTA/JScript code).
//
// MessageBoxW takes the message as a UTF-16 string argument — no
// parsing, no script engine, no injection surface.
func showAlert(msg string) {
	const (
		MB_OK              = 0x00000000
		MB_ICONINFORMATION = 0x00000040
		MB_SETFOREGROUND   = 0x00010000
	)

	title, _ := syscall.UTF16PtrFromString("CleanIP")
	body, err := syscall.UTF16PtrFromString(msg)
	if err != nil {
		// If the message contains invalid UTF-16 (extremely unlikely
		// for network errors), fall back to a generic message so we
		// never silently swallow the alert.
		body, _ = syscall.UTF16PtrFromString("(unprintable error message)")
	}

	_, _, _ = procMessageBoxW.Call(
		0,
		uintptr(unsafe.Pointer(body)),
		uintptr(unsafe.Pointer(title)),
		uintptr(MB_OK|MB_ICONINFORMATION|MB_SETFOREGROUND),
	)
}
