//go:build !windows || !cgo

package guard

// antiDebug is a no-op on non-Windows builds or when cgo is disabled. The real
// probes live in antidebug_windows.go.
func antiDebug() bool { return false }
