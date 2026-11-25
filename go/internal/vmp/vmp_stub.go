//go:build !vmprotect

// Package vmp is the VMProtect (layer 6) integration point.
//
// Why a native (cgo) function instead of SDK macros around Go code:
// VMProtect's VMProtectBegin/VMProtectEnd markers must bracket machine code
// INSIDE A SINGLE native function. You cannot reliably wrap a pure-Go function
// with them. The robust, garble-proof pattern is therefore to move the single
// most sensitive decision into a small C function compiled via cgo and bracket
// THAT with the markers. garble never touches C, so the markers survive, and
// VMProtect virtualizes exactly the bytes between them.
//
// This file is the DEFAULT build: pure-Go, no SDK required, markers are no-ops.
// Build with `-tags vmprotect` (and the VMProtect SDK present) to compile
// vmp_sdk.go instead, which runs the identical computation inside markers.
package vmp

// Protected reports whether this binary was built with the VMProtect SDK path.
const Protected = false

// CriticalCombine folds the three diffused license-trust fragments into the
// final decision scalar. This is the most sensitive single operation in the
// client, which is exactly why it is isolated here as the virtualization target.
//
// The pure-Go and SDK implementations MUST agree bit-for-bit.
func CriticalCombine(a, b, c uint64) uint64 {
	return combine(a, b, c)
}

// combine is shared logic so both build variants stay in sync.
func combine(a, b, c uint64) uint64 {
	x := a ^ (b*0x9E3779B97F4A7C15 + 0x165667B19E3779F9)
	x = (x << 31) | (x >> 33)
	x *= c | 1
	x ^= x >> 29
	x *= 0xBF58476D1CE4E5B9
	x ^= x >> 32
	return x
}
