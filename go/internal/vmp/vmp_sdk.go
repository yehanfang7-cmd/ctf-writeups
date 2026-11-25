//go:build vmprotect && windows && cgo

package vmp

/*
// Build requirements (see docs/vmprotect-manual.md):
//   1. Install the VMProtect SDK.
//   2. Point cgo at it, e.g.:
//        set CGO_CFLAGS=-IC:\VMProtect\SDK\C
//        set CGO_LDFLAGS=C:\VMProtect\SDK\C\VMProtectSDK64.lib
//   3. Build with: ... build -tags vmprotect ...
//   4. Open the resulting exe in VMProtect; the "CriticalCombine" marker pair
//      is auto-detected and set to Virtualization.
//
#cgo CFLAGS: -I${SRCDIR}
#include "VMProtectSDK.h"
#include <stdint.h>

static uint64_t native_combine(uint64_t a, uint64_t b, uint64_t c) {
    VMProtectBegin("CriticalCombine");
    uint64_t x = a ^ (b * 0x9E3779B97F4A7C15ULL + 0x165667B19E3779F9ULL);
    x = (x << 31) | (x >> 33);
    x *= c | 1ULL;
    x ^= x >> 29;
    x *= 0xBF58476D1CE4E5B9ULL;
    x ^= x >> 32;
    VMProtectEnd();
    return x;
}
*/
import "C"

// Protected reports that this binary was built with the VMProtect SDK path.
const Protected = true

// CriticalCombine runs the decision fold inside the VMProtect-virtualized native
// function. Result is identical to the pure-Go combine() in vmp_stub.go.
func CriticalCombine(a, b, c uint64) uint64 {
	return uint64(C.native_combine(C.uint64_t(a), C.uint64_t(b), C.uint64_t(c)))
}
