//go:build windows && cgo

package guard

/*
#include <windows.h>

// Resolve NtQueryInformationProcess dynamically to avoid an import that an
// analyst can grep for in the IAT.
typedef LONG (NTAPI *pNtQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);

static int c_basic_debug_probes(void) {
    if (IsDebuggerPresent()) return 1;

    BOOL remote = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote) && remote) return 1;

    return 0;
}

static int c_ntquery_debug(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;
    pNtQIP f = (pNtQIP)GetProcAddress(ntdll, "NtQueryInformationProcess");
    if (!f) return 0;

    HANDLE self = GetCurrentProcess();

    // ProcessDebugPort (7): non-zero port => user-mode debugger attached.
    DWORD_PTR port = 0;
    if (f(self, 7, &port, sizeof(port), NULL) == 0 && port != 0) return 1;

    // ProcessDebugFlags (0x1f): 0 => NoDebugInherit cleared => being debugged.
    DWORD flags = 1;
    if (f(self, 0x1f, &flags, sizeof(flags), NULL) == 0 && flags == 0) return 1;

    // ProcessDebugObjectHandle (0x1e): non-NULL => a debug object exists.
    HANDLE dbgobj = NULL;
    if (f(self, 0x1e, &dbgobj, sizeof(dbgobj), NULL) == 0 && dbgobj != NULL) return 1;

    return 0;
}

// c_timing_suspect times a tight arithmetic loop. Single-stepping inflates wall
// time by orders of magnitude. The threshold is deliberately generous so normal
// (even heavily loaded) execution never trips it; only interactive stepping does.
static int c_timing_suspect(void) {
    LARGE_INTEGER freq, a, b;
    if (!QueryPerformanceFrequency(&freq)) return 0;
    QueryPerformanceCounter(&a);
    volatile unsigned long long acc = 0;
    for (int i = 0; i < 200000; i++) { acc += (unsigned long long)i * 2654435761ULL; }
    QueryPerformanceCounter(&b);
    double ms = (double)(b.QuadPart - a.QuadPart) * 1000.0 / (double)freq.QuadPart;
    (void)acc;
    // ~0.1ms uninstrumented. Single-stepping inflates this to seconds, so a high
    // threshold still catches a debugger while staying robust on loaded/shared
    // machines (e.g. CI runners) that may preempt the loop for tens of ms.
    return ms > 200.0 ? 1 : 0;
}
*/
import "C"

// antiDebug runs the native probes. Any single positive is enough; the caller
// decides how (and how late) to react.
func antiDebug() bool {
	if C.c_basic_debug_probes() != 0 {
		return true
	}
	if C.c_ntquery_debug() != 0 {
		return true
	}
	if C.c_timing_suspect() != 0 {
		return true
	}
	return false
}
