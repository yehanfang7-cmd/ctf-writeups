"""Find JIT-generated code: which heap buffers get executed, from where, and how often."""
import sys
from emu import *

def scan(path, args):
    e = Emu(Program(path))
    allocs = []                                # (ptr, size) from posix_memalign
    e.on_call["posix_memalign"] = lambda em: allocs.append((em.heap, em.arg(1), em.arg(2)))
    regions = {}                               # heap exec: page-less contiguous tracking
    state = {"prev": 0, "entries": []}
    def code(uc, addr, size, _):
        r = state
        if not (HEAP <= r["prev"] < HEAP + HEAP_SIZE):
            r["entries"].append((r["prev"], addr, e.count_heap))
        e.count_heap += 1
        regions[addr] = regions.get(addr, 0) + 1
        r["prev"] = addr
    def anycode(uc, addr, size, _):
        if not (HEAP <= addr < HEAP + HEAP_SIZE):
            state["prev"] = addr
    e.count_heap = 0
    # block-level hook for non-heap is enough to know the caller region; use code hook on heap only
    from unicorn import UC_HOOK_BLOCK
    e.uc.hook_add(UC_HOOK_BLOCK, anycode)
    e.uc.hook_add(UC_HOOK_CODE, code, begin=HEAP, end=HEAP + HEAP_SIZE)
    out = e.run(args)
    addrs = sorted(regions)
    spans = []
    for a in addrs:
        if spans and a - spans[-1][1] < 0x400: spans[-1][1] = a
        else: spans.append([a, a])
    return e, out, allocs, spans, state["entries"], regions

if __name__ == "__main__":
    n, k = sys.argv[1], sys.argv[2]
    e, out, allocs, spans, entries, regions = scan(HERE/"inputs"/n/f"challenge-{k}", [int(sys.argv[3]) if len(sys.argv) > 3 else 12345])
    print("out", out, "heap insns executed", e.count_heap, "signals", e.signals)
    print("posix_memalign:", [(hex(p), a, s) for p, a, s in allocs])
    for lo, hi in spans:
        n_ex = sum(c for a, c in regions.items() if lo <= a <= hi)
        print("  exec span %#x-%#x  distinct=%d  total=%d" % (lo, hi, sum(1 for a in regions if lo <= a <= hi), n_ex))
    print("entries into heap code (from -> to @heapcount):", [(hex(a), hex(b), c) for a, b, c in entries[:40]], len(entries))
