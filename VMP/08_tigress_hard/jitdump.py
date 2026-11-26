"""Dump the JIT buffers of a 0005/0006 program after one run, plus how each is entered."""
import sys, json
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from jitscan import scan
from emu import *

def dump(n, k, x=12345):
    e, out, allocs, spans, entries, regions = scan(HERE/"inputs"/n/f"challenge-{k}", [x])
    bufs = []
    for (p, al, sz) in allocs:
        base = (p + al - 1) & ~(al - 1)
        code = bytes(e.uc.mem_read(base, sz))
        executed = sorted(a for a in regions if base <= a < base + sz)
        bufs.append({"base": base, "size": sz, "code": code, "executed": executed})
    return e, out, bufs, entries

if __name__ == "__main__":
    n, k = sys.argv[1], sys.argv[2]
    which = int(sys.argv[3]) if len(sys.argv) > 3 else -1
    e, out, bufs, entries = dump(n, k)
    b = bufs[which]
    (HERE/"generated"/f"{n}-{k}-jit{which % len(bufs)}.bin").write_bytes(b["code"])
    print("out", out, "base %#x size %d executed %d" % (b["base"], b["size"], len(b["executed"])))
    first = [(hex(a), hex(t)) for a, t, c in entries if b["base"] <= t < b["base"] + b["size"]][:3]
    print("entered:", first)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    ex = set(b["executed"])
    for ins in md.disasm(b["code"], b["base"]):
        print("%s %#x: %-8s %s" % ("*" if ins.address in ex else " ", ins.address, ins.mnemonic, ins.op_str))
