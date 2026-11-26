"""Tigress challenge 0006 (JIT applied twice): recover SECRET as C.

  native SECRET --builds--> outer JIT code (implicit-flow obfuscated)
  outer JIT code --builds--> inner JIT code == the original SECRET, compiled by MyJIT

The inner buffer is taken from the emulated process after one run and lifted to C (x86lift.py).

Gates (any failure raises):
  A. the inner buffer is byte-identical for different inputs (the generated code does not depend on x)
  B. z3 path enumeration over the lifted blocks covers every block, except blocks z3 proves unreachable
     (those must be empty)
  C. gcc-compiled C == inner code run in Unicorn, on N inputs + one input per path
  D. gcc-compiled C == the whole original program (main, both JIT stages) on a smaller input set
"""
import sys
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

import x86lift
import verify
from verify import devirt
from emu import *

HERE = Path(__file__).resolve().parent
GEN = HERE / "generated"


class Jit:
    """One process image after a run; the JIT buffers stay in memory and can be called directly."""

    def __init__(self, path, x=12345):
        self.emu = e = Emu(Program(path))
        self.allocs = []
        e.on_call["posix_memalign"] = lambda em: self.allocs.append((em.heap, em.arg(1), em.arg(2)))
        self.first_out = int(e.run([x])[0])
        self.bufs = []
        for p, al, sz in self.allocs:
            base = (p + al - 1) & ~(al - 1)
            self.bufs.append((base, bytes(e.uc.mem_read(base, sz))))
        self.inp, self.outp = e.alloc(64), e.alloc(64)

    def call(self, base, x):
        e = self.emu
        e.wq(self.inp, x); e.wq(self.outp, 0)
        sp = STACK_TOP - 0x2000
        e.wq(sp, EXIT)
        e.uc.reg_write(UC_X86_REG_RSP, sp)
        e.uc.reg_write(UC_X86_REG_RDI, self.inp); e.uc.reg_write(UC_X86_REG_RSI, self.outp)
        e.start(base)
        return e.rq(self.outp)


def whole(path, x):
    return int(Emu(Program(path)).run([x])[0])


def solve(k, n_random=2000, n_whole=24):
    path = HERE / "inputs" / "0006" / f"challenge-{k}"
    j = Jit(path)
    assert len(j.bufs) == 2, f"expected two JIT buffers, got {len(j.bufs)}"
    base, code = j.bufs[1]
    # gate A
    other = Jit(path, x=0xFEDCBA9876543210)
    assert other.bufs[1][1] == code and other.bufs[1][0] == base, "inner JIT code depends on the input"
    # trim to the function: MyJIT pads the buffer; lift() only follows reachable code
    blocks = x86lift.lift(code, 0)
    src = x86lift.BlockLifter(blocks).source()
    # gate B
    paths, undecided, visited = verify.explore_blocks(blocks)
    covered, dead, unknown = verify.coverage(blocks, paths, undecided, visited)
    assert not unknown, f"z3 could not decide the branches leading to blocks {sorted(unknown)}"
    assert all(not blocks[b][0] for b in dead), f"unreachable blocks with statements: {sorted(dead)}"
    # gate C
    xs = devirt.test_inputs(n_random) + [p["input"] for p in paths]
    bad = verify.compare_c(src, f"0006-{k}", lambda x: j.call(base, x), xs)
    assert not bad, f"C differs from the inner JIT code on {len(bad)} inputs, e.g. {bad[0]}"
    # gate D
    ws = [p["input"] for p in paths] + devirt.test_inputs(n_whole, seed=600 + k)[-(n_whole - len(paths)):]
    for x in ws:
        want = whole(path, x)
        got = j.call(base, x)
        assert want == got, f"whole program {want:#x} != inner code {got:#x} for x={x:#x}"
    (GEN / f"0006-{k}.c").write_text(src)
    n_insn = sum(1 for _ in Cs(CS_ARCH_X86, CS_MODE_64).disasm(code, 0))
    return dict(k=k, dead=len(dead), outer=len(j.bufs[0][1]), inner=len(code), blocks=len(blocks), paths=len(paths),
                compared=len(xs), whole=len(ws), lines=src.count("\n"), source=src)


if __name__ == "__main__":
    ks = [int(a) for a in sys.argv[1:]] or range(5)
    report = []
    for k in ks:
        r = solve(k)
        line = (f"0006 challenge-{k}: outer JIT {r['outer']} bytes -> inner JIT {r['inner']} bytes, {r['blocks']} blocks, "
                f"{r['paths']} paths ({r['dead']} empty block proven unreachable), C ({r['lines']} lines) == inner code on {r['compared']} inputs, "
                f"== whole program on {r['whole']} inputs")
        print(line, flush=True)
        report.append(line)
    if len(report) == 5:
        (GEN / "report-0006.txt").write_text("\n".join(report) + "\n")
