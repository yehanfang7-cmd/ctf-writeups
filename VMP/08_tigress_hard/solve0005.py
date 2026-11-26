"""Tigress challenge 0005 (Virtualize + JIT): recover SECRET as C.

  native SECRET --builds--> JIT code == a stack-VM interpreter (if-nest dispatch, implicit-flow copies)
  the interpreter runs bytecode stored in .data

The JIT buffer is taken from the emulated process.  Its VM layout (dispatch head, vpc slot, vsp slot,
bytecode address) is found by observing one run, not by matching code.  Then unit 06's black-box
method applies unchanged: classify every opcode by experiments on the real handlers, decode the
bytecode, enumerate paths with z3, lift to C.

Gates (any failure raises):
  A. the JIT buffer is byte-identical for different inputs
  B. lockstep: on every VM step of real runs, the classified semantics predict the real state
  C. z3 enumerates the paths through the lifted blocks; every block is covered by a solved input, proven
     unreachable, or reported as "undecided" when z3 times out on its branch condition
  D. gcc-compiled C == JIT interpreter run in Unicorn, on N inputs + one input per path
  E. gcc-compiled C == the whole original program on a smaller input set
"""
import sys
import struct
from collections import Counter
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_READ, UcError

import verify
from verify import devirt
from emu import *
from solve0006 import Jit, whole

HERE = Path(__file__).resolve().parent
GEN = HERE / "generated"
FRAME = 0x4000                      # bytes of machine stack saved/restored around the interpreter's frame


class JitMachine:
    """The JIT-compiled interpreter, with the interface devirt.classify/decode/lockstep expect."""

    def __init__(self, path):
        self.jit = j = Jit(path)
        assert len(j.bufs) == 1, f"expected one JIT buffer, got {len(j.bufs)}"
        self.base, self.code = j.bufs[0]
        self.emu = e = j.emu
        self.uc = uc = e.uc
        self.inp, self.out = j.inp, j.outp
        uc.mem_map(devirt.SCR, 0x10000)
        self.data_end = max(s.virtual_address + s.virtual_size for s in e.prog.elf.segments)
        self.L = self._layout()
        self.on_head = None                                # one permanent hook at the head; callers swap the callback
        uc.hook_add(UC_HOOK_CODE, lambda uc_, a, s, _: self.on_head and self.on_head(), begin=self.L["head"], end=self.L["head"])
        self.flush()
        # state at the first arrival at the head, for probes
        self._enter(0x1234567)
        uc.emu_start(self.base, self.L["head"])
        self.ctx = uc.context_save()
        self.rbp = uc.reg_read(UC_X86_REG_RBP)
        self.sp0 = self.q(self.rbp + self.L["vsp"])
        data = [(s.virtual_address, s.size) for s in e.prog.elf.sections if s.name in (".data", ".bss")]
        self.snap = [(a, bytes(uc.mem_read(a, n))) for a, n in data + [(self.rbp - FRAME, FRAME + 0x100), (devirt.SCR, 0x10000)]]

    def flush(self): self.uc.ctl_remove_cache(self.base, self.base + len(self.code))
    def q(self, a): return struct.unpack("<Q", self.uc.mem_read(a, 8))[0]
    def wq(self, a, v): self.uc.mem_write(a, struct.pack("<Q", v & M64))

    def _enter(self, x):
        uc = self.uc
        self.wq(self.inp, x); self.wq(self.out, 0)
        sp = STACK_TOP - 0x2000
        uc.mem_write(sp - FRAME, bytes(FRAME))
        self.wq(sp, EXIT)
        uc.reg_write(UC_X86_REG_RSP, sp)
        uc.reg_write(UC_X86_REG_RDI, self.inp); uc.reg_write(UC_X86_REG_RSI, self.out)

    def _layout(self):
        """Observe one call.  head = the address most handlers jump back to; vpc = the frame slot read
        first after the head (it holds a .data address); vsp = the frame slot that is rewritten with frame addresses."""
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        back = Counter()
        for ins in md.disasm(self.code, self.base):
            if ins.mnemonic == "jmp" and ins.op_str.startswith("0x"):
                t = int(ins.op_str, 16)
                if t < ins.address: back[t] += 1
        head, n_handlers = back.most_common(1)[0]
        assert n_handlers >= 8, "no dispatch head found"
        uc = self.uc
        st = dict(armed=False, vpc=None, rbp=None, writes=Counter(), heads=0)

        def on_head(uc_, a, s, _):
            st["heads"] += 1
            st["armed"] = st["vpc"] is None
            st["rbp"] = uc_.reg_read(UC_X86_REG_RBP)

        def on_read(uc_, access, addr, size, value, _):
            if st["armed"] and size == 8 and st["rbp"] - FRAME < addr < st["rbp"]:
                st["vpc"] = addr - st["rbp"]; st["armed"] = False

        def on_write(uc_, access, addr, size, value, _):
            rbp = st["rbp"]
            if rbp and size == 8 and rbp - FRAME < addr < rbp and rbp - FRAME < (value & M64) < rbp:
                st["writes"][addr - rbp] += 1
        hs = [uc.hook_add(UC_HOOK_CODE, on_head, begin=head, end=head), uc.hook_add(UC_HOOK_MEM_READ, on_read),
              uc.hook_add(UC_HOOK_MEM_WRITE, on_write)]
        self.flush()                                       # hooks only reach code translated after they are added
        self._enter(0x1234567)
        self.emu.start(self.base)
        for h in hs: uc.hook_del(h)
        self.flush()
        assert st["vpc"] is not None and st["heads"] > 20, "the head candidate is not a dispatch loop"
        vsp, n = st["writes"].most_common(1)[0]
        assert n > st["heads"] // 8, "no VM stack pointer found"
        # bytecode address: value of vpc at the first head arrival
        self._enter(0x1234567)
        uc.emu_start(self.base, head)
        rbp = uc.reg_read(UC_X86_REG_RBP)
        code = self.q(rbp + st["vpc"])
        sec = {s.name: s for s in self.emu.prog.elf.sections}[".data"]
        assert sec.virtual_address <= code < sec.virtual_address + sec.size, "vpc does not point into .data"
        return dict(head=head, vpc=st["vpc"], vsp=vsp, code=code, handlers=n_handlers)

    # ---- interface used by devirt -------------------------------------------------------
    def vm_state(self):
        rbp = self.uc.reg_read(UC_X86_REG_RBP)
        return self.q(rbp + self.L["vpc"]) - self.L["code"], self.q(rbp + self.L["vsp"])

    def run(self, x, on_head=None):
        self.on_head = (lambda: on_head(self)) if on_head else None
        try:
            self._enter(x)
            self.emu.start(self.base)
            return self.q(self.out)
        finally:
            self.on_head = None

    def probe(self, code, stack, fill=None, above=0):
        uc, L = self.uc, self.L
        uc.context_restore(self.ctx)
        for a, d in self.snap: uc.mem_write(a, d)
        uc.mem_write(devirt.SCR, code + bytes(32))
        if fill is not None: uc.mem_write(devirt.DATA, fill)
        base = self.sp0 + 64
        for i, v in enumerate(stack): self.wq(base + 8 * i, v)
        sp = base + 8 * (len(stack) - 1)
        self.wq(sp + 8, above)
        self.wq(self.rbp + L["vpc"], devirt.SCR); self.wq(self.rbp + L["vsp"], sp)
        hits = [0]

        def at_head():
            hits[0] += 1
            if hits[0] > 1: uc.emu_stop()
        self.on_head = at_head
        halted = False
        try:
            uc.emu_start(L["head"], 0, count=200000)
        except Exited:
            halted = True
        except (UcError, RuntimeError) as ex:
            return dict(error=str(ex))
        finally:
            self.on_head = None
        if halted: return dict(halt=True)
        if hits[0] <= 1: return dict(error="did not return to the head")
        npc, nsp = self.q(self.rbp + L["vpc"]), self.q(self.rbp + L["vsp"])
        if (nsp - sp) % 8: return dict(error="misaligned stack pointer")
        return dict(dpc=npc - devirt.SCR, dsp=(nsp - sp) // 8, top=self.q(nsp))


def solve(k, n_random=2000, n_whole=16, lock_random=20):
    path = HERE / "inputs" / "0005" / f"challenge-{k}"
    mc = JitMachine(path)
    other = Jit(path, x=0xFEDCBA9876543210)                                   # gate A
    assert other.bufs[0] == (mc.base, mc.code), "JIT code depends on the input"
    isa, insns = devirt.decode(mc)
    lifter = devirt.Lifter(insns)
    paths, undecided, visited = verify.explore_blocks(lifter.blocks)                   # gate C
    covered, dead, unknown = verify.coverage(lifter.blocks, paths, undecided, visited)
    xs_lock = [p["input"] for p in paths] + devirt.test_inputs(lock_random, seed=500 + k)
    steps = sum(devirt.lockstep(mc, insns, x) for x in xs_lock)               # gate B
    src = lifter.source()
    xs = devirt.test_inputs(n_random) + [p["input"] for p in paths]           # gate D
    bad = verify.compare_c(src, f"0005-{k}", mc.run, xs)
    assert not bad, f"C differs from the interpreter on {len(bad)} inputs, e.g. {bad[0]}"
    ws = [p["input"] for p in paths] + devirt.test_inputs(n_whole, seed=550 + k)[-max(0, n_whole - len(paths)):]
    for x in ws:                                                              # gate E
        want, got = whole(path, x), mc.run(x)
        assert want == got, f"whole program {want:#x} != interpreter {got:#x} for x={x:#x}"
    (GEN / f"0005-{k}.c").write_text(src)
    kinds = sorted({s[0] for s in isa.values()})
    return dict(k=k, blocks=len(lifter.blocks), dead=len(dead), unknown=len(unknown), L=mc.L, jit=len(mc.code), opcodes=len(isa), kinds=kinds, insns=len(insns), paths=len(paths),
                lock_inputs=len(xs_lock), steps=steps, compared=len(xs), whole=len(ws), lines=src.count("\n"), source=src)


if __name__ == "__main__":
    ks = [int(a) for a in sys.argv[1:]] or range(5)
    report = []
    for k in ks:
        r = solve(k)
        L = r["L"]
        line = (f"0005 challenge-{k}: JIT interpreter {r['jit']} bytes, head {L['head']:#x}, vpc rbp{L['vpc']:+#x}, vsp rbp{L['vsp']:+#x}, "
                f"bytecode {L['code']:#x}, {r['opcodes']} opcodes ({', '.join(r['kinds'])}), {r['insns']} VM instructions, {r['blocks']} blocks: {r['paths']} paths, {r['dead']} proven dead, {r['unknown']} undecided, "
                f"lockstep {r['steps']} steps on {r['lock_inputs']} inputs, C ({r['lines']} lines) == interpreter on {r['compared']} inputs, "
                f"== whole program on {r['whole']} inputs")
        print(line, flush=True)
        report.append(line)
    if len(report) == 5:
        (GEN / "report-0005.txt").write_text("\n".join(report) + "\n")
