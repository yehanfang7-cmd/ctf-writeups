"""Tigress challenge 0004 (two nested VMs + implicit flow + branch functions): recover SECRET as C.

  native code = interpreter of VM2 (dispatch: call / switch / direct / indirect / if-nest, chosen per program)
  VM2 bytecode = interpreter of VM1 (the first Virtualize pass, PC initialised through implicit flow)
  VM1 bytecode = SECRET

The outer VM is never analysed.  Tigress keeps the locals of a virtualized function in the native
frame, so VM1's pc, stack pointer and stack are plain memory cells of SECRET's frame, and VM1's
bytecode is a byte array in .data.  Everything is found by observation:

  pc1 slot   the stack slot whose value equals the address of each 1-byte read of .data
  R (ret)    the opcode fetched last in a real run
  snapshot   machine state just before pc1 is read for the first fetch (found by bisection on the
             instruction count); nothing before it depends on the bytecode or on the input
  sp1 slot   the slot that, after a probed "push imm", points at the cell holding imm

A probe then is: restore the snapshot, point pc1 at scratch bytecode `op, operands, R, R, R...`,
write the stack cells, run until SECRET returns, and read pc1 / sp1 / the stack from the dead frame.
That is the interface unit 06's classifier needs, so opcode semantics come from experiments on the
real two-level interpreter.

Gates (any failure raises):
  A. trace: a Python model of the classified VM1 runs next to the real program; its opcode-fetch
     addresses and its store events (address, size, value) must equal the real ones, in order
  B. z3 paths over the lifted blocks: covered / proven dead / undecided (reported)
  C. gcc-compiled C == SECRET run in Unicorn (from the snapshot) on N inputs + one input per path
  D. gcc-compiled C == the whole original program (main included) on a smaller input set
"""
import sys
import random
import struct
import time
from collections import Counter
from pathlib import Path

from unicorn import UC_HOOK_BLOCK, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UcError

import verify
from verify import devirt
from emu import *

HERE = Path(__file__).resolve().parent
GEN = HERE / "generated"
FRAME = 0x4000
X0 = 0x1234567
CODEPOS = 0x1000                    # probe bytecode sits here inside the scratch page, R everywhere around


class NestedMachine:
    def __init__(self, path, log=lambda *a: None):
        self.log = log
        self.prog = p = Program(path)
        self.emu = e = Emu(p)
        self.uc = uc = e.uc
        sec = {s.name: (s.virtual_address, s.size) for s in p.elf.sections}
        self.d0, self.d1 = sec[".data"][0], sec[".bss"][0] + sec[".bss"][1]
        self.data_end = self.d1
        uc.mem_map(devirt.SCR, 0x10000)
        # 1. whole run: initialises the globals main sets up, and shows where SECRET is called
        found = {}

        def blk(uc_, a, s, _):
            if not found and a < 0x700000 and bytes(uc_.mem_read(a, 4)) == b"\x55\x48\x89\xe5":
                rdi, rsi = uc_.reg_read(UC_X86_REG_RDI), uc_.reg_read(UC_X86_REG_RSI)
                if all(STACK_TOP - STACK_SIZE <= v < STACK_TOP for v in (rdi, rsi)) and e.rq(rdi) == X0:
                    found.update(secret=a, rsp=uc_.reg_read(UC_X86_REG_RSP))
        h = uc.hook_add(UC_HOOK_BLOCK, blk)
        self.first_out = int(e.run([X0])[0])
        uc.hook_del(h)
        assert found, "SECRET(in, out) call not seen"
        self.secret, self.sp = found["secret"], found["rsp"]
        self.rbp = self.sp - 8
        self.inp, self.out = e.alloc(64), e.alloc(64)
        self.text = (sec[".text"][0] & ~0xFFF, (sec[".text"][0] + sec[".text"][1] + 0xFFF) & ~0xFFF)
        self.entry_mem = [(self.d0, bytes(uc.mem_read(self.d0, self.d1 - self.d0)))]
        self.hooks_on = dict(rd=None, wr=None)
        uc.hook_add(UC_HOOK_MEM_READ, lambda u, acc, a, s, v, _: self.hooks_on["rd"] and self.hooks_on["rd"](a, s),
                    begin=self.d0, end=self.d1)
        uc.hook_add(UC_HOOK_MEM_READ, lambda u, acc, a, s, v, _: self.hooks_on["rd"] and self.hooks_on["rd"](a, s),
                    begin=self.sp - FRAME, end=self.sp)
        uc.hook_add(UC_HOOK_MEM_WRITE, lambda u, acc, a, s, v, _: self.hooks_on["wr"] and self.hooks_on["wr"](a, s, v & M64),
                    begin=self.sp - FRAME, end=self.sp)
        uc.hook_add(UC_HOOK_MEM_WRITE, lambda u, acc, a, s, v, _: self.hooks_on["wr"] and self.hooks_on["wr"](a, s, v & M64),
                    begin=self.out, end=self.out + 8)
        uc.ctl_remove_cache(*self.text)
        self.lens = {}
        self.counted = False
        self._observe()
        self._snapshot()
        self._find_sp()
        self.L = dict(code=self.B1, secret=self.secret, vpc=self.P1 - self.rbp, vsp=self.S1 - self.rbp, ret=self.R,
                      fetches=self.nfetch, prologue=self.n_snap)

    # ---- plumbing ----------------------------------------------------------------------------
    def _go(self, at, count=0):
        """Start emulation.  Unicorn's instruction counter is a hook compiled into translated code, so the cache
        is dropped whenever we switch between counted and free-running execution (counted code is much slower)."""
        if bool(count) != self.counted:
            self.uc.ctl_remove_cache(*self.text)
            self.counted = bool(count)
        self.uc.emu_start(at, 0, count=count)

    def q(self, a): return struct.unpack("<Q", self.uc.mem_read(a, 8))[0]
    def wq(self, a, v): self.uc.mem_write(a, struct.pack("<Q", v & M64))

    def _enter(self, x):
        uc = self.uc
        for a, d in self.entry_mem: uc.mem_write(a, d)
        uc.mem_write(self.sp - FRAME, bytes(FRAME))
        self.wq(self.inp, x); self.wq(self.out, 0); self.wq(self.sp, EXIT)
        uc.reg_write(UC_X86_REG_RSP, self.sp); uc.reg_write(UC_X86_REG_RBP, 0)
        uc.reg_write(UC_X86_REG_RDI, self.inp); uc.reg_write(UC_X86_REG_RSI, self.out)

    def call(self, x, count=0, rd=None, wr=None):
        """SECRET(&x, &out) from its entry.  Returns True if it returned (False: stopped by `count`)."""
        self._enter(x)
        self.hooks_on.update(rd=rd, wr=wr)
        try:
            self._go(self.secret, count)
            return False
        except Exited:
            return True
        finally:
            self.hooks_on.update(rd=None, wr=None)

    # ---- 2. observe one run ------------------------------------------------------------------
    def _observe(self):
        e = self.emu
        cands, hits, first, last = {}, Counter(), {}, {}

        def wr(a, s, v):
            if s == 8 and self.d0 <= v < self.d1 and a < self.sp: cands[a] = cands.get(a, 0) + 1

        def rd(a, s):
            if s == 1 and self.d0 <= a < self.d1:
                for c in cands:
                    if e.rq(c) == a:
                        hits[c] += 1; first.setdefault(c, a); last[c] = a
        assert self.call(X0, rd=rd, wr=wr) and self.q(self.out) == self.first_out, "direct call differs from the whole run"
        # group the slots by the bytecode they walk; VM1's is the one fetched least often
        groups = {}
        for c, n in hits.items():
            if n >= 30: groups.setdefault((first[c], n), []).append(c)
        assert groups, "no slot follows 1-byte reads of .data"
        (self.B1, self.nfetch), slots = min(groups.items(), key=lambda kv: kv[0][1])
        # pc1 ends one past the last fetch (the ret); temporaries holding a copy do not
        self.pc_cands = sorted((c for c in slots if e.rq(c) == last[c] + 1), reverse=True)
        assert self.pc_cands, "no pc1 candidate"
        self.last_fetch = last[self.pc_cands[0]]
        self.R = self.uc.mem_read(self.last_fetch, 1)[0]
        self.c0 = 1
        self.log(f"SECRET {self.secret:#x}, bytecode1 {self.B1:#x}, {self.nfetch} 1-byte fetches, ret opcode {self.R:#x}, "
                 f"pc1 candidates {[hex(c - self.rbp) for c in self.pc_cands]}")

    # ---- 3. snapshot before the first fetch ---------------------------------------------------
    def _snapshot(self):
        uc = self.uc
        for P1 in self.pc_cands:
            st = dict(reads=0, fetched=False)

            def rd(a, s):
                if a == P1 and s == 8: st["reads"] += 1
                elif a == self.B1 and s == 1: st["fetched"] = True

            def upto(n):
                st.update(reads=0, fetched=False)
                self.call(X0, count=n, rd=rd)
                return st["reads"], st["fetched"]
            hi = 1 << 12
            while not upto(hi)[1]: hi <<= 1
            lo = hi >> 1                                    # smallest n whose first n instructions include the fetch
            while lo + 1 < hi:
                mid = (lo + hi) // 2
                if upto(mid)[1]: hi = mid
                else: lo = mid
            n_fetch = hi
            r = upto(n_fetch)[0]
            if r == 0: continue
            lo, hi = 0, n_fetch                             # smallest n whose first n instructions include read #r of P1
            while lo + 1 < hi:
                mid = (lo + hi) // 2
                if upto(mid)[0] >= r: hi = mid
                else: lo = mid
            self.call(X0, count=hi - 1)                     # stop right before that read
            self.P1, self.n_snap = P1, hi - 1
            self.ctx = uc.context_save()
            self.rip = uc.reg_read(UC_X86_REG_RIP)
            self.snap = [(self.d0, bytes(uc.mem_read(self.d0, self.d1 - self.d0))),
                         (self.sp - FRAME, bytes(uc.mem_read(self.sp - FRAME, FRAME + 0x100)))]
            # check: redirecting pc1 must move the fetch to the scratch page
            seen = []
            ret = self._resume([(P1, devirt.SCR + CODEPOS)], bytes([self.R]) * 16, rd=None, watch=seen)
            self.log(f"candidate rbp{P1 - self.rbp:+#x}: fetch at instruction {n_fetch}, {r} reads before, snapshot {self.n_snap}, "
                     f"returned={ret}, scratch reads {[hex(a) for a in seen[:4]]}, final pc1 {self.q(P1):#x}")
            if seen and seen[0] == devirt.SCR + CODEPOS and self.q(P1) == devirt.SCR + CODEPOS + self.c0:
                self.log(f"snapshot after {self.n_snap} native instructions, pc1 at rbp{P1 - self.rbp:+#x}")
                return
        raise AssertionError("no pc1 slot controls the fetch address")

    def _resume(self, pokes, code, fill=None, count=30_000_000, rd=None, wr=None, watch=None, x=None):
        """From the snapshot: apply memory pokes, put `code` in the scratch page (R around it), run to SECRET's return."""
        uc = self.uc
        uc.context_restore(self.ctx)
        for a, d in self.snap: uc.mem_write(a, d)
        scr = bytearray([self.R]) * 0x8000
        scr[CODEPOS:CODEPOS + len(code)] = code
        uc.mem_write(devirt.SCR, bytes(scr))
        uc.mem_write(devirt.DATA, fill if fill is not None else bytes(64))
        if x is not None: self.wq(self.inp, x)
        self.wq(self.out, 0)
        for a, v in pokes: self.wq(a, v)
        h = None
        if watch is not None:
            h = uc.hook_add(UC_HOOK_MEM_READ, lambda u, acc, a, s, v, _: watch.append(a), begin=devirt.SCR, end=devirt.SCR + 0x8000)
        self.hooks_on.update(rd=rd, wr=wr)
        try:
            self._go(self.rip, count)
            return False
        except Exited:
            return True
        finally:
            self.hooks_on.update(rd=None, wr=None)
            if h is not None: uc.hook_del(h)

    # ---- 4. the VM1 stack pointer -------------------------------------------------------------
    def _find_sp(self):
        rng = random.Random(4)
        lo = self.sp - FRAME
        P = [(self.P1, devirt.SCR + CODEPOS)]
        assert self._resume(P, b""), "ret-only bytecode does not return"
        base = bytes(self.uc.mem_read(lo, FRAME))
        for b in range(256):
            if b == self.R: continue
            imm = rng.getrandbits(64) | (1 << 63) | 1
            try:
                if not self._resume(P, bytes([b]) + struct.pack("<Q", imm), count=3_000_000): continue
            except (UcError, RuntimeError):
                continue
            after = bytes(self.uc.mem_read(lo, FRAME))
            at = after.find(struct.pack("<Q", imm))
            if at < 0: continue
            cell = lo + at
            for off in range(0, FRAME - 8):
                if struct.unpack_from("<Q", after, off)[0] == cell and struct.unpack_from("<Q", base, off)[0] == cell - 8:
                    S = lo + off
                    moved = cell + 0x80                      # check: moving sp1 moves where the push lands
                    try:
                        ok = self._resume(P + [(S, moved - 8)], bytes([b]) + struct.pack("<Q", imm), count=3_000_000)
                    except (UcError, RuntimeError):
                        ok = False
                    if ok and self.q(moved) == imm and self.q(S) == moved:
                        self.S1, self.sp0, self.push8 = S, cell - 8, b
                        self.log(f"sp1 at rbp{S - self.rbp:+#x}, empty stack at rbp{self.sp0 - self.rbp:+#x}, opcode {b:#x} pushes imm64")
                        return
        raise AssertionError("no VM1 stack pointer found")

    # ---- interface used by devirt --------------------------------------------------------------
    def oplen(self, op):
        """Operand bytes of an opcode.  A probe runs until SECRET returns, so the scratch bytecode must hold exactly
        one instruction followed by ret opcodes.  With no operand bytes supplied the instruction reads ret opcodes as
        its operand and the ret after it shows its length; a jump would fly off, so it is measured with a short
        forward displacement instead."""
        if op in self.lens: return self.lens[op]
        D = devirt.DATA
        r = self._probe1(bytes([op]), [D + 8, D + 16, D + 24])
        n = None
        if r.get("halt"): n = 0
        elif r.get("dpc") in (1, 2, 3, 5, 9): n = r["dpc"] - 1
        else:
            r = self._probe1(bytes([op]) + struct.pack("<i", 7), [D + 8, D + 16, 1])
            if r.get("dpc") in (8, 5): n = 4
        self.lens[op] = n
        return n

    def probe(self, code, stack, fill=None, above=0):
        n = self.oplen(code[0])
        if n is None: return dict(error="instruction length not measurable")
        return self._probe1(code[:1 + n], stack, fill, above)

    def _probe1(self, code, stack, fill=None, above=0):
        base = self.sp0 + 64
        sp = base + 8 * (len(stack) - 1)
        pokes = [(base + 8 * i, v) for i, v in enumerate(stack)] + [(sp + 8, above), (self.P1, devirt.SCR + CODEPOS), (self.S1, sp)]
        try:
            if not self._resume(pokes, code, fill, count=3_000_000):
                return dict(error="did not return")
        except (UcError, RuntimeError) as ex:
            return dict(error=str(ex))
        dpc = self.q(self.P1) - self.c0 - (devirt.SCR + CODEPOS)       # position of the ret that ended the run
        nsp = self.q(self.S1)
        if dpc == 0: return dict(halt=True)
        if (nsp - sp) % 8: return dict(error="misaligned stack pointer")
        return dict(dpc=dpc, dsp=(nsp - sp) // 8, top=self.q(nsp))

    def run(self, x):
        """Original SECRET on x, resumed from the snapshot (the skipped prologue does not read the input)."""
        uc = self.uc
        uc.context_restore(self.ctx)
        for a, d in self.snap: uc.mem_write(a, d)
        self.wq(self.inp, x); self.wq(self.out, 0)
        try:
            self._go(self.rip)
        except Exited:
            return self.q(self.out)
        raise AssertionError("SECRET did not return")

    def trace(self, x):
        """Real run from the snapshot: 1-byte reads of VM1 bytecode and every write to the frame / output."""
        fetch, writes = [], []
        lo, hi = self.B1, self.last_fetch + 1

        def rd(a, s):
            if s == 1 and lo <= a < hi: fetch.append(a - self.B1)
        uc = self.uc
        uc.context_restore(self.ctx)
        for a, d in self.snap: uc.mem_write(a, d)
        self.wq(self.inp, x); self.wq(self.out, 0)
        self.hooks_on.update(rd=rd, wr=lambda a, s, v: writes.append((a, s, v)))
        try:
            self._go(self.rip)
            raise AssertionError("SECRET did not return")
        except Exited:
            return fetch, writes, self.q(self.out)
        finally:
            self.hooks_on.update(rd=None, wr=None)


def classify_extra(mc, op):
    """Forms unit 06's classifier does not cover.  Returns a semantics tuple or None."""
    # parameter address: operand 0/1 -> address of the frame cell that holds `input` / `output`.
    # (06 expects that cell within 0x400 bytes of rbp; under an outer VM the frame is larger.)
    params = {}
    for v in (0, 1):
        r = mc.probe(bytes([op]) + struct.pack("<I", v), [0x1111])
        if r.get("dsp") != 1 or r.get("dpc") != 5: return None
        off = r["top"] - mc.rbp
        if not -FRAME < off < 0: return None
        held = mc.q(r["top"])
        if held not in (mc.inp, mc.out): return None
        params[v] = ("in" if held == mc.inp else "out", off)
    if {p[0] for p in params.values()} == {"in", "out"}:
        return ("param", params)
    return None


SAFE_RELS = [5, 9, 17, 64, 0x1FF, -2, -9, -64, -0x200, 300, -300, 33]      # never land inside the instruction itself


def classify_jump(mc, op):
    """jmp / conditional branch.  06 tests these with random displacements, which is fine when a probe stops at the
    next dispatch; here a probe runs on to a ret, so the target must not be the jump's own operand bytes."""
    conds = [0, 1, 1 << 32, 1 << 63, 0xFF00, 0x100000000FF, 0x8000000000000001, 2, 1 << 31, 0xFFFFFFFF00000000, 1 << 16, 1 << 8]
    obs = []
    for rel, cond in zip(SAFE_RELS, conds):
        r = mc.probe(bytes([op]) + struct.pack("<i", rel), [0x2222, cond])
        if "dpc" not in r: return None
        obs.append((cond, rel, r["dpc"], r["dsp"]))
    if all(d == 0 and dpc == 1 + rel for c, rel, dpc, d in obs): return ("jmp",)
    if all(d == -1 and dpc in (1 + rel, 5) for c, rel, dpc, d in obs):
        for w in devirt.WIDTHS:
            for sense in ("nz", "z"):
                if all((dpc == 1 + rel) == (((c & ((1 << w) - 1)) != 0) == (sense == "nz")) for c, rel, dpc, d in obs):
                    return ("br", sense, w)
    return None


def decode(mc):
    """devirt.decode, with classify_extra as a fallback for opcodes it reports as unknown."""
    isa = {}
    for _ in range(64):
        try:
            return devirt.decode(mc, isa=isa)
        except ValueError as ex:
            unknown = [op for op, sem in isa.items() if sem[0] == "unknown"]
            if not unknown: raise
            for op in unknown:
                sem = classify_jump(mc, op) or classify_extra(mc, op)
                if sem is None: raise ValueError(f"{ex} (and no extra rule matches)") from None
                isa[op] = sem
    raise ValueError("decode did not converge")


def model_run(mc, insns, x, max_steps=1_000_000):
    """Execute the classified VM1 program in Python on a copy of the snapshot memory.
    Returns (1-byte bytecode reads, store events, output)."""
    mem = {}
    snap = {a: d for a, d in mc.snap}

    def rb(a):
        if a in mem: return mem[a]
        if mc.inp <= a < mc.inp + 8: return (x >> 8 * (a - mc.inp)) & 0xFF
        for base, d in snap.items():
            if base <= a < base + len(d): return d[a - base]
        return 0

    def rd(a, n): return int.from_bytes(bytes(rb(a + i) for i in range(n)), "little")

    def wr(a, n, v):
        for i in range(n): mem[a + i] = (v >> 8 * i) & 0xFF
    for i in range(8): mem[mc.out + i] = 0
    K = devirt.keep_high
    pc, sp, fetch, stores = 0, mc.sp0, [], []
    for _ in range(max_steps):
        op, sem, arg, n = insns[pc]
        fetch.append(pc)
        k = sem[0]
        a, b = rd(sp, 8), rd(sp - 8, 8)
        if k == "push":
            if sem[1] == 1: fetch.append(pc + 1)
            sp += 8; wr(sp, 8, K(rd(sp, 8), arg & M64, sem[3])); pc += n
        elif k == "local": sp += 8; wr(sp, 8, (mc.rbp + sem[1] + arg) & M64); pc += n
        elif k == "param": sp += 8; wr(sp, 8, (mc.rbp + sem[1][arg][1]) & M64); pc += n
        elif k == "load":
            v = rd(a, sem[1])
            wr(sp, 8, K(a, devirt.sx(v, 8 * sem[1]) if sem[2] else v, sem[3])); pc += 1
        elif k == "store":
            ptr, v = (a, b) if sem[2] == "ptr_top" else (b, a)
            v &= (1 << 8 * sem[1]) - 1
            wr(ptr, sem[1], v); stores.append((ptr, sem[1], v)); sp -= 16; pc += 1
        elif k == "bin":
            name, order, cx, cy, w = sem[1:]
            x_, y_ = (a, b) if order == "ts" else (b, a)
            r = devirt.BIN[name](devirt.CASTS[cx](x_), devirt.CASTS[cy](y_))
            assert r is not None, f"model: division by zero at pc {pc}"
            sp -= 8; wr(sp, 8, K(b, r, w)); pc += 1
        elif k == "un": wr(sp, 8, K(a, devirt.UN[sem[1]](a), sem[2])); pc += 1
        elif k == "jmp": pc += 1 + arg
        elif k == "br":
            taken = ((a & ((1 << sem[2]) - 1)) != 0) == (sem[1] == "nz")
            sp -= 8; pc = pc + 1 + arg if taken else pc + n
        elif k == "ret":
            return fetch, stores, rd(mc.out, 8)
    raise AssertionError("model: too many steps")


def trace_gate(mc, insns, x):
    """Gate A for one input.  Returns the number of VM1 steps checked."""
    fetch, writes, out = mc.trace(x)
    mfetch, mstores, mout = model_run(mc, insns, x)
    assert fetch == mfetch, (f"x={x:#x}: fetch sequence differs at index "
                             f"{next((i for i, (p, q_) in enumerate(zip(fetch, mfetch)) if p != q_), min(len(fetch), len(mfetch)))}")
    keys = {(a, s) for a, s, v in mstores}
    real = [(a, s, v & ((1 << 8 * s) - 1)) for a, s, v in writes if (a, s) in keys]
    assert real == mstores, f"x={x:#x}: store sequence differs (real {len(real)} events, model {len(mstores)})"
    assert out == mout, f"x={x:#x}: output {out:#x}, model {mout:#x}"
    return len({i for i in range(len(mfetch))})


def solve(k, n_random=2000, n_whole=8, trace_random=6, budget=300, log=print):
    path = HERE / "inputs" / "0004" / f"challenge-{k}"
    t0 = time.time()
    mc = NestedMachine(path, log=lambda *a: log(f"  [{k}]", *a, flush=True))
    isa, insns = decode(mc)
    log(f"  [{k}] decoded {len(insns)} VM1 instructions, {len(isa)} opcodes in {time.time() - t0:.0f}s", flush=True)
    lifter = devirt.Lifter(insns)
    src = lifter.source()
    paths, undecided, visited = verify.explore_blocks(lifter.blocks)                   # gate B
    covered, dead, unknown = verify.coverage(lifter.blocks, paths, undecided, visited)
    xs_tr = [p["input"] for p in paths] + devirt.test_inputs(trace_random, seed=400 + k)
    steps = sum(trace_gate(mc, insns, x) for x in xs_tr)                      # gate A
    log(f"  [{k}] trace gate passed on {len(xs_tr)} inputs at {time.time() - t0:.0f}s", flush=True)
    t1 = time.time(); mc.run(X0); mc.run(~X0 & M64)
    per_run = max((time.time() - t1) / 2, 1e-3)
    n = max(100, min(n_random, int(budget / per_run)))                        # keep gate C inside the time budget
    log(f"  [{k}] {per_run:.2f}s per run of the original, comparing on {n} inputs", flush=True)
    xs = devirt.test_inputs(n) + [p["input"] for p in paths]                  # gate C
    bad = verify.compare_c(src, f"0004-{k}", mc.run, xs)
    assert not bad, f"C differs from SECRET on {len(bad)} inputs, e.g. {bad[0]}"
    ws = [p["input"] for p in paths] + devirt.test_inputs(n_whole, seed=450 + k)[-max(0, n_whole - len(paths)):]
    for x in ws:                                                              # gate D
        want, got = int(Emu(Program(path)).run([x])[0]), mc.run(x)
        assert want == got, f"whole program {want:#x} != SECRET from the snapshot {got:#x} for x={x:#x}"
    (GEN / f"0004-{k}.c").write_text(src)
    kinds = sorted({s[0] for s in isa.values()})
    return dict(k=k, L=mc.L, opcodes=len(isa), kinds=kinds, insns=len(insns), blocks=len(lifter.blocks), paths=len(paths),
                dead=len(dead), unknown=len(unknown), trace_inputs=len(xs_tr), steps=steps, compared=len(xs), whole=len(ws),
                lines=src.count("\n"), source=src, seconds=time.time() - t0)


if __name__ == "__main__":
    ks = [int(a) for a in sys.argv[1:]] or range(5)
    report = []
    for k in ks:
        r = solve(k)
        L = r["L"]
        line = (f"0004 challenge-{k}: SECRET {L['secret']:#x}, VM1 bytecode {L['code']:#x}, pc1 rbp{L['vpc']:+#x}, sp1 rbp{L['vsp']:+#x}, "
                f"snapshot after {L['prologue']} native instructions, {r['opcodes']} opcodes ({', '.join(r['kinds'])}), "
                f"{r['insns']} VM1 instructions, {r['blocks']} blocks: {r['paths']} paths, {r['dead']} proven dead, {r['unknown']} undecided, "
                f"trace gate {r['steps']} VM1 steps on {r['trace_inputs']} inputs, C ({r['lines']} lines) == SECRET on {r['compared']} inputs, "
                f"== whole program on {r['whole']} inputs, {r['seconds']:.0f}s")
        print(line, flush=True)
        report.append(line)
    if len(report) == 5:
        (GEN / "report-0004.txt").write_text("\n".join(report) + "\n")
