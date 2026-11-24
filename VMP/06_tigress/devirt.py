"""Unit 06: devirtualize Tigress challenge 0000 (one level of Virtualize, random dispatch, stack operands).

Pipeline, per program (no knowledge of the dispatcher kind or the opcode numbering is built in):
  1. find SECRET from main, read the VM layout (vpc / vsp slots, bytecode address, dispatch head) from its prologue;
  2. classify every opcode by experiments: run ONE real VM instruction in Unicorn from the head with chosen
     state and match the effect against a library of hypotheses (operation, operand order, casts, write width);
  3. disassemble the bytecode by recursive descent;
  4. lift to C: expression trees, demanded-bits cleanup, variables / arrays from addresses, if / while;
  5. gates:
       A. lockstep: at every VM step of real runs the classified semantics predict pc, sp, the new top of
          stack, every loaded value and every stored value;
       B. z3 enumerates every feasible path of the bytecode; together they must cover all instructions;
       C. the recovered C (compiled with gcc) equals the original SECRET (Unicorn) on 2000 inputs plus one
          input per path.
The binaries are Linux x86-64 and are never executed natively: only SECRET's code runs, inside Unicorn.
"""
import argparse
import hashlib
import io
import os
import random
import re
import shutil
import struct
import subprocess
import sys
import zipfile
from pathlib import Path
from urllib.request import urlopen

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_PROT_ALL
from unicorn.x86_const import (UC_X86_REG_FS_BASE, UC_X86_REG_RBP, UC_X86_REG_RDI, UC_X86_REG_RIP,
                               UC_X86_REG_RSI, UC_X86_REG_RSP)

HERE = Path(__file__).resolve().parent
INPUTS = HERE / "inputs"
GENERATED = HERE / "generated"
URL = "https://tigress.cs.arizona.edu/tigress-challenges-Linux-x86_64.zip"
ZIP_SHA256 = "cabb97d67c591549cde9ce478d8d1db557668bd9ebb25ae077ad6e5fd57a91fc"
MEMBER = "tigress-challenges/Linux-x86_64/0000/challenge-{}"
BINARIES = {
    0: "581936cbe0b0b7a7b323f2c48d93202100faf78d7d512418c7f6f873d8ce011b",
    1: "5f0d952c0e8d3471e38b0ed3bc96263a2b84001a133f3cce626334cbb28b1191",
    2: "087a550f3730c574548806ed34e465ba0370f48173e53edc5c4137fcf6bcd072",
    3: "fe8e69f2d348bcc2c9050f2552665736fc3a3f098fcd11b2bfbb514cef1a8043",
    4: "3344044ae05863f4162be58c234e5c40819c5a8630b2de118c17f4454b84dfa9",
}
SCRIPT = ("tigress-challenges/Linux-x86_64/0000.sh", "c5de881dff4f4d2128a297ca18b251a950223666f85b08c350b9b91bf8053701")

M = 2**64 - 1
STOP, STACK, TLS = 0x10000, 0x7FF00000, 0x7FC00000
SCR = 0x5A5A5A5A0000            # scratch page for probes; high bits set so "keeps the pointer's high bits" is visible
DATA = SCR + 0x8000
CANARY = 0xDEADBEEFCAFEF00D


# ============================================================================ inputs

def fetch():
    """Download the archive once, check it and the five binaries, extract them (never executed)."""
    INPUTS.mkdir(parents=True, exist_ok=True)
    archive = INPUTS / "tigress-challenges-Linux-x86_64.zip"
    if not archive.exists():
        with urlopen(URL, timeout=120) as r:
            archive.write_bytes(r.read(64 * 1024 * 1024))
    if hashlib.sha256(archive.read_bytes()).hexdigest() != ZIP_SHA256:
        raise ValueError(f"SHA256 mismatch for {archive}")
    with zipfile.ZipFile(archive) as z:
        for k, digest in BINARIES.items():
            data = z.read(MEMBER.format(k))
            if hashlib.sha256(data).hexdigest() != digest:
                raise ValueError(f"SHA256 mismatch for challenge-{k}")
            (INPUTS / f"challenge-{k}").write_bytes(data)
        data = z.read(SCRIPT[0])
        if hashlib.sha256(data).hexdigest() != SCRIPT[1]:
            raise ValueError("SHA256 mismatch for 0000.sh")
        (INPUTS / "0000.sh").write_bytes(data)


def binary(k):
    path = INPUTS / f"challenge-{k}"
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != BINARIES[k]:
        raise ValueError(f"SHA256 mismatch for {path}")
    return data


# ============================================================================ ELF + x86

class Elf:
    def __init__(self, data: bytes):
        if data[:4] != b"\x7fELF" or data[4] != 2:
            raise ValueError("not an ELF64 file")
        self.data = data
        self.entry, phoff = struct.unpack_from("<QQ", data, 24)
        phnum = struct.unpack_from("<H", data, 56)[0]
        self.loads = []
        for i in range(phnum):
            t, fl, off, va, pa, fs, ms, al = struct.unpack_from("<IIQQQQQQ", data, phoff + 56 * i)
            if t == 1:
                self.loads.append((off, va, fs, ms))
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)

    def read(self, va, n):
        for off, v, fs, ms in self.loads:
            if v <= va < v + fs:
                return self.data[off + va - v:off + va - v + n]
        raise ValueError(f"{va:#x} is not in a loaded segment")

    def dis(self, va, count):
        out = []
        for ins in self.md.disasm(self.read(va, count * 15), va):
            out.append((ins.address, ins.mnemonic, ins.op_str))
            if len(out) == count:
                break
        return out


def expect(cond, what):
    if not cond:
        raise ValueError(f"unexpected code: {what}")


def find_secret(elf):
    """_start passes main in rdi; main calls SECRET(in, out) right after 'mov rsi, rdx; mov rdi, rax'."""
    start = elf.dis(elf.entry, 12)
    main = [int(o.split(", ")[1], 16) for a, m, o in start if m == "mov" and o.startswith("rdi, 0x")]
    expect(len(main) == 1, "_start does not load main into rdi")
    ins = elf.dis(main[0], 80)
    for i in range(2, len(ins)):
        if ins[i][1] == "call" and ins[i - 1][1:] == ("mov", "rdi, rax") and ins[i - 2][1:] == ("mov", "rsi, rdx"):
            return int(ins[i][2], 16)
    raise ValueError("unexpected code: no SECRET(in, out) call in main")


def vm_layout(elf, secret):
    """Prologue: lea rax, [rbp-S]; mov [rbp-SP], rax; mov qword [rbp-PC], <bytecode>.  Head = first read of PC."""
    ins = elf.dis(secret, 40)
    for i, (a, m, o) in enumerate(ins):
        mm = re.fullmatch(r"qword ptr \[rbp - (0x[0-9a-f]+)\], (0x[0-9a-f]+)", o)
        if m == "mov" and mm:
            m2 = re.fullmatch(r"qword ptr \[rbp - (0x[0-9a-f]+)\], rax", ins[i - 1][2])
            m3 = re.fullmatch(r"rax, \[rbp - (0x[0-9a-f]+)\]", ins[i - 2][2])
            expect(m2 and m3 and ins[i - 2][1] == "lea", "VM stack set-up before the bytecode pointer")
            vpc, code, vsp, vstack = -int(mm[1], 16), int(mm[2], 16), -int(m2[1], 16), -int(m3[1], 16)
            addr = ins[i + 1][0]
            break
    else:
        raise ValueError("unexpected code: no bytecode pointer initialisation")
    for _ in range(4):
        a, m, o = elf.dis(addr, 1)[0]
        if m == "jmp" and o.startswith("0x"):
            addr = int(o, 16)
            continue
        expect(m == "mov" and o == f"rax, qword ptr [rbp - {-vpc:#x}]", "dispatch head reads the bytecode pointer")
        return dict(secret=secret, vpc=vpc, vsp=vsp, vstack=vstack, code=code, head=addr)
    raise ValueError("unexpected code: dispatch head not found")


class Machine:
    """SECRET's code in Unicorn.  run(x) executes it; probe() executes one VM instruction from the head."""

    def __init__(self, data):
        self.elf = Elf(data)
        self.L = vm_layout(self.elf, find_secret(self.elf))
        uc = self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
        self.pristine = []
        for off, va, fs, ms in self.elf.loads:
            lo, hi = va & ~0xFFF, (va + ms + 0xFFF) & ~0xFFF
            uc.mem_map(lo, hi - lo, UC_PROT_ALL)
            uc.mem_write(va, data[off:off + fs])
            self.pristine.append((lo, bytes(uc.mem_read(lo, hi - lo))))
        self.data_end = max(va + ms for off, va, fs, ms in self.elf.loads)
        uc.mem_map(STOP, 0x1000); uc.mem_write(STOP, b"\xf4")
        uc.mem_map(STACK - 0x100000, 0x100000)
        uc.mem_map(TLS, 0x1000); uc.mem_write(TLS + 0x28, struct.pack("<Q", CANARY))
        uc.mem_map(SCR, 0x10000)
        uc.reg_write(UC_X86_REG_FS_BASE, TLS)
        self.inp, self.out = STACK - 0x1000 + 0x100, STACK - 0x1000 + 0x200
        self.hooks = []
        # state at the first arrival at the head, for probes
        self._enter(0x1234567)
        uc.emu_start(self.L["secret"], self.L["head"])
        self.ctx = uc.context_save()
        self.snap = [(a, bytes(uc.mem_read(a, n))) for a, n in
                     [(lo, len(d)) for lo, d in self.pristine] + [(STACK - 0x100000, 0x100000), (SCR, 0x10000)]]
        self.rbp = uc.reg_read(UC_X86_REG_RBP)

    def q(self, a): return struct.unpack("<Q", self.uc.mem_read(a, 8))[0]
    def wq(self, a, v): self.uc.mem_write(a, struct.pack("<Q", v & M))

    def _enter(self, x):
        uc = self.uc
        for a, d in self.pristine: uc.mem_write(a, d)
        uc.mem_write(STACK - 0x100000, bytes(0x100000))
        self.wq(self.inp, x); self.wq(self.out, 0)
        sp = STACK - 0x1000 - 8
        self.wq(sp, STOP)
        uc.reg_write(UC_X86_REG_RSP, sp); uc.reg_write(UC_X86_REG_RDI, self.inp); uc.reg_write(UC_X86_REG_RSI, self.out)

    def run(self, x, on_head=None):
        """Original SECRET(&x, &out); on_head(machine) is called at every arrival at the dispatch head."""
        h = None
        if on_head:
            h = self.uc.hook_add(UC_HOOK_CODE, lambda uc, a, s, _: on_head(self), begin=self.L["head"], end=self.L["head"])
        try:
            self._enter(x)
            self.uc.emu_start(self.L["secret"], STOP, count=50_000_000)
            expect(self.uc.reg_read(UC_X86_REG_RIP) == STOP, "SECRET did not return")
            return self.q(self.out)
        finally:
            if h is not None: self.uc.hook_del(h)

    def vm_state(self):
        rbp = self.uc.reg_read(UC_X86_REG_RBP)
        return self.q(rbp + self.L["vpc"]) - self.L["code"], self.q(rbp + self.L["vsp"])

    def probe(self, code: bytes, stack, fill=None, above=0):
        """One VM instruction: bytecode at SCR, stack[-1] on top, `above` in the free slot over it,
        optional bytes at DATA."""
        uc, L = self.uc, self.L
        uc.context_restore(self.ctx)
        for a, d in self.snap: uc.mem_write(a, d)
        uc.mem_write(SCR, code + bytes(32))
        if fill is not None: uc.mem_write(DATA, fill)
        base = self.rbp + L["vstack"] + 32
        for i, v in enumerate(stack): self.wq(base + 8 * i, v)
        sp = base + 8 * (len(stack) - 1)
        self.wq(sp + 8, above)
        self.wq(self.rbp + L["vpc"], SCR); self.wq(self.rbp + L["vsp"], sp)
        hits = [0]
        def at_head(uc, a, s, _):
            hits[0] += 1
            if hits[0] > 1: uc.emu_stop()
        h = uc.hook_add(UC_HOOK_CODE, at_head, begin=L["head"], end=L["head"])
        try:
            uc.emu_start(L["head"], STOP, count=20000)
        except UcError as e:
            return dict(error=str(e))
        finally:
            uc.hook_del(h)
        if uc.reg_read(UC_X86_REG_RIP) == STOP:
            return dict(halt=True)
        if hits[0] <= 1:
            return dict(error="did not return to the head")
        npc, nsp = self.q(self.rbp + L["vpc"]), self.q(self.rbp + L["vsp"])
        if (nsp - sp) % 8:
            return dict(error="misaligned stack pointer")
        return dict(dpc=npc - SCR, dsp=(nsp - sp) // 8, top=self.q(nsp))


# ============================================================================ opcode semantics

def s64(v): return v - (1 << 64) if v >> 63 else v


def sx(v, bits):
    v &= (1 << bits) - 1
    return (v - (1 << bits) if v >> (bits - 1) else v) & M


def _div(a, b, signed, rem):
    if b == 0: return None
    if signed:
        a, b = s64(a), s64(b)
        q = abs(a) // abs(b) * (1 if (a < 0) == (b < 0) else -1)
        return ((a - q * b) if rem else q) & M
    return (a % b if rem else a // b) & M


BIN = {
    "add": lambda a, b: (a + b) & M, "sub": lambda a, b: (a - b) & M, "mul": lambda a, b: (a * b) & M,
    "and": lambda a, b: a & b, "or": lambda a, b: a | b, "xor": lambda a, b: a ^ b,
    "shl": lambda a, b: (a << (b & 63)) & M, "shr": lambda a, b: a >> (b & 63), "sar": lambda a, b: (s64(a) >> (b & 63)) & M,
    "udiv": lambda a, b: _div(a, b, 0, 0), "urem": lambda a, b: _div(a, b, 0, 1),
    "sdiv": lambda a, b: _div(a, b, 1, 0), "srem": lambda a, b: _div(a, b, 1, 1),
    "eq": lambda a, b: int(a == b), "ne": lambda a, b: int(a != b),
    "ult": lambda a, b: int(a < b), "ule": lambda a, b: int(a <= b), "ugt": lambda a, b: int(a > b), "uge": lambda a, b: int(a >= b),
    "slt": lambda a, b: int(s64(a) < s64(b)), "sle": lambda a, b: int(s64(a) <= s64(b)),
    "sgt": lambda a, b: int(s64(a) > s64(b)), "sge": lambda a, b: int(s64(a) >= s64(b)),
}
UN = {"id": lambda a: a, "not": lambda a: a ^ M, "neg": lambda a: -a & M, "lnot": lambda a: int(a == 0)}
for _b in (8, 16, 32):
    UN[f"zext{_b}"] = (lambda b: lambda a: a & ((1 << b) - 1))(_b)
    UN[f"sext{_b}"] = (lambda b: lambda a: sx(a, b))(_b)
CASTS = {"": lambda v: v, "s32": lambda v: sx(v, 32), "z32": lambda v: v & 0xFFFFFFFF}
WIDTHS = (64, 32, 16, 8)


def keep_high(old, new, w):
    """A w-bit result written into a 64-bit slot keeps the slot's other bits (the VM stack is a union)."""
    m = (1 << w) - 1
    return (old & ~m & M) | (new & m)


def classify(mc, op, rng, trials=12):
    """Semantics of one opcode, found by running its real handler on chosen states."""
    def rnd():
        return rng.getrandbits(64) if rng.random() < .7 else rng.choice([0, 1, 2, 63, 64, M, 1 << 63, rng.getrandbits(8)])
    # operand bytes are random: with zeros a "jmp +0" would look like a no-op
    code = bytes([op]) + bytes(rng.randrange(1, 256) for _ in range(16))
    first = mc.probe(code, [rnd(), rnd(), rnd()])
    if first.get("halt"): return ("ret",)
    # load: top = keep_high(ptr, ext(mem[ptr]), w)
    obs = []
    for _ in range(trials):
        fill = bytes(rng.randrange(256) for _ in range(64)); ptr = DATA + rng.randrange(32)
        r = mc.probe(code, [rnd(), rnd(), ptr], fill)
        if r.get("dsp") != 0 or r.get("dpc") != 1: obs = None; break
        obs.append((fill[ptr - DATA:], ptr, r["top"]))
    if obs:
        for w in WIDTHS:
            for size, signed in ((1, 0), (1, 1), (2, 0), (2, 1), (4, 0), (4, 1), (8, 0)):
                def val(mem, size=size, signed=signed):
                    v = int.from_bytes(mem[:size], "little")
                    return sx(v, 8 * size) if signed else v
                if all(t == keep_high(p, val(mem), w) for mem, p, t in obs):
                    return ("load", min(size, w // 8), signed if 8 * size < w else 0, w)
    # store: *ptr = value (size bytes), pops both
    for size in (8, 4, 2, 1):
        for order in ("ptr_top", "val_top"):
            ok = True
            for _ in range(trials):
                ptr = DATA + rng.randrange(32); v = rnd()
                r = mc.probe(code, [rnd(), v, ptr] if order == "ptr_top" else [rnd(), ptr, v], bytes(64))
                got = int.from_bytes(mc.uc.mem_read(DATA, 64), "little")
                if r.get("dsp") != -2 or r.get("dpc") != 1 or got != (v & ((1 << 8 * size) - 1)) << 8 * (ptr - DATA):
                    ok = False; break
            if ok: return ("store", size, order)
    for _ in range(20):
        if "error" not in first: break
        first = mc.probe(code, [rnd(), rng.getrandbits(64) | 1, rng.getrandbits(64) | 1])
    if "error" in first: return ("unknown", first["error"])
    dsp, dpc = first["dsp"], first["dpc"]
    if dsp == -1 and dpc == 1:            # binary: new top = keep_high(second, f(x, y), w)
        obs = []
        for _ in range(2 * trials):
            a, b = rnd(), rnd()
            r = mc.probe(code, [rnd(), b, a])
            if "error" in r: continue      # e.g. a division by zero
            if r.get("dsp") != -1: obs = None; break
            obs.append((a, b, r["top"]))
        if obs:
            for name, f in BIN.items():
                for order in ("ts", "st"):
                    for cx in CASTS:
                        for cy in CASTS:
                            for w in WIDTHS:
                                def ok(a, b, t):
                                    x, y = (a, b) if order == "ts" else (b, a)
                                    v = f(CASTS[cx](x), CASTS[cy](y))
                                    return v is not None and t == keep_high(b, v, w)
                                if all(ok(*o) for o in obs):
                                    return ("bin", name, order, cx, cy, w)
    if dsp == 0 and dpc == 1:             # unary
        obs = [(a, mc.probe(code, [rnd(), rnd(), a]).get("top")) for a in (rnd() for _ in range(2 * trials))]
        for name, f in UN.items():
            for w in WIDTHS:
                if all(t == keep_high(a, f(a), w) for a, t in obs):
                    return ("un", name, w)
    if dsp == 1:
        size = dpc - 1
        obs = []                          # push an immediate: top = keep_high(stale slot, ext(imm), w)
        for _ in range(trials):
            o = bytes(rng.randrange(256) for _ in range(size)); above = rnd()
            r = mc.probe(bytes([op]) + o + bytes(8), [rnd()], above=above)
            if r.get("dsp") != 1 or r.get("dpc") != dpc: obs = None; break
            obs.append((int.from_bytes(o, "little"), above, r["top"]))
        if obs:
            for w in WIDTHS:
                for signed in (0, 1):
                    if all(t == keep_high(ab, sx(v, 8 * size) if signed else v, w) for v, ab, t in obs):
                        return ("push", size, signed, w)
        if size == 4:                     # push the address of a frame slot: local or parameter
            offs = {}
            for v in (0, 1, 2, 4, 8, 16, 24, 40):
                r = mc.probe(bytes([op]) + v.to_bytes(4, "little") + bytes(8), [rnd()])
                offs[v] = r["top"] - mc.rbp if r.get("dsp") == 1 else None
            if None not in offs.values() and len({o - v for v, o in offs.items()}) == 1:
                return ("local", offs[0])
            params = {}
            for v in (0, 1):
                if offs[v] is not None and -0x400 < offs[v] < 0:
                    held = mc.q(mc.rbp + offs[v])
                    if held in (mc.inp, mc.out):
                        params[v] = ("in" if held == mc.inp else "out", offs[v])
            if params: return ("param", params)
    if dsp in (0, -1):                    # jmp rel32 / conditional branch rel32
        obs = []
        for _ in range(2 * trials):
            rel = rng.randrange(-0x200, 0x200)
            o = (rel & 0xFFFFFFFF).to_bytes(4, "little")
            cond = rng.choice([0, 1, 1 << 32, 1 << 63, 0xFF00, 0x100000000FF, rnd(), rnd()])
            r = mc.probe(bytes([op]) + o + bytes(8), [rnd(), cond])
            if r.get("dsp") != dsp: obs = None; break
            if r["dpc"] == 1 + rel and 1 + rel != 5: obs.append((cond, True))
            elif r["dpc"] == 5 and 1 + rel != 5: obs.append((cond, False))
            else: obs = None; break
        if obs and dsp == 0 and all(t for _, t in obs): return ("jmp",)
        if obs and dsp == -1:
            for w in WIDTHS:
                for sense in ("nz", "z"):
                    if all(t == (((c & ((1 << w) - 1)) != 0) == (sense == "nz")) for c, t in obs):
                        return ("br", sense, w)
    return ("unknown", first)


def length(sem):
    if sem[0] == "push": return 1 + sem[1]
    if sem[0] in ("local", "param", "jmp", "br"): return 5
    return 1


def decode(mc, seed=7, isa=None):
    """Recursive descent from pc 0.  Returns (isa, insns): insns[pc] = (opcode, sem, arg, length)."""
    rng = random.Random(seed)
    isa = {} if isa is None else isa
    code = bytes(mc.uc.mem_read(mc.L["code"], mc.data_end - mc.L["code"]))
    insns, todo = {}, [0]
    while todo:
        pc = todo.pop()
        while pc not in insns:
            op = code[pc]
            if op not in isa:
                isa[op] = classify(mc, op, rng)
            sem = isa[op]
            if sem[0] == "unknown":
                raise ValueError(f"opcode {op:#x} at pc {pc} not classified: {sem[1]}")
            n = length(sem)
            arg = int.from_bytes(code[pc + 1:pc + n], "little")
            if sem[0] in ("jmp", "br"): arg = s64(sx(arg, 32))
            if sem[0] == "push" and sem[2]: arg = sx(arg, 8 * sem[1])
            insns[pc] = (op, sem, arg, n)
            if sem[0] == "ret": break
            if sem[0] == "jmp": pc += 1 + arg; continue
            if sem[0] == "br": todo.append(pc + 1 + arg)
            pc += n
    return isa, insns


# ============================================================================ gate A: lockstep

def lockstep(mc, insns, x):
    """Run the original on x; at every head arrival predict the next state from the model.  Returns #steps."""
    pending = [None, None, None]          # (predicted next pc, dsp, top, store), sp, pc of the step being checked
    steps = [0]

    def check(m):
        pc, sp = m.vm_state()
        if pending[0] is not None:
            want_pc, want_dsp, want_top, store = pending[0]
            if pc != want_pc or sp - pending[1] != 8 * want_dsp:
                raise ValueError(f"lockstep: step {steps[0]} pc {pending[2]}: real ({pc}, {sp - pending[1]:+}) "
                                 f"model ({want_pc}, {8 * want_dsp:+})")
            if want_top is not None and m.q(sp) != want_top:
                raise ValueError(f"lockstep: step {steps[0]} pc {pending[2]} {insns[pending[2]][1]}: top {m.q(sp):#x}, model {want_top:#x}")
            if store is not None:
                ptr, size, v = store
                got = int.from_bytes(m.uc.mem_read(ptr, size), "little")
                if got != v & ((1 << 8 * size) - 1):
                    raise ValueError(f"lockstep: step {steps[0]} pc {pending[2]}: stored {got:#x}, model {v:#x}")
        steps[0] += 1
        if pc not in insns:
            raise ValueError(f"lockstep: real pc {pc} was not decoded")
        op, sem, arg, n = insns[pc]
        a, b = m.q(sp), m.q(sp - 8)
        k, store, top = sem[0], None, None
        if k == "push": nxt, d, top = pc + n, 1, keep_high(m.q(sp + 8), arg & M, sem[3])
        elif k == "local": nxt, d, top = pc + n, 1, (m.uc.reg_read(UC_X86_REG_RBP) + sem[1] + arg) & M
        elif k == "param": nxt, d, top = pc + n, 1, (m.uc.reg_read(UC_X86_REG_RBP) + sem[1][arg][1]) & M
        elif k == "load":
            v = int.from_bytes(m.uc.mem_read(a, sem[1]), "little")
            nxt, d, top = pc + 1, 0, keep_high(a, sx(v, 8 * sem[1]) if sem[2] else v, sem[3])
        elif k == "store":
            ptr, v = (a, b) if sem[2] == "ptr_top" else (b, a)
            nxt, d, store = pc + 1, -2, (ptr, sem[1], v)
        elif k == "bin":
            name, order, cx, cy, w = sem[1:]
            x_, y_ = (a, b) if order == "ts" else (b, a)
            nxt, d, top = pc + 1, -1, keep_high(b, BIN[name](CASTS[cx](x_), CASTS[cy](y_)), w)
        elif k == "un": nxt, d, top = pc + 1, 0, keep_high(a, UN[sem[1]](a), sem[2])
        elif k == "jmp": nxt, d = pc + 1 + arg, 0
        elif k == "br":
            taken = ((a & ((1 << sem[2]) - 1)) != 0) == (sem[1] == "nz")
            nxt, d = (pc + 1 + arg if taken else pc + n), -1
        elif k == "ret": nxt, d = None, 0
        pending[0] = (nxt, d, top, store)
        pending[1] = sp
        pending[2] = pc

    mc.run(x, on_head=check)
    expect(insns[pending[2]][1][0] == "ret", "the last VM instruction is not ret")
    return steps[0]


# ============================================================================ gate B: paths (z3)

def explore(insns, max_paths=256):
    import z3
    Z = lambda v: z3.BitVecVal(v, 64)
    RBP, IN, OUT = 0x7FFF0000, 0x10000, 0x20000

    def ext(c, v):
        if c == "s32": return z3.SignExt(32, z3.Extract(31, 0, v))
        if c == "z32": return z3.ZeroExt(32, z3.Extract(31, 0, v))
        return v

    def b01(c): return z3.If(c, Z(1), Z(0))
    ZB = {"add": lambda x, y: x + y, "sub": lambda x, y: x - y, "mul": lambda x, y: x * y, "and": lambda x, y: x & y,
          "or": lambda x, y: x | y, "xor": lambda x, y: x ^ y, "shl": lambda x, y: x << (y & 63),
          "shr": lambda x, y: z3.LShR(x, y & 63), "sar": lambda x, y: x >> (y & 63), "udiv": z3.UDiv, "urem": z3.URem,
          "sdiv": lambda x, y: x / y, "srem": z3.SRem, "eq": lambda x, y: b01(x == y), "ne": lambda x, y: b01(x != y),
          "ult": lambda x, y: b01(z3.ULT(x, y)), "ule": lambda x, y: b01(z3.ULE(x, y)), "ugt": lambda x, y: b01(z3.UGT(x, y)),
          "uge": lambda x, y: b01(z3.UGE(x, y)), "slt": lambda x, y: b01(x < y), "sle": lambda x, y: b01(x <= y),
          "sgt": lambda x, y: b01(x > y), "sge": lambda x, y: b01(x >= y)}

    def zun(name, a):
        if name == "id": return a
        if name == "not": return ~a
        if name == "neg": return -a
        if name == "lnot": return b01(a == 0)
        bits = int(name[4:]); lo = z3.Extract(bits - 1, 0, a)
        return z3.ZeroExt(64 - bits, lo) if name[0] == "z" else z3.SignExt(64 - bits, lo)

    def zmerge(old, new, w):
        return new if w == 64 else z3.Concat(z3.Extract(63, w, old), z3.Extract(w - 1, 0, new))

    def zload(mem, p, size):
        parts = [z3.Select(mem, p + i) for i in reversed(range(size))]
        return parts[0] if size == 1 else z3.Concat(*parts)

    def zstore(mem, p, v, size):
        for i in range(size): mem = z3.Store(mem, p + i, z3.Extract(8 * i + 7, 8 * i, v))
        return mem

    x = z3.BitVec("x", 64)
    mem = zstore(z3.K(z3.BitVecSort(64), z3.BitVecVal(0, 8)), Z(IN), x, 8)
    for pc, (op, sem, arg, n) in insns.items():
        if sem[0] == "param":
            for nm, off in sem[1].values():
                mem = zstore(mem, Z(RBP + off), Z(IN if nm == "in" else OUT), 8)
    paths, work = [], [(0, [], mem, [])]
    while work:
        if len(paths) >= max_paths: raise ValueError("too many paths")
        pc, stack, mem, cond = work.pop()
        seen = set()
        for _ in range(1_000_000):
            op, sem, arg, n = insns[pc]
            seen.add(pc)
            k = sem[0]
            if k == "push":
                v = Z(arg & M)
                if sem[3] < 64: v = zmerge(z3.BitVec(f"stale{pc}_{len(paths)}_{len(seen)}", 64), v, sem[3])
                stack.append(v)
            elif k == "local": stack.append(Z(RBP + sem[1] + arg))
            elif k == "param": stack.append(Z(RBP + sem[1][arg][1]))
            elif k == "load":
                p = stack.pop(); v = zload(mem, p, sem[1])
                if sem[1] < 8: v = (z3.SignExt if sem[2] else z3.ZeroExt)(64 - 8 * sem[1], v)
                stack.append(z3.simplify(zmerge(p, v, sem[3])))
            elif k == "store":
                a = stack.pop(); b = stack.pop()
                p, v = (a, b) if sem[2] == "ptr_top" else (b, a)
                mem = zstore(mem, z3.simplify(p), v, sem[1])
            elif k == "bin":
                name, order, cx, cy, w = sem[1:]
                a = stack.pop(); b = stack.pop()
                xx, yy = (a, b) if order == "ts" else (b, a)
                stack.append(z3.simplify(zmerge(b, ZB[name](ext(cx, xx), ext(cy, yy)), w)))
            elif k == "un":
                a = stack.pop(); stack.append(z3.simplify(zmerge(a, zun(sem[1], a), sem[2])))
            elif k == "jmp": pc += 1 + arg; continue
            elif k == "br":
                c = stack.pop()
                nz = z3.Extract(sem[2] - 1, 0, c) != 0
                taken = nz if sem[1] == "nz" else z3.Not(nz)
                outs = []
                for t, tgt in ((taken, pc + 1 + arg), (z3.Not(taken), pc + n)):
                    t = z3.simplify(t)
                    if z3.is_true(t): outs = [(tgt, cond)]; break
                    if z3.is_false(t): continue
                    s = z3.Solver(); s.add(*cond, t)
                    if s.check() == z3.sat: outs.append((tgt, cond + [t]))
                expect(outs, "a branch with no feasible successor")
                for tgt, cnd in outs[1:]: work.append((tgt, list(stack), mem, cnd))
                pc, cond = outs[0]
                continue
            elif k == "ret":
                s = z3.Solver(); s.add(*cond)
                expect(s.check() == z3.sat, "infeasible path")
                paths.append(dict(input=s.model().eval(x, model_completion=True).as_long(), pcs=seen, branches=len(cond)))
                break
            pc += n
        else:
            raise ValueError("path too long")
    return paths


# ============================================================================ lifting to C

def block_ir(insns):
    """{leader: (stores, terminator)}; values are trees.  The stack must be empty at block ends and stores."""
    leaders = {0}
    for pc, (op, sem, arg, n) in insns.items():
        if sem[0] in ("jmp", "br"): leaders |= {pc + 1 + arg, pc + n}
    out = {}
    for lead in sorted(l for l in leaders if l in insns):
        pc, stack, stmts = lead, [], []
        while True:
            op, sem, arg, n = insns[pc]
            k = sem[0]
            if k == "push": stack.append(("c", arg & M) if sem[3] == 64 else ("merge", ("stale",), ("c", arg & M), sem[3]))
            elif k == "local": stack.append(("laddr", sem[1] + arg))
            elif k == "param": stack.append(("paddr", sem[1][arg][0]))
            elif k == "load": p = stack.pop(); stack.append(("merge", p, ("load", sem[1], sem[2], p), sem[3]))
            elif k == "store":
                a = stack.pop(); b = stack.pop()
                ptr, val = (a, b) if sem[2] == "ptr_top" else (b, a)
                expect(not stack, f"values left on the VM stack across a store at pc {pc}")
                stmts.append(("store", sem[1], ptr, val))
            elif k == "bin":
                name, order, cx, cy, w = sem[1:]
                a = stack.pop(); b = stack.pop()
                x, y = (a, b) if order == "ts" else (b, a)
                stack.append(("merge", b, (name, (cx, x) if cx else x, (cy, y) if cy else y), w))
            elif k == "un": a = stack.pop(); stack.append(("merge", a, (sem[1], a), sem[2]))
            elif k == "jmp":
                expect(not stack, f"stack not empty at pc {pc}"); out[lead] = (stmts, ("goto", pc + 1 + arg)); break
            elif k == "br":
                c = stack.pop(); expect(not stack, f"stack not empty at pc {pc}")
                out[lead] = (stmts, ("br", c, sem[1], sem[2], pc + 1 + arg, pc + n)); break
            elif k == "ret": out[lead] = (stmts, ("ret",)); break
            pc += n
            if pc in leaders:
                expect(not stack, f"stack not empty at pc {pc}"); out[lead] = (stmts, ("goto", pc)); break
    return out


LOWBITS = {"add", "sub", "mul", "and", "or", "xor", "not", "neg"}     # low result bits need only low operand bits
CMP = {"eq", "ne", "ult", "ule", "ugt", "uge", "slt", "sle", "sgt", "sge", "lnot"}


def simp(e, d=64):
    """Simplify e, of which only the low d bits are used."""
    t = e[0]
    if t == "c": return ("c", e[1] & ((1 << d) - 1)) if d < 64 else e
    if t in ("laddr", "paddr", "stale"): return e
    if t == "merge":
        if e[3] >= d: return simp(e[2], d)
        return ("merge", simp(e[1]), simp(e[2], e[3]), e[3])
    if t == "load": return ("load", e[1], e[2], simp(e[3]))
    if t in ("s32", "z32"):
        a = simp(e[1], 32)
        if a[0] == "c": return ("c", sx(a[1], 32) if t == "s32" else a[1] & 0xFFFFFFFF)
        return (t, a)
    if t == "id": return simp(e[1], d)
    if t.startswith(("zext", "sext")):
        bits = int(t[4:]); a = simp(e[1], bits)
        if a[0] == "c": return ("c", UN[t](a[1]))
        return a if bits >= d else (t, a)
    if t in ("not", "neg", "lnot"):
        a = simp(e[1], d if t != "lnot" else 64)
        return ("c", UN[t](a[1])) if a[0] == "c" else (t, a)
    x = simp(e[1], d if t in LOWBITS or t == "shl" else 64)
    y = simp(e[2], d if t in LOWBITS else 64)
    if x[0] == "c" and y[0] == "c":
        r = BIN[t](x[1], y[1])
        if r is not None: return ("c", r & ((1 << d) - 1) if d < 64 else r)
    if t in ("add", "or", "xor"):
        if x == ("c", 0): return y
        if y == ("c", 0): return x
    if t == "mul":
        if ("c", 0) in (x, y): return ("c", 0)
        if x == ("c", 1): return y
        if y == ("c", 1): return x
    return (t, x, y)


def norm32(e):
    """Under an (int) cast only the low 32 bits matter: write constants as signed 32-bit values."""
    if e[0] == "c": return ("c", sx(e[1], 32))
    if e[0] in ("add", "sub", "mul"): return (e[0], norm32(e[1]), norm32(e[2]))
    return e


def split_addr(a):
    """Address tree -> (base, byte offset, [(index, scale)]); base ('L', rbp offset) or ('P', 'in'/'out')."""
    terms = []
    def flat(e):
        if e[0] == "add": flat(e[1]); flat(e[2])
        elif e[0] == "s32" and e[1][0] == "add": flat(("s32", norm32(e[1][1]))); flat(("s32", norm32(e[1][2])))
        elif e[0] == "s32": terms.append(("s32", norm32(e[1])))
        else: terms.append(e)
    flat(a)
    base, off, idx = None, 0, []
    for t in terms:
        u = t[1] if t[0] == "s32" else t
        if u[0] == "laddr" and base is None: base = ("L", u[1])
        elif u[0] == "load" and u[1] == 8 and u[3][0] == "paddr" and base is None: base = ("P", u[3][1])
        elif u[0] == "c": off += s64(u[1])
        elif u[0] == "mul" and u[2][0] == "c": idx.append((u[1], s64(u[2][1])))
        elif u[0] == "mul" and u[1][0] == "c": idx.append((u[2], s64(u[1][1])))
        else: idx.append((u, 1))
    return (base, off, idx) if base else None


CB = {"add": "+", "sub": "-", "mul": "*", "and": "&", "or": "|", "xor": "^", "udiv": "/", "urem": "%",
      "eq": "==", "ne": "!=", "ult": "<", "ule": "<=", "ugt": ">", "uge": ">="}
CSIGNED = {"slt": "<", "sle": "<=", "sgt": ">", "sge": ">=", "sdiv": "/", "srem": "%"}
CTYPE = {8: "unsigned long", 4: "unsigned int", 2: "unsigned short", 1: "unsigned char"}
STYPE = {32: "int", 16: "short", 8: "signed char"}


class Lifter:
    def __init__(self, insns, alias_narrow=True):
        self.alias_narrow = alias_narrow          # tests turn this off to show why it is needed
        raw = block_ir(insns)
        self.blocks = {}
        for b, (st, term) in raw.items():
            st = [("store", s[1], simp(s[2]), simp(s[3], 8 * s[1])) for s in st]
            if term[0] == "br": term = ("br", simp(term[1], term[3])) + term[2:]
            self.blocks[b] = (st, term)
        self.acc = {}
        for st, term in self.blocks.values():
            for s in st:
                self._note(s[2], s[1]); self._walk(s[2]); self._walk(s[3])
            if term[0] == "br": self._walk(term[1])
        self.arrays = {b for b, a in self.acc.items() if any(ix for _, _, ix in a)}
        for b, a in self.acc.items():
            offs = sorted({o for o, s, ix in a if s == 8})
            if len(offs) > 2 and min(offs) == 0 and all((q - p) % 8 == 0 for p, q in zip(offs, offs[1:])):
                self.arrays.add(b)
        self.slots8 = sorted({b[1] + o for b, a in self.acc.items() if b not in self.arrays for o, s, ix in a if s == 8})
        self.names = {}

    def _note(self, ptr, size):
        s = split_addr(ptr)
        if s and s[0][0] == "L": self.acc.setdefault(s[0], []).append((s[1], size, bool(s[2])))

    def _walk(self, e):
        if e[0] == "load": self._note(e[3], e[1])
        for x in e[1:]:
            if isinstance(x, tuple): self._walk(x)

    # ---- names
    def index(self, off, idx):
        parts = []
        for e, scale in idx:
            expect(scale == 8, f"index scale {scale}")
            parts.append(self.e(e))
        expect(off % 8 == 0, "unaligned element offset")
        if off or not parts: parts.append(str(off // 8))
        return " + ".join(parts)

    def lvalue(self, ptr, size):
        s = split_addr(ptr)
        if not s: return f"*({CTYPE[size]} *){self.e(ptr)}"
        (kind, b), off, idx = s
        if kind == "P":
            expect(size == 8, "narrow access to input/output")
            return f"{'input' if b == 'in' else 'output'}[{self.index(off, idx)}]"
        if (kind, b) in self.arrays:
            if size == 8: return f"a{-b}[{self.index(off, idx)}]"
            if not self.alias_narrow and not idx:                       # the wrong rendering, kept for a test
                self.names[(b + off, size)] = f"v{-(b + off)}_{8 * size}"
                return self.names[(b + off, size)]
            el, k = off // 8 * 8, off % 8
            expect(k % size == 0, "misaligned narrow access")
            return f"*(({CTYPE[size]} *)&a{-b}[{self.index(el, idx)}] + {k // size})"
        expect(not idx, "computed index into a scalar")
        a = b + off
        if size == 8:
            self.names[(a, 8)] = f"v{-a}"
            return f"v{-a}"
        if self.alias_narrow:
            for S in self.slots8:
                if S <= a < S + 8:
                    expect((a - S) % size == 0, "misaligned narrow access")
                    self.names[(S, 8)] = f"v{-S}"
                    return f"*(({CTYPE[size]} *)&v{-S} + {(a - S) // size})"
        self.names[(a, size)] = f"v{-a}_{8 * size}"
        return self.names[(a, size)]

    # ---- expressions
    def e(self, x):
        t = x[0]
        if t == "c": return f"{x[1]}UL" if x[1] < 10 else f"0x{x[1]:x}UL"
        if t == "stale": raise ValueError("the program uses stale VM-stack bits above a narrow push")
        if t == "merge":
            m = (1 << x[3]) - 1
            return f"(({self.e(x[1])} & 0x{~m & M:x}UL) | ({self.e(x[2])} & 0x{m:x}UL))"
        if t == "load":
            v = self.lvalue(x[3], x[1])
            return f"(unsigned long)({STYPE[8 * x[1]]}){v}" if x[2] else v
        if t == "laddr": return f"(unsigned long)&frame[{x[1]}]"
        if t == "paddr": return f"(unsigned long)&{x[1]}"
        if t == "s32": return f"(unsigned long)(int){self.e(x[1])}"
        if t == "z32": return f"(unsigned int){self.e(x[1])}"
        if t.startswith("zext"): return f"({CTYPE[int(t[4:]) // 8]}){self.e(x[1])}"
        if t.startswith("sext"): return f"(unsigned long)({STYPE[int(t[4:])]}){self.e(x[1])}"
        if t == "not": return f"~{self.e(x[1])}"
        if t == "neg": return f"-{self.e(x[1])}"
        if t == "lnot": return f"!{self.e(x[1])}"
        if t == "add" and x[2][0] == "c" and x[2][1] >> 63:
            return f"({self.e(x[1])} - {self.e(('c', -x[2][1] & M))})"
        a, b = self.e(x[1]), self.e(x[2])
        if t in CB: return f"({a} {CB[t]} {b})"
        if t in CSIGNED: return f"(unsigned long)((long){a} {CSIGNED[t]} (long){b})"
        sh = str(x[2][1] & 63) if x[2][0] == "c" else f"({b} & 63)"
        if t == "shl": return f"({a} << {sh})"
        if t == "shr": return f"({a} >> {sh})"
        if t == "sar": return f"(unsigned long)((long){a} >> {sh})"
        raise KeyError(t)

    def cond(self, term, negate=False):
        _, c, sense, w, tk, fl = term
        s = self.e(c)
        if w < 64 and c[0] not in CMP: s = f"({STYPE[w]}){s}"
        if s.startswith("(") and s.endswith(")") and s.count("(") == 1: s = s[1:-1]
        return s if (sense == "nz") != negate else f"!({s})"

    # ---- control flow
    def emit(self):
        blocks = self.blocks
        succ = {b: [] if t[0] == "ret" else [t[1]] if t[0] == "goto" else [t[4], t[5]] for b, (s, t) in blocks.items()}
        EXIT = -1
        nodes = list(blocks) + [EXIT]
        pdom = {n: set(nodes) for n in nodes}; pdom[EXIT] = {EXIT}
        changed = True
        while changed:
            changed = False
            for n in blocks:
                new = {n} | set.intersection(*(pdom[s] for s in (succ[n] or [EXIT])))
                if new != pdom[n]: pdom[n] = new; changed = True
        def ipdom(n):
            c = pdom[n] - {n}
            return next(x for x in c if all(y == x or y in pdom[x] for y in c))
        preds = {}
        for b, ss in succ.items():
            for s in ss: preds.setdefault(s, []).append(b)
        headers = {s for b, ss in succ.items() for s in ss if s <= b}
        lines = []

        def stmts(b, ind):
            for s in blocks[b][0]:
                lines.append(f"{ind}{self.lvalue(s[2], s[1])} = {self.e(s[3])};")

        def region(b, stop, ind, loop=None):
            while b not in (stop, EXIT):
                if loop and b == loop[1]: lines.append(ind + "break;"); return
                if loop and b == loop[0]: return                       # back to the header: continue
                if b in headers and not (loop and b == loop[0]):
                    b = while_loop(b, ind); continue
                stmts(b, ind)
                term = blocks[b][1]
                if term[0] == "ret": lines.append(ind + "return;"); return
                if term[0] == "goto": b = term[1]; continue
                _, c, sense, w, tk, fl = term
                if loop and tk == loop[1]: lines.append(f"{ind}if ({self.cond(term)}) break;"); b = fl; continue
                if loop and fl == loop[1]: lines.append(f"{ind}if ({self.cond(term, True)}) break;"); b = tk; continue
                j = ipdom(b)
                lines.append(f"{ind}if ({self.cond(term)}) {{")
                region(tk, j, ind + "    ", loop)
                if fl != j:
                    mark = len(lines)
                    lines.append(ind + "} else {")
                    region(fl, j, ind + "    ", loop)
                    if len(lines) == mark + 1: del lines[mark]           # the else part was only a jump
                lines.append(ind + "}")
                b = j

        def while_loop(h, ind):
            body, work = {h}, [b for b, ss in succ.items() if h in ss and b >= h]
            while work:
                n = work.pop()
                if n not in body: body.add(n); work.extend(preds.get(n, []))
            exits = {s for b in body for s in succ[b] if s not in body}
            expect(len(exits) == 1, f"loop at {h} has {len(exits)} exits")
            ex = exits.pop()
            st, term = blocks[h]
            expect(term[0] == "br" and ex in term[4:], f"loop at {h} does not test at the top")
            start = len(lines)
            lines.append(ind + "while (1) {")
            stmts(h, ind + "    ")
            inner = ind + "    "
            if not st:                                                   # while (cond) { body }
                cnd = self.cond(term, negate=(term[4] == ex))
                lines[start] = f"{ind}while ({cnd}) {{"
            else:
                lines.append(f"{inner}if ({self.cond(term, negate=(term[5] == ex))}) break;")
            region(term[5] if term[4] == ex else term[4], h, inner, (h, ex))
            lines.append(ind + "}")
            return ex

        region(0, EXIT, "    ")
        return lines

    def source(self):
        body = self.emit()
        decl = []
        for b in sorted(self.arrays):
            n = max(o for o, s, ix in self.acc[b]) // 8 + 1
            if any(ix for _, _, ix in self.acc[b]):          # indexed: up to the next variable in the frame
                above = [c[1] + o for c, a in self.acc.items() if c[1] > b[1] for o, s, ix in a]
                if above: n = max(n, (min(above) - b[1]) // 8)
            decl.append(f"    unsigned long a{-b[1]}[{n}];")
        for (off, size), name in sorted(self.names.items(), key=lambda kv: kv[1]):
            decl.append(f"    {CTYPE[size]} {name};")
        return "\n".join(["void SECRET(unsigned long input[1], unsigned long output[1])", "{"] + decl + [""] + body + ["}"]) + "\n"


# ============================================================================ gate C: compile and compare

HARNESS = r"""
#include <stdio.h>
void SECRET(unsigned long long input[1], unsigned long long output[1]);
int main(void) {
    unsigned long long x;
    while (scanf("%llx", &x) == 1) {
        unsigned long long in[1] = {x}, out[1] = {0};
        SECRET(in, out);
        printf("%llx\n", out[0]);
    }
    return 0;
}
"""
WINLIBS = Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft/WinGet/Packages/BrechtSanders.WinLibs.POSIX.UCRT_Microsoft.Winget.Source_8wekyb3d8bbwe/mingw64/bin/gcc.exe"


def compiler():
    for c in (os.environ.get("CC"), shutil.which("gcc"), shutil.which("cc"), str(WINLIBS) if WINLIBS.exists() else None):
        if c: return c
    return None


def for_host(src):
    """The recovered source is LP64 C (Linux).  For a Windows (LLP64) build make long 64-bit."""
    if os.name != "nt": return src
    src = re.sub(r"\bunsigned long\b", "unsigned long long", src)
    src = re.sub(r"\(long\)", "(long long)", src)
    return re.sub(r"\b(0x[0-9a-f]+|\d+)UL\b", r"\1ULL", src)


def build(src, name):
    cc = compiler()
    if not cc: raise RuntimeError("no C compiler (set CC)")
    GENERATED.mkdir(exist_ok=True)
    c = GENERATED / f"{name}.host.c"; h = GENERATED / "harness.c"; exe = GENERATED / f"{name}.exe"
    c.write_text(for_host(src)); h.write_text(HARNESS)
    env = dict(os.environ, PATH=str(Path(cc).parent) + os.pathsep + os.environ.get("PATH", ""))
    subprocess.run([cc, "-O1", "-fno-strict-aliasing", "-o", str(exe), str(c), str(h)], check=True, env=env)
    return exe


def test_inputs(n, seed=1):
    rng = random.Random(seed)
    xs = [0, 1, 2, 3, 0xFF, 0x100, 0xFFFF, 2**31 - 1, 2**31, 2**32 - 1, 2**32, 2**63 - 1, 2**63, M]
    xs += [1 << i for i in range(64)]
    while len(xs) < n:
        xs.append(rng.getrandbits(64) if rng.random() < .8 else rng.getrandbits(rng.randrange(1, 64)))
    return xs


def compare(mc, exe, xs):
    p = subprocess.run([str(exe)], input="".join(f"{x:x}\n" for x in xs), capture_output=True, text=True, check=True)
    got = [int(l, 16) for l in p.stdout.split()]
    expect(len(got) == len(xs), "the compiled program printed too few lines")
    bad = []
    for x, g in zip(xs, got):
        o = mc.run(x)
        if o != g: bad.append((x, o, g))
    return bad


# ============================================================================ main

def devirtualize(k, n_random=2000, lockstep_random=20):
    mc = Machine(binary(k))
    isa, insns = decode(mc)
    paths = explore(insns)
    covered = set().union(*(p["pcs"] for p in paths))
    if covered != set(insns):
        raise ValueError(f"paths cover {len(covered)}/{len(insns)} instructions")
    xs_lock = [p["input"] for p in paths] + test_inputs(lockstep_random, seed=k + 100)
    steps = sum(lockstep(mc, insns, x) for x in xs_lock)
    src = Lifter(insns).source()
    res = dict(k=k, layout=mc.L, isa=isa, insns=insns, paths=paths, lock_inputs=len(xs_lock), lock_steps=steps, source=src)
    if compiler():
        xs = test_inputs(n_random) + [p["input"] for p in paths]
        bad = compare(mc, build(src, f"challenge-{k}"), xs)
        if bad:
            raise ValueError(f"challenge-{k}: recovered C differs on {len(bad)}/{len(xs)} inputs, e.g. "
                             f"x={bad[0][0]:#x} original {bad[0][1]:#x} recovered {bad[0][2]:#x}")
        res["compared"] = len(xs)
    return res


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("programs", nargs="*", type=int, default=list(BINARIES))
    ap.add_argument("--random", type=int, default=2000)
    a = ap.parse_args()
    fetch()
    GENERATED.mkdir(exist_ok=True)
    report = []
    for k in a.programs:
        r = devirtualize(k, a.random)
        (GENERATED / f"challenge-{k}.c").write_text(r["source"])
        kinds = sorted({s[0] for s in r["isa"].values()})
        line = (f"challenge-{k}: SECRET {r['layout']['secret']:#x}, head {r['layout']['head']:#x}, "
                f"{len(r['isa'])} opcodes ({', '.join(kinds)}), {len(r['insns'])} VM instructions, "
                f"{len(r['paths'])} paths, lockstep {r['lock_steps']} steps on {r['lock_inputs']} inputs, "
                + (f"C == original on {r['compared']} inputs" if "compared" in r else "C NOT compiled (no compiler)"))
        print(line)
        report.append(line)
    (GENERATED / "report.txt").write_text("\n".join(report) + "\n")
    if not compiler():
        print("gate C skipped: no C compiler (set CC)")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
