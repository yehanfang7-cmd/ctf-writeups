"""Unit 05: devirtualise Flare-On 5 #12 "suspicious_floppy" layer by layer and check every layer.

    x86 INT 13h hook (TMP.DAT)  ->  Subleq interpreter  ->  RSSB interpreter written in Subleq  ->  password check

Each layer is replaced by a model of the layer above it, and each replacement is checked against the
layer below it:

    gate 1  x86 == Subleq     Unicorn runs the real 16-bit code; the final 64 KiB segment, the printed text
                              and the return value must equal the Subleq interpreter's (vm.c).
    gate 2  Subleq == RSSB    lockstep: an independent RSSB model, started from the pristine image, must
                              match the whole RSSB region of Subleq memory after every RSSB instruction.
    gate 3  RSSB == lifted    the per-pair values the RSSB program computes, and its verdict, must equal the
                              lifted formula on random and edge-case passwords.
    gate 4  solve             an exhaustive search of the lifted formula; every solution is run on x86.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import random
import shutil
import struct
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
IMAGE = HERE.parent.parent / "FlareOn" / "Fo5" / "12" / "suspicious_floppy_v1.0.img"
IMAGE_SHA256 = "cf6954385203aa02c4b1c1558b7a5613279c204606f6dff50e614da310abf98b"
TMP_SHA256 = "b9917d86002ba58f10883d11ca35827f93ac293b56f4b469557c6c987e8cd423"
GENERATED = HERE / "generated"

# Found by analysis (see writeup); every gate below fails if one of them is wrong.
RSSB_BASE = 0x7F6      # RSSB cell k is Subleq word RSSB_BASE + k
RSSB_HEAD = 0x42A      # Subleq pc reached once per RSSB instruction
RSSB_IP0 = 0x15C       # RSSB ip after the Subleq start-up code
TABLE = 0xA79          # 15 target words, one per character pair
PROBE_Y = 0x1FFA       # RSSB ip that writes y_i = (x_i ^ 33*i) + G
PAIRS = 15
PRINTABLE = range(0x20, 0x7F)


def expect(cond, what):
    if not cond:
        raise ValueError(what)


# ---------------------------------------------------------------- floppy image and resident code

def fat12_files(image: bytes) -> dict[str, bytes]:
    bps, spc, reserved, fats, roots = struct.unpack_from("<HBHBH", image, 11)
    spf = struct.unpack_from("<H", image, 22)[0]
    fat = image[reserved * bps:(reserved + spf) * bps]
    root = (reserved + fats * spf) * bps
    data = root + roots * 32
    files = {}
    for i in range(roots):
        e = image[root + 32 * i:root + 32 * i + 32]
        if e[0] == 0:
            break
        if e[0] == 0xE5 or e[11] & 0x18:
            continue
        name = (e[:8].rstrip() + b"." + e[8:11].rstrip()).decode().strip(".")
        cluster, size = struct.unpack_from("<H", e, 26)[0], struct.unpack_from("<I", e, 28)[0]
        body = bytearray()
        while 2 <= cluster < 0xFF8:
            off = data + (cluster - 2) * spc * bps
            body += image[off:off + spc * bps]
            v = struct.unpack_from("<H", fat, cluster * 3 // 2)[0]
            cluster = v >> 4 if cluster & 1 else v & 0xFFF
        files[name] = bytes(body[:size])
    return files


@dataclass(frozen=True)
class Resident:
    code: bytes     # what TMP.DAT copies to the top of conventional memory (offset 0 = segment start)
    check: int      # near routine run when MESSAGE.DAT is read
    mem0: int       # Subleq word 0
    words: int      # Subleq memory size in words
    pc0: int        # Subleq entry pc
    pwdst: int      # where the password is spread, one byte per word
    maxlen: int     # at most this many bytes are copied
    result: int     # Subleq word returned in ax


def parse_resident(tmp: bytes) -> Resident:
    """Read every constant from the x86 instructions themselves."""
    expect(tmp[0x19:0x1C] == b"\xbe\x43\x08", "installer: mov si, 0x843")
    expect(tmp[0x1E] == 0xB9, "installer: mov cx, length")
    code = tmp[0x43:0x43 + struct.unpack_from("<H", tmp, 0x1F)[0]]
    u16 = lambda off: struct.unpack_from("<H", code, off)[0]
    expect(code[0x1E8:0x1EC] == b"\xe8\x00\x00\x58", "check: call $+3; pop ax")
    anchor = 0x1EB
    expect(code[0x1EF] == 0x05, "check: add ax, imm16 (password words)")
    expect(code[0x215:0x217] == b"\x83\xf8", "check: cmp ax, maxlen")
    expect(code[0x220] == 0xE8, "check: call interpreter")
    mem0 = 0x223
    entry = (mem0 + struct.unpack_from("<h", code, 0x221)[0]) & 0xFFFF
    expect(code[entry:entry + 2] == b"\x58\x6a" and code[entry + 3] == 0x68, "interpreter args: pop ax; push pc; push words")
    expect(code[entry + 0x11:entry + 0x13] == b"\x81\xc3", "result: add bx, imm16")
    result_addr = anchor + u16(entry + 0x13)
    return Resident(code=code, check=0x1DA, mem0=mem0, words=u16(entry + 4), pc0=code[entry + 2],
                    pwdst=anchor + u16(0x1F0), maxlen=code[0x217], result=(result_addr - mem0) // 2)


def load_inputs(image_path: Path = IMAGE) -> tuple[bytes, Resident]:
    image = image_path.read_bytes()
    expect(hashlib.sha256(image).hexdigest() == IMAGE_SHA256, f"{image_path} is not the challenge image")
    tmp = fat12_files(image)["TMP.DAT"]
    expect(hashlib.sha256(tmp).hexdigest() == TMP_SHA256, "TMP.DAT hash differs")
    return tmp, parse_resident(tmp)


# ---------------------------------------------------------------- layer 0: real x86 (Unicorn)

def x86_check(r: Resident, password: bytes) -> tuple[int, bytes, bytes]:
    """Run routine 0x1da on the real code. Returns (ax, printed text, final segment)."""
    from unicorn import UC_ARCH_X86, UC_HOOK_INTR, UC_MODE_16, Uc
    from unicorn.x86_const import (UC_X86_REG_AX, UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_ES,
                                   UC_X86_REG_IP, UC_X86_REG_SP, UC_X86_REG_SS)
    seg, stack = 0x9000, 0x7000                 # the caller's stack is not in the resident segment
    stop = len(r.code)                          # near return lands on a hlt just after the code
    uc = Uc(UC_ARCH_X86, UC_MODE_16)
    uc.mem_map(0, 0x100000)
    uc.mem_write(seg * 16, r.code)
    uc.mem_write(seg * 16 + BUFFER, (password + b"\0").ljust(0x40, b"\0")[:0x40])  # filled by the write hook
    uc.mem_write(seg * 16 + stop, b"\xf4")
    for reg in (UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_ES):
        uc.reg_write(reg, seg)
    uc.reg_write(UC_X86_REG_SS, stack)
    uc.reg_write(UC_X86_REG_SP, 0xFFFE)
    uc.mem_write(stack * 16 + 0xFFFE, stop.to_bytes(2, "little"))
    printed = bytearray()

    def interrupt(u, number, _):
        ax = u.reg_read(UC_X86_REG_AX)
        expect(number == 0x10 and ax >> 8 == 0x0E, f"unexpected int {number:#x} ax={ax:#x}")
        printed.append(ax & 0xFF)

    uc.hook_add(UC_HOOK_INTR, interrupt)
    uc.emu_start(r.check, seg * 16 + stop)      # 'until' is a linear address in real mode
    expect(uc.reg_read(UC_X86_REG_IP) == stop, "x86 check did not return")
    return uc.reg_read(UC_X86_REG_AX), bytes(printed), resident_area(bytes(uc.mem_read(seg * 16, 0x10000)))


BUFFER = 0x5E70     # cs:0x5e70, where the INT 13h write hook keeps the password (x86 side only)


def resident_area(segment: bytes) -> bytes:
    """The whole resident segment except the password buffer and the hlt placed after the code."""
    return segment[:BUFFER] + segment[BUFFER + 0x41:]


# ---------------------------------------------------------------- layer 1: Subleq

class Subleq:
    """Readable reference for the interpreter at 0x5dd9 (vm.c is the same thing, fast)."""

    def __init__(self, r: Resident, password: bytes):
        self.r = r
        self.seg = bytearray(0x10000)
        self.seg[:len(r.code)] = r.code
        for i in range(r.maxlen):                      # routine 0x1da
            ch = password[i] if i < len(password) else 0
            struct.pack_into("<H", self.seg, r.pwdst + 2 * i, ch)
            if ch == 0:
                break
        self.pc, self.printed = r.pc0, bytearray()

    def rd(self, i):
        o = (self.r.mem0 + 2 * i) & 0xFFFF
        return self.seg[o] | self.seg[(o + 1) & 0xFFFF] << 8

    def wr(self, i, v):
        o = (self.r.mem0 + 2 * i) & 0xFFFF
        self.seg[o], self.seg[(o + 1) & 0xFFFF] = v & 0xFF, v >> 8

    def step(self) -> bool:
        if self.pc + 3 > self.r.words:
            return False
        a, b, c = self.rd(self.pc), self.rd(self.pc + 1), self.rd(self.pc + 2)
        v = (self.rd(b) - self.rd(a)) & 0xFFFF
        self.wr(b, v)
        if c != 0 and (v == 0 or v & 0x8000):
            if c == 0xFFFF:
                return False
            self.pc = c
        else:
            self.pc += 3
        if self.rd(4):
            self.printed.append(self.rd(2) & 0xFF)
            self.wr(4, 0)
            self.wr(2, 0)
        return True


def build_vm() -> Path:
    exe = GENERATED / ("vm.exe" if os.name == "nt" else "vm")
    src = HERE / "vm.c"
    if exe.exists() and exe.stat().st_mtime >= src.stat().st_mtime:
        return exe
    cc = os.environ.get("CC") or shutil.which("gcc") or shutil.which("cc") or shutil.which("g++")
    expect(cc, "no C compiler on PATH (set CC)")
    GENERATED.mkdir(exist_ok=True)
    subprocess.run([cc, "-O2", "-o", str(exe), str(src)], check=True)
    return exe


def _resident_file(r: Resident) -> Path:
    GENERATED.mkdir(exist_ok=True)
    path = GENERATED / "resident.bin"
    if not path.exists() or path.read_bytes() != r.code:
        path.write_bytes(r.code)
    return path


def _args(r: Resident, password: bytes):
    return [f"{r.mem0:x}", f"{r.words:x}", f"{r.pc0:x}", f"{r.pwdst:x}", f"{r.maxlen:x}", password.hex() or "00"]


def subleq_fast(r: Resident, password: bytes, max_steps: int | None = None) -> dict:
    out = GENERATED / "subleq_seg.bin"
    cmd = [str(build_vm()), "run", str(_resident_file(r)), str(out)] + _args(r, password)
    if max_steps is not None:
        cmd.append(str(max_steps))
    res = dict(l.split(" ", 1) for l in subprocess.run(cmd, check=True, capture_output=True, text=True).stdout.splitlines())
    seg = out.read_bytes()
    word = lambda i: struct.unpack_from("<H", seg, (r.mem0 + 2 * i) & 0xFFFF)[0]
    return {"steps": int(res["steps"]), "pc": int(res["pc"], 16), "printed": bytes.fromhex(res["out"]),
            "segment": seg, "result": word(r.result)}


def lockstep(r: Resident, password: bytes) -> dict:
    cmd = [str(build_vm()), "lockstep", str(_resident_file(r))] + _args(r, password) + \
          [f"{RSSB_HEAD:x}", f"{RSSB_BASE:x}", f"{RSSB_IP0:x}"]
    p = subprocess.run(cmd, capture_output=True, text=True)
    lines = dict(l.split(" ", 1) for l in p.stdout.splitlines() if " " in l)
    if p.returncode != 0:
        raise ValueError(f"lockstep failed: {p.stdout.strip()}")
    return {"subleq": int(lines["subleq"]), "rssb": int(lines["rssb"]), "printed": bytes.fromhex(lines["out"])}


# ---------------------------------------------------------------- layer 2: RSSB

def rssb_image(r: Resident) -> list[int]:
    s = Subleq(r, b"")
    return [s.rd(RSSB_BASE + k) for k in range(r.words - RSSB_BASE)]


class Rssb:
    """acc = m[x] - acc; m[x] = acc; skip the next word if the result is negative.
    m[0] = ip, m[1] = acc, m[2] = constant 0, m[4]/m[6] = output char/strobe, x = -1 no-op, x = -2 halt."""

    def __init__(self, image: list[int], r: Resident, password: bytes, *, zero_register=True, output_rule=True):
        self.m = image[:] + [0] * (0x10000 - len(image))
        self.m[0] = RSSB_IP0
        self.pw_cell = (r.pwdst - r.mem0) // 2 - RSSB_BASE
        self.result_cell = r.result - RSSB_BASE
        for i in range(r.maxlen):
            ch = password[i] if i < len(password) else 0
            self.m[self.pw_cell + i] = ch
            if ch == 0:
                break
        self.zero_register, self.output_rule = zero_register, output_rule
        self.printed = bytearray()

    def step(self) -> bool:
        m = self.m
        ip = m[0]
        x = m[ip]
        if x == 0xFFFE:
            return False
        if x == 0xFFFF:
            m[0] = (ip + 1) & 0xFFFF
            return True
        v = (m[x] - m[1]) & 0xFFFF
        if x != 2 or not self.zero_register:
            m[x] = v
        m[1] = v
        m[0] = (m[0] + 1 + (v >> 15)) & 0xFFFF
        if self.output_rule and m[6]:
            self.printed.append(m[4] & 0xFF)
            m[4] = m[6] = 0
        return True

    def run(self, probe: int | None = None) -> list[int]:
        seen = []
        while True:
            ip = self.m[0]
            if not self.step():
                return seen
            if ip == probe:
                seen.append(self.m[1])

    @property
    def result(self) -> int:
        return self.m[self.result_cell]


def lockstep_python(r: Resident, password: bytes, rssb_steps: int, **rules) -> int:
    """Slow lockstep for a prefix; used to show that a wrong RSSB rule is caught."""
    sub, model = Subleq(r, password), Rssb(rssb_image(r), r, password, **rules)
    n, started = 0, False
    while n < rssb_steps:
        if sub.pc == RSSB_HEAD:
            if started:
                model.step()
                n += 1
            started = True
            for k in range(r.words - RSSB_BASE):
                if model.m[k] != sub.rd(RSSB_BASE + k):
                    raise ValueError(f"RSSB model differs after {n} steps at cell {k:#x}")
        if not sub.step():
            break
    return n


# ---------------------------------------------------------------- layer 3: the lifted check

def table(image: list[int]) -> list[int]:
    return image[TABLE:TABLE + PAIRS]


def cells(r: Resident, password: bytes) -> list[int]:
    """The 32 password words as the RSSB program sees them (the copy stops after the NUL)."""
    pw = password[:r.maxlen]
    if 0 in pw:
        pw = pw[:pw.index(0)]
    return list(pw) + [0] * (r.maxlen - len(pw))


def at_weight(p: int) -> int:
    """K(p) = (p << 11) + (p << 10), as the program computes it.  Its 'move' macro is
    acc = -src; skip-if-negative; dst -= acc, and -0x8000 == 0x8000 is negative, so moving 0x8000 is
    skipped and the destination keeps 0.  That happens for p << 11 == 0x8000, i.e. p = 16."""
    double = (p << 11) & 0xFFFF
    return ((0 if double == 0x8000 else double) + (p << 10)) & 0xFFFF


def lifted(c: list[int], targets: list[int]) -> tuple[int, list[int]]:
    """Returns (verdict, y values). No '@' -> rejected before the loop."""
    if 0x40 not in c:
        return 0, []
    p = c.index(0x40)
    g = (at_weight(p) + sum(c[:p])) & 0xFFFF
    ys = []
    for i in range(PAIRS):
        x = ((c[2 * i + 1] - 32) * 128 + (c[2 * i] - 32)) & 0xFFFF
        ys.append(((x ^ (33 * i)) + g) & 0xFFFF)
    return int(ys == targets), ys


def boundary_cases(r: Resident, count: int, rng: random.Random) -> list[bytes]:
    """Passwords where some y_i is 0x7fff, 0x8000 or 0x8001, the values the 0x8000 move bug could hit."""
    out = []
    alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-!"
    while len(out) < count:
        n = rng.randint(18, r.maxlen)
        pw = bytearray(rng.choice(alphabet) for _ in range(n))
        p = rng.randrange(min(n, 2 * PAIRS))
        pw[p] = 0x40
        g = (at_weight(p) + sum(pw[:p])) & 0xFFFF
        want = (0x7FFF, 0x8000, 0x8001)[len(out) % 3]
        for i in rng.sample(range(PAIRS), PAIRS):
            if 2 * i <= p or 2 * i + 1 >= n:            # keep '@' and every character before it
                continue
            x = ((want - g) & 0xFFFF) ^ (33 * i)
            lo, hi = x & 0x7F, x >> 7
            if lo <= 0x7E - 32 and hi <= 0x7E - 32 and 0x40 not in (lo + 32, hi + 32):
                pw[2 * i], pw[2 * i + 1] = lo + 32, hi + 32
                out.append(bytes(pw))
                break
    return out


def solve(targets: list[int], maxlen: int) -> list[bytes]:
    """Every printable password of 1..maxlen bytes that the lifted check accepts, as patterns:
    '?' stands for a character the check never reads (any printable one)."""
    found = set()
    checked = 2 * PAIRS
    past_end = (-32 * 128 - 32) & 0xFFFF            # x of a pair made of two zero words
    for g in range(0x10000):
        typed, half = [], []                         # per pair: both chars typed / first typed, second is NUL
        for i in range(PAIRS):
            x = ((targets[i] - g) & 0xFFFF) ^ (33 * i)
            lo, hi = x & 0x7F, x >> 7
            typed.append((lo + 32, hi + 32) if lo <= 0x7E - 32 and hi <= 0x7E - 32 else None)
            first = (x + 32 * 128 + 32) & 0xFFFF
            half.append(first if first in PRINTABLE else None if x != past_end else "end")
        for length in range(1, maxlen + 1):
            chars = []
            for i in range(PAIRS):
                a, b = 2 * i, 2 * i + 1
                if b < length:
                    if typed[i] is None:
                        break
                    chars += typed[i]
                elif a < length:
                    if half[i] in (None, "end"):
                        break
                    chars.append(half[i])
                elif half[i] != "end":
                    break
            else:
                found.update(_complete(bytes(chars), length, g, checked))
    return sorted(found)


def _complete(head, length, g, fixed):
    """Characters beyond the 30 checked ones are free unless they hold the first '@' or precede it."""
    assert len(head) == min(length, fixed)
    tail = length - len(head)
    out = []
    if b"@" in head:
        p = head.index(b"@")
        if (at_weight(p) + sum(head[:p])) & 0xFFFF == g:
            out.append(head + b"?" * tail if tail else head)     # '?' marks a free printable character
        return out
    for p in range(len(head), length):                          # first '@' in the tail
        free_before = p - len(head)
        base = (at_weight(p) + sum(head)) & 0xFFFF
        if free_before == 0:
            if base == g:
                out.append(head + b"@" + b"?" * (length - p - 1))
        elif free_before == 1:
            ch = (g - base) & 0xFFFF
            if ch in PRINTABLE and ch != 0x40:
                out.append(head + bytes([ch]) + b"@" + b"?" * (length - p - 1))
        else:
            raise ValueError("maxlen larger than this solver handles")
    return out


def expand(pattern: bytes, fill: bytes = b"XY") -> bytes:
    it = iter(fill * len(pattern))
    return bytes(next(it) if ch == ord("?") else ch for ch in pattern)


def measure_global(image, r, base_password: bytes) -> dict:
    """Recover G's law from the program: dG/dc_j and K(p) = G - sum(c[:p])."""
    def g_of(pw):
        model = Rssb(image, r, pw)
        ys = model.run(probe=PROBE_Y)
        c = cells(r, pw)
        return (ys[0] - ((c[1] - 32) * 128 + (c[0] - 32))) & 0xFFFF
    g0 = g_of(base_password)
    p = base_password.index(b"@")
    slopes = {}
    for j in range(len(base_password)):
        if j == p:
            continue
        pw = bytearray(base_password)
        pw[j] += 1 if pw[j] != 0x3F else 2                       # never create a second '@'
        slopes[j] = ((g_of(bytes(pw)) - g0) & 0xFFFF) // (pw[j] - base_password[j])
    ks = {}
    for at in range(r.maxlen):
        pw = bytearray(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef")
        pw[at] = 0x40
        ks[at] = (g_of(bytes(pw)) - sum(pw[:at])) & 0xFFFF
    return {"slopes": slopes, "at": p, "K": ks}


# ---------------------------------------------------------------- report

def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--image", type=Path, default=IMAGE)
    ap.add_argument("--random", type=int, default=40, help="random passwords for gate 3")
    ap.add_argument("--boundary", type=int, default=30, help="passwords with y_i near 0x8000 for gate 3")
    ap.add_argument("--pin", action="store_true", help="print the TMP.DAT hash and exit")
    args = ap.parse_args()
    if args.pin:
        print(hashlib.sha256(fat12_files(args.image.read_bytes())["TMP.DAT"]).hexdigest())
        return
    tmp, r = load_inputs(args.image)
    lines = []

    def say(s=""):
        print(s, flush=True)
        lines.append(s)

    say(f"resident {len(r.code):#x} bytes; check {r.check:#x}; Subleq mem0 {r.mem0:#x}, {r.words:#x} words, "
        f"pc0 {r.pc0}; password -> word {(r.pwdst - r.mem0) // 2:#x} (max {r.maxlen}); result word {r.result:#x}")

    image = rssb_image(r)
    targets = table(image)
    probes = [b"", b"hello@flare-on.com", b"no-at-sign", b"Av0cad0_Love_2018@flare-on.co"]

    say("\n[gate 1] x86 (Unicorn) == Subleq (vm.c)")
    for pw in probes:
        ax, printed, area = x86_check(r, pw)
        s = subleq_fast(r, pw)
        expect(area == resident_area(s["segment"]), f"memory differs for {pw!r}")
        expect(printed == s["printed"] and ax == s["result"], f"output/result differ for {pw!r}")
        say(f"  {pw!r:34} {s['steps']:>11,} Subleq steps; ax={ax}; {len(area):#x} bytes of memory "
            f"and {len(printed)} printed bytes equal")

    say("\n[gate 2] Subleq == RSSB (lockstep, whole RSSB region after every instruction)")
    for pw in probes:
        ls = lockstep(r, pw)
        model = Rssb(image, r, pw)
        model.run()
        expect(bytes(model.printed) == ls["printed"], f"RSSB output differs for {pw!r}")
        say(f"  {pw!r:34} {ls['rssb']:>8,} RSSB instructions == {ls['subleq']:>11,} Subleq steps")

    say("\n[lift] G measured on the program")
    mg = measure_global(image, r, b"ABCDEFGHIJKLMNOPQ@flare-on.com")
    before = {mg["slopes"][j] for j in mg["slopes"] if j < mg["at"]}
    after = {mg["slopes"][j] for j in mg["slopes"] if j > mg["at"]}
    expect(before == {1} and after == {0}, f"G is not sum(chars before '@') + K: {mg['slopes']}")
    expect(all(k == at_weight(p) for p, k in mg["K"].items()), f"K(p) differs: {mg['K']}")
    odd = {p: k for p, k in mg["K"].items() if k != (0xC00 * p) & 0xFFFF}
    say(f"  dG/dc_j = 1 before '@', 0 after; K(p) measured for p = 0..{r.maxlen - 1}: 0xc00*p except "
        + ", ".join(f"K({p}) = {k:#06x}" for p, k in odd.items()) + " (the 0x8000 move bug)")
    say("  y_i = (((c[2i+1]-32)*128 + (c[2i]-32)) ^ 33*i) + K(p) + sum(c[:p])   (mod 2^16)")
    say("  accepted iff y_i == table[i] for i < 15, table = " + " ".join(f"{t:04x}" for t in targets))

    say(f"\n[gate 3] RSSB == lifted formula (edge cases, {args.random} random, {args.boundary} near 0x8000)")
    rng = random.Random(2018)
    cases = [b"", b"@", b"a@b", b"no-at-sign", b"x" * 31 + b"@", b"@@", b"A" * 40, b"hello@flare-on.com"]
    cases += [b"Q" * p + b"@" + b"z" * (29 - p) for p in range(30)]          # '@' at every checked position
    for _ in range(args.random):
        n = rng.randint(1, r.maxlen + 4)
        pw = bytearray(rng.randrange(0x20, 0x7F) for _ in range(n))
        if rng.random() < 0.8:
            pw[rng.randrange(n)] = 0x40
        cases.append(bytes(pw))
    edges = boundary_cases(r, args.boundary, rng)
    for pw in cases + edges:
        model = Rssb(image, r, pw)
        ys = model.run(probe=PROBE_Y)
        verdict, want = lifted(cells(r, pw), targets)
        expect(ys == want and model.result == verdict, f"lifted formula differs for {pw!r}")
    say(f"  {len(cases)} passwords + {len(edges)} with some y_i in {{0x7fff, 0x8000, 0x8001}}: "
        "every y_i and the verdict equal")

    say("\n[gate 4] exhaustive solve over G (65,536 values) x length (1..32)")
    patterns = solve(targets, r.maxlen)
    say(f"  {len(patterns)} solution pattern(s) ('?' = any printable character):")
    for pat in patterns:
        say(f"    {pat.decode()}")
    for pat in patterns:
        pw = expand(pat)
        ax, printed, _ = x86_check(r, pw)
        verdict, _ = lifted(cells(r, pw), targets)
        model = Rssb(image, r, pw)
        model.run()
        expect(model.result == 1, f"RSSB rejects {pw!r}")
        expect(ax == 1 and verdict == 1 and b"Password Matched" in printed, f"x86 rejects {pw!r}")
        message = printed.decode().split("\r\n")[-4:-2]
        say(f"  x86: {pw.decode()!r} -> ax=1, {' '.join(message)!r}")
    for pat in patterns:                                   # one wrong character anywhere is rejected
        pw = bytearray(expand(pat))
        for j in (0, 13, 29):
            bad = bytearray(pw)
            bad[j] = 0x21 if bad[j] != 0x21 else 0x22
            ax, _, _ = x86_check(r, bytes(bad))
            expect(ax == 0, f"x86 accepts {bytes(bad)!r}")
    say("  x86 rejects each solution with character 0, 13 or 29 changed")

    GENERATED.mkdir(exist_ok=True)
    (GENERATED / "report.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
