"""Whole-program Unicorn emulation of the Tigress challenge ELFs (0004-0006).

The binaries are Linux x86-64, dynamically linked, non-PIE.  Nothing is ever run natively:
segments are mapped into Unicorn, every imported libc function is replaced by a Python stub
reached through its GOT slot, and `main` is called the way __libc_start_main would.
"""
import re
import struct
from pathlib import Path

import lief
from unicorn import (Uc, UcError, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED,
                     UC_PROT_ALL)
from unicorn.x86_const import *

HERE = Path(__file__).resolve().parent
M64 = (1 << 64) - 1
PAGE = 0x1000
STUBS = 0x7F0000000000          # one 16-byte slot per imported function
STACK_TOP = 0x7FFF00000000
STACK_SIZE = 0x400000
HEAP = 0x10000000
HEAP_SIZE = 0x8000000
ARGV = 0x7FFE00000000
EXIT = STUBS + 0xFF000           # return address of main
ARG_REGS = (UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_RCX, UC_X86_REG_R8, UC_X86_REG_R9)


class Exited(Exception):
    pass


class Program:
    def __init__(self, path):
        self.path = Path(path)
        self.elf = lief.ELF.parse(str(path))
        self.raw = self.path.read_bytes()
        self.imports = {}                       # stub address -> name
        self.got = {}                           # name -> got slot
        for i, rel in enumerate(self.elf.pltgot_relocations):
            self.imports[STUBS + 16 * i] = rel.symbol.name
            self.got[rel.symbol.name] = rel.address
        self.data_relocs = [(r.address, r.symbol.name) for r in self.elf.dynamic_relocations if r.has_symbol and r.symbol.name]
        self.main = self._find_main()

    def _find_main(self):
        # _start: ... mov rdi, <main> ; call __libc_start_main
        code = bytes(self.elf.get_content_from_virtual_address(self.elf.entrypoint, 0x40))
        m = re.search(rb"\x48\xc7\xc7(....)", code, re.S)
        assert m, "main not found in _start"
        return struct.unpack("<I", m.group(1))[0]

    def read_static(self, addr, n):
        return bytes(self.elf.get_content_from_virtual_address(addr, n))


class Emu:
    """One process image.  `run(args)` executes main(argc, argv) and returns the printed lines."""

    def __init__(self, prog, insn_limit=0):
        self.prog = prog
        self.insn_limit = insn_limit
        self.out = []
        self.heap = HEAP
        self.rand_state = 1
        self.handlers = {}
        self.signals = 0
        self.calls = []                         # (name, args) log of libc calls
        self.log_calls = False
        self.on_call = {}                       # name -> callback(emu) run before the stub
        uc = self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
        for seg in prog.elf.segments:
            if seg.type != lief.ELF.Segment.TYPE.LOAD:
                continue
            lo = seg.virtual_address & ~(PAGE - 1)
            hi = (seg.virtual_address + seg.virtual_size + PAGE - 1) & ~(PAGE - 1)
            try:
                uc.mem_map(lo, hi - lo, UC_PROT_ALL)
            except UcError:                      # segments sharing a page
                for a in range(lo, hi, PAGE):
                    try:
                        uc.mem_map(a, PAGE, UC_PROT_ALL)
                    except UcError:
                        pass
            uc.mem_write(seg.virtual_address, bytes(seg.content))
        uc.mem_map(STUBS, 0x100000, UC_PROT_ALL)
        uc.mem_write(STUBS, b"\xc3" * 0x100000)
        uc.mem_map(STACK_TOP - STACK_SIZE, STACK_SIZE, UC_PROT_ALL)
        uc.mem_map(HEAP, HEAP_SIZE, UC_PROT_ALL)
        uc.mem_map(ARGV, 0x10000, UC_PROT_ALL)
        uc.mem_map(0x7FFD00000000, 0x2000, UC_PROT_ALL)          # TLS: fs:0x28 stack canary
        uc.reg_write(UC_X86_REG_FS_BASE, 0x7FFD00001000)
        uc.mem_write(0x7FFD00001028, struct.pack("<Q", 0xDEADBEEFCAFEF00D))
        for stub, name in prog.imports.items():
            uc.mem_write(prog.got[name], struct.pack("<Q", stub))
        for addr, name in prog.data_relocs:                      # stdout/stderr style data imports
            uc.mem_write(addr, struct.pack("<Q", HEAP + HEAP_SIZE - 0x1000))
        uc.hook_add(UC_HOOK_CODE, self._stub, begin=STUBS, end=STUBS + 0x100000)
        self.count = 0

    # -- helpers ---------------------------------------------------------------------------
    def arg(self, i): return self.uc.reg_read(ARG_REGS[i])
    def rq(self, a): return struct.unpack("<Q", self.uc.mem_read(a, 8))[0]
    def wq(self, a, v): self.uc.mem_write(a, struct.pack("<Q", v & M64))

    def cstr(self, a):
        s = b""
        while True:
            c = bytes(self.uc.mem_read(a + len(s), 64))
            if b"\0" in c:
                return s + c[:c.index(b"\0")]
            s += c

    def alloc(self, n, align=16):
        self.heap = (self.heap + align - 1) & ~(align - 1)
        p = self.heap
        self.heap += max(n, 1)
        assert self.heap < HEAP + HEAP_SIZE - 0x2000, "heap exhausted"
        return p

    # -- libc ------------------------------------------------------------------------------
    def _stub(self, uc, addr, size, _):
        if addr == EXIT:
            raise Exited()
        name = self.prog.imports.get(addr)
        if name is None:
            return
        if self.log_calls:
            self.calls.append((name, tuple(self.arg(i) for i in range(4))))
        cb = self.on_call.get(name)
        if cb:
            cb(self)
        fn = getattr(self, "libc_" + name, None)
        if fn is None:
            raise RuntimeError(f"unimplemented libc function {name}")
        ret = fn()
        if ret is not None:
            uc.reg_write(UC_X86_REG_RAX, ret & M64)

    def libc_strtoul(self):
        s = self.cstr(self.arg(0)).decode()
        end = self.arg(1)
        base = self.arg(2)
        m = re.match(r"\s*(0[xX][0-9a-fA-F]+|\d+)", s)
        v = int(m.group(1), base or 0) if m else 0
        if end:
            self.wq(end, self.arg(0) + (m.end() if m else 0))
        return v & M64

    def libc_printf(self):
        fmt = self.cstr(self.arg(0)).decode()
        args = [self.arg(i) for i in range(1, 6)]
        it = iter(args)

        def sub(m):
            c = m.group(0)[-1]
            v = next(it)
            if c == "u": return str(v if "l" in m.group(0) else v & 0xFFFFFFFF)
            if c in "di":
                bits = 64 if "l" in m.group(0) else 32
                v &= (1 << bits) - 1
                return str(v - (1 << bits) if v >> (bits - 1) else v)
            if c == "x": return "%x" % v
            if c == "s": return self.cstr(v).decode()
            return m.group(0)
        self.out.append(re.sub(r"%[0-9l]*[a-zA-Z]", sub, fmt))
        return 0

    def libc_malloc(self):
        return self.alloc(self.arg(0))

    def libc_realloc(self):
        old, n = self.arg(0), self.arg(1)
        p = self.alloc(n)
        if old:
            self.uc.mem_write(p, bytes(self.uc.mem_read(old, min(n, HEAP + HEAP_SIZE - old))))
        return p

    def libc_posix_memalign(self):
        p = self.alloc(self.arg(2), max(self.arg(1), 16))
        self.wq(self.arg(0), p)
        return 0

    def libc_free(self): return 0
    def libc_mprotect(self): return 0
    def libc_sysconf(self): return PAGE

    def libc_memcpy(self):
        d, s, n = self.arg(0), self.arg(1), self.arg(2)
        self.uc.mem_write(d, bytes(self.uc.mem_read(s, n)))
        return d

    def libc_rand(self):
        self.rand_state = (self.rand_state * 1103515245 + 12345) & 0x7FFFFFFF
        return self.rand_state

    def libc_exit(self):
        raise Exited()

    def libc___stack_chk_fail(self):
        raise RuntimeError("stack smashing detected")

    def libc_getenv(self): return 0

    def libc_signal(self):
        self.handlers[self.arg(0)] = self.arg(1)
        return 0

    def libc_raise(self):
        # deliver synchronously: tail-jump into the handler, which returns to raise()'s caller
        h = self.handlers.get(self.arg(0))
        if h is None:
            raise RuntimeError(f"raise({self.arg(0)}) with no handler")
        self.signals += 1
        self.uc.reg_write(UC_X86_REG_RIP, h)
        return None

    # -- run -------------------------------------------------------------------------------
    def setup_main(self, args):
        uc = self.uc
        strs = [b"challenge"] + [str(a).encode() for a in args]
        p = ARGV + 0x1000
        ptrs = []
        for s in strs:
            uc.mem_write(p, s + b"\0")
            ptrs.append(p)
            p += len(s) + 1
        for i, q in enumerate(ptrs + [0]):
            self.wq(ARGV + 8 * i, q)
        sp = STACK_TOP - 0x1000
        self.wq(sp, EXIT)
        uc.reg_write(UC_X86_REG_RSP, sp)
        uc.reg_write(UC_X86_REG_RBP, 0)
        uc.reg_write(UC_X86_REG_RDI, len(strs))
        uc.reg_write(UC_X86_REG_RSI, ARGV)
        uc.reg_write(UC_X86_REG_RDX, ARGV + 8 * len(strs))

    def start(self, at, until=0):
        try:
            self.uc.emu_start(at, until, count=self.insn_limit)
        except Exited:
            pass

    def run(self, args):
        self.out = []
        self.setup_main(args)
        self.start(self.prog.main)
        return self.out


def run(path, args, **kw):
    e = Emu(Program(path), **kw)
    return e.run(args)


if __name__ == "__main__":
    import sys, time
    for n in sys.argv[1].split(","):
        for k in range(5):
            p = HERE / "inputs" / n / f"challenge-{k}"
            for args in ([], [1], [1, 2], [0x1234567]):
                t = time.time()
                try:
                    e = Emu(Program(p))
                    e.log_calls = True
                    out = e.run(args)
                    names = sorted({c[0] for c in e.calls})
                    print(n, k, args, "->", out, "%.1fs" % (time.time() - t), names)
                except Exception as ex:
                    print(n, k, args, "ERROR", type(ex).__name__, ex)
