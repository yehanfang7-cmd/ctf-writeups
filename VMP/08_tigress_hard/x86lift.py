"""Lift the native code emitted by Tigress' JIT (MyJIT back end) to the block IR of unit 06's Lifter.

The emitted code is very regular: every C statement is compiled on its own, values live in registers
only inside a statement and go through the frame in between.  Each basic block is evaluated
symbolically; anything outside the handled instruction forms raises instead of being guessed.

IR (same trees as 06_tigress/devirt.py):
  ("c", v) ("laddr", rbp_offset) ("paddr", "in"|"out") ("load", size, signed, ptr)
  (binop, x, y) (unop, x) ("merge", old, new, width)
  block = ([("store", size, ptr, value), ...], ("goto", t) | ("br", cond, "nz", 64, taken, fall) | ("ret",))
"""
import sys
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "06_tigress"))
import devirt                                                    # noqa: E402  (unit 06: Lifter, simp, build, ...)

M = (1 << 64) - 1
REG64 = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"] + [f"r{i}" for i in range(8, 16)]
SUB = {}
for i, r in enumerate(REG64):
    if i < 8:
        SUB["e" + r[1:]] = (r, 32)
        SUB[r[1:]] = (r, 16)
        SUB[(r[1] + "l") if r[2] == "x" else r[1:] + "l"] = (r, 8)
    else:
        SUB[r + "d"] = (r, 32); SUB[r + "w"] = (r, 16); SUB[r + "b"] = (r, 8)
    SUB[r] = (r, 64)
SETCC = {"a": "ugt", "b": "ult", "ae": "uge", "be": "ule", "e": "eq", "ne": "ne", "g": "sgt", "l": "slt", "ge": "sge", "le": "sle"}
ALU = {"add": "add", "sub": "sub", "and": "and", "or": "or", "xor": "xor", "shl": "shl", "shr": "shr", "sar": "sar", "imul": "mul"}
BOOL = set(SETCC.values())


class LiftError(ValueError):
    pass


def need(cond, what):
    if not cond:
        raise LiftError(what)


def has(t, kind):
    return isinstance(t, tuple) and (t[0] == kind or any(has(x, kind) for x in t[1:]))


def addr_norm(t):
    """Inside an address, write `x << k` as `x * 2**k` so the index scale is visible."""
    if t[0] == "add": return ("add", addr_norm(t[1]), addr_norm(t[2]))
    if t[0] == "shl" and t[2][0] == "c": return ("mul", t[1], ("c", 1 << t[2][1]))
    return t


def lift(code, base=0, frame_params=True):
    """code: bytes of one function (rdi = input, rsi = output).  Returns {leader offset: (stmts, term)}."""
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    insns, seen, todo = {}, set(), [base]
    leaders = {base}
    while todo:                                           # recursive descent
        a = todo.pop()
        while a not in insns and base <= a < base + len(code):
            ins = next(md.disasm(code[a - base:a - base + 16], a), None)
            need(ins is not None, f"undecodable bytes at {a:#x}")
            insns[a] = ins
            m = ins.mnemonic
            if m == "ret": break
            if m == "jmp":
                need(ins.operands[0].type == X86_OP_IMM, f"indirect jmp at {a:#x}")
                a = ins.operands[0].imm; leaders.add(a); continue
            if m.startswith("j"):
                t = ins.operands[0].imm
                leaders |= {t, a + ins.size}; todo.append(t)
            a += ins.size
    params = {}                                            # rbp offset -> "in" / "out"
    blocks = {}
    for lead in sorted(leaders):
        need(lead in insns, f"jump outside the function: {lead:#x}")
        reg = {r: ("undef", r) for r in REG64}
        if lead == base:
            reg["rdi"], reg["rsi"] = ("arg", "in"), ("arg", "out")
        mstack, stmts, flags, epoch = [], [], None, 0      # epoch: number of stores so far
        clean = lambda: all(x[0] == "undef" for x in mstack)   # only callee-saved registers pushed by the prologue
        born = {}                                          # id(tree) -> epoch of a load

        def fresh(t):
            """Reject a value that was loaded before a later store (it could have been overwritten)."""
            def walk(x):
                if not isinstance(x, tuple): return
                if x[0] == "load":
                    need(born.get(id(x), epoch) == epoch, f"value loaded before a store is used after it (block {lead:#x})")
                need(x[0] != "undef", f"register {x[1] if len(x) > 1 else '?'} is read before it is written in block {lead:#x}")
                for y in x[1:]: walk(y)
            walk(t)
            return t

        def frame(off):
            return ("paddr", params[off]) if off in params else ("laddr", off)

        def ea(op, ins):
            m = op.mem
            b = ins.reg_name(m.base) if m.base else None
            need(b != "rsp" and m.segment == 0, f"unexpected address form at {ins.address:#x}")
            if b == "rbp":
                need(not m.index, "indexed rbp access")
                return frame(m.disp)
            t = reg[b] if b else None
            if m.index:
                ix = reg[ins.reg_name(m.index)]
                if m.scale != 1: ix = ("mul", ix, ("c", m.scale))
                t = ix if t is None else ("add", t, ix)
            if m.disp or t is None:
                c = ("c", m.disp & M)
                t = c if t is None else ("add", t, c)
            return addr_norm(t)

        def is_rsp_top(op, ins):
            return op.type == X86_OP_MEM and op.mem.base and ins.reg_name(op.mem.base) == "rsp" and not op.mem.index and op.mem.disp == 0

        def rd(op, ins, signed=False):
            """64-bit tree of an operand (narrow operands are zero- or sign-extended)."""
            w = 8 * op.size
            if op.type == X86_OP_IMM: return ("c", op.imm & M)
            if op.type == X86_OP_REG:
                full, bits = SUB[ins.reg_name(op.reg)]
                t = reg[full]
                if bits == 64: return t
                if t[0] == "c":
                    v = t[1] & ((1 << bits) - 1)
                    return ("c", devirt.sx(v, bits) if signed else v)
                return (f"{'sext' if signed else 'zext'}{bits}", t)
            if is_rsp_top(op, ins):
                need(w == 64 and mstack, "narrow or empty machine-stack read")
                return mstack[-1]
            t = ("load", op.size, int(signed and w < 64), ea(op, ins))
            born[id(t)] = epoch
            return t

        def wr(op, ins, v):
            nonlocal epoch
            if op.type == X86_OP_REG:
                full, bits = SUB[ins.reg_name(op.reg)]
                if bits == 64: reg[full] = v
                elif bits == 32: reg[full] = v if v[0] in ("c", "load") and (v[0] != "c" or v[1] >> 32 == 0) and (v[0] != "load" or v[1] <= 4) else ("zext32", v)
                else:
                    old = reg[full]
                    small = v[0] in BOOL or (v[0] == "c" and v[1] >> bits == 0)
                    reg[full] = v if (old == ("c", 0) and small) else ("merge", old, v, bits)
                return
            need(op.type == X86_OP_MEM and not is_rsp_top(op, ins), "unexpected destination")
            ptr = ea(op, ins)
            if v[0] == "arg":                             # prologue: the parameter is spilled to the frame
                need(ptr[0] == "laddr" and op.size == 8, "parameter spilled to an unexpected place")
                params[ptr[1]] = v[1]
                return
            fresh(ptr); fresh(v)
            stmts.append(("store", op.size, ptr, v))
            epoch += 1

        a = lead
        term = None
        while term is None:
            ins = insns[a]
            m, ops = ins.mnemonic, ins.operands
            nxt = a + ins.size
            if m in ("mov", "movabs"):
                if ops[0].type == X86_OP_REG and ins.reg_name(ops[0].reg) in ("rbp", "rsp"):
                    pass                                   # frame set-up / tear-down
                else:
                    wr(ops[0], ins, rd(ops[1], ins))
            elif m in ("movsx", "movsxd", "movzx"):
                wr(ops[0], ins, rd(ops[1], ins, signed=m != "movzx"))
            elif m == "lea":
                wr(ops[0], ins, ea(ops[1], ins))
            elif m == "push":
                mstack.append(rd(ops[0], ins))
            elif m == "pop":
                v = mstack.pop() if mstack else ("undef", "callee-saved")   # epilogue restores what the prologue pushed
                if ins.reg_name(ops[0].reg) != "rbp": wr(ops[0], ins, v)
            elif m in ("add", "sub") and ops[0].type == X86_OP_REG and ins.reg_name(ops[0].reg) == "rsp":
                if lead == base and m == "sub" and not stmts:
                    pass                                   # frame allocation
                else:
                    need(m == "add" and ops[1].imm % 8 == 0 and len(mstack) >= ops[1].imm // 8, f"stack adjustment at {a:#x}")
                    del mstack[len(mstack) - ops[1].imm // 8:]
            elif m == "xor" and ops[1].type == X86_OP_REG and ops[0].reg == ops[1].reg:
                wr(ops[0], ins, ("c", 0))
            elif m in ALU and len(ops) == 2:
                x, y = rd(ops[0], ins), rd(ops[1], ins)
                if m in ("shl", "shr", "sar") and ops[1].type == X86_OP_REG:
                    y = reg["rcx"]                          # count in cl; the IR's shifts mask with 63 like the CPU
                need(ops[0].size == 8 or m in ("add", "sub", "and", "or", "xor"), f"narrow {m} at {a:#x}")
                wr(ops[0], ins, (ALU[m], x, y))
                flags = None
            elif m in ("not", "neg"):
                wr(ops[0], ins, (m, rd(ops[0], ins)))
            elif m == "mul":
                need(ops[0].size == 8, "narrow mul")
                reg["rax"] = ("mul", reg["rax"], rd(ops[0], ins)); reg["rdx"] = ("undef", "rdx(mul)")
            elif m in ("div", "idiv"):
                need(ops[0].size == 8, "narrow div")
                d = rd(ops[0], ins)
                if m == "div":
                    need(reg["rdx"] == ("c", 0), f"div with rdx != 0 at {a:#x}")
                    reg["rax"], reg["rdx"] = ("udiv", reg["rax"], d), ("urem", reg["rax"], d)
                else:
                    need(reg["rdx"] == ("cqo", reg["rax"]), f"idiv without cqo at {a:#x}")
                    reg["rax"], reg["rdx"] = ("sdiv", reg["rax"], d), ("srem", reg["rax"], d)
            elif m == "cqo":
                reg["rdx"] = ("cqo", reg["rax"])
            elif m in ("cmp", "test"):
                need(ops[0].size == 8, "narrow compare")
                flags = (m, rd(ops[0], ins), rd(ops[1], ins))
            elif m.startswith("set") and m[3:] in SETCC:
                need(flags and flags[0] == "cmp", f"setcc without cmp at {a:#x}")
                wr(ops[0], ins, (SETCC[m[3:]], flags[1], flags[2]))
            elif m == "jmp":
                need(clean(), "machine stack not empty at a jump")
                term = ("goto", ops[0].imm - base)
            elif m.startswith("j") and m[1:] in SETCC:
                need(flags and flags[0] == "cmp" and clean(), f"conditional jump without cmp at {a:#x}")
                if m in ("jne", "je") and flags[2] == ("c", 0):
                    c, sense = flags[1], "nz" if m == "jne" else "z"
                else:
                    c, sense = (SETCC[m[1:]], flags[1], flags[2]), "nz"
                term = ("br", fresh(c), sense, 64, ops[0].imm - base, nxt - base)
            elif m == "ret":
                term = ("ret",)
            elif m == "nop":
                pass
            else:
                raise LiftError(f"unhandled instruction at {a:#x}: {m} {ins.op_str}")
            a = nxt
            if term is None and a in leaders:
                need(clean(), "machine stack not empty at a block boundary")
                term = ("goto", a - base)
        blocks[lead - base] = (stmts, term)
    need(set(params.values()) == {"in", "out"}, f"parameters not spilled as expected: {params}")
    return blocks


class BlockLifter(devirt.Lifter):
    """Unit 06's C back end, fed with ready-made blocks instead of stack-VM instructions."""

    def __init__(self, raw):
        self.alias_narrow = True
        self.blocks = {}
        simp = devirt.simp
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


if __name__ == "__main__":
    n, k = sys.argv[1], sys.argv[2]
    code = (Path(__file__).resolve().parent / "generated" / f"{n}-{k}-jit1.bin").read_bytes()
    blocks = lift(code)
    for b, (st, term) in blocks.items():
        print(hex(b), len(st), "stores,", term[0], term[-2:] if term[0] == "br" else term[1:])
    print(BlockLifter(blocks).source())
