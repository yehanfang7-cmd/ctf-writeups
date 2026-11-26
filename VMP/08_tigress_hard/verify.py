"""Shared verification for unit 08: path enumeration over block IR (z3) and C-vs-original comparison."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "06_tigress"))
import devirt                                                    # noqa: E402

M = (1 << 64) - 1
HERE = Path(__file__).resolve().parent
devirt.GENERATED = HERE / "generated"


def explore_blocks(blocks, max_paths=256, max_steps=100_000, timeout_ms=60_000):
    """Symbolically execute block IR; every feasible branch side is followed.
    Returns [{input, blocks (set of leaders), branches}] - one solved input per path.
    Returns (paths, undecided, visited).  A branch side is dropped when z3 proves it unsatisfiable.
    When z3 gives up within timeout_ms, the side is recorded in `undecided` as (block, target) and not
    followed: nothing is known about it.  `visited` also contains the blocks of paths that had to be
    abandoned at such a branch (they are reachable, but no input was solved for them)."""
    import z3
    Z = lambda v: z3.BitVecVal(v & M, 64)
    RBP, IN, OUT = 0x7FFF0000, 0x10000, 0x20000
    b01 = lambda c: z3.If(c, Z(1), Z(0))
    ZB = {"add": lambda x, y: x + y, "sub": lambda x, y: x - y, "mul": lambda x, y: x * y, "and": lambda x, y: x & y,
          "or": lambda x, y: x | y, "xor": lambda x, y: x ^ y, "shl": lambda x, y: x << (y & 63),
          "shr": lambda x, y: z3.LShR(x, y & 63), "sar": lambda x, y: x >> (y & 63), "udiv": z3.UDiv, "urem": z3.URem,
          "sdiv": lambda x, y: x / y, "srem": z3.SRem, "eq": lambda x, y: b01(x == y), "ne": lambda x, y: b01(x != y),
          "ult": lambda x, y: b01(z3.ULT(x, y)), "ule": lambda x, y: b01(z3.ULE(x, y)), "ugt": lambda x, y: b01(z3.UGT(x, y)),
          "uge": lambda x, y: b01(z3.UGE(x, y)), "slt": lambda x, y: b01(x < y), "sle": lambda x, y: b01(x <= y),
          "sgt": lambda x, y: b01(x > y), "sge": lambda x, y: b01(x >= y)}

    def zload(mem, p, size):
        parts = [z3.Select(mem, p + i) for i in reversed(range(size))]
        return parts[0] if size == 1 else z3.Concat(*parts)

    def zstore(mem, p, v, size):
        for i in range(size): mem = z3.Store(mem, p + i, z3.Extract(8 * i + 7, 8 * i, v))
        return mem

    def ev(t, mem):
        k = t[0]
        if k == "c": return Z(t[1])
        if k == "laddr": return Z(RBP + t[1])
        if k == "paddr": return Z(RBP - 0x1000 + (8 if t[1] == "in" else 16))
        if k == "load":
            v = zload(mem, z3.simplify(ev(t[3], mem)), t[1])
            return v if t[1] == 8 else (z3.SignExt if t[2] else z3.ZeroExt)(64 - 8 * t[1], v)
        if k == "merge":
            new = ev(t[2], mem)
            return new if t[3] == 64 else z3.Concat(z3.Extract(63, t[3], ev(t[1], mem)), z3.Extract(t[3] - 1, 0, new))
        if k in ("s32", "z32") or k.startswith(("zext", "sext")):
            bits = 32 if k in ("s32", "z32") else int(k[4:])
            lo = z3.Extract(bits - 1, 0, ev(t[1], mem))
            return (z3.SignExt if k[0] == "s" else z3.ZeroExt)(64 - bits, lo)
        if k == "id": return ev(t[1], mem)
        if k == "not": return ~ev(t[1], mem)
        if k == "neg": return -ev(t[1], mem)
        if k == "lnot": return b01(ev(t[1], mem) == 0)
        return ZB[k](ev(t[1], mem), ev(t[2], mem))

    x = z3.BitVec("x", 64)
    mem0 = z3.K(z3.BitVecSort(64), z3.BitVecVal(0, 8))
    mem0 = zstore(mem0, Z(IN), x, 8)
    mem0 = zstore(mem0, Z(RBP - 0x1000 + 8), Z(IN), 8)
    mem0 = zstore(mem0, Z(RBP - 0x1000 + 16), Z(OUT), 8)
    paths, work, undecided, visited = [], [(0, mem0, [], set())], set(), set()
    while work:
        if len(paths) >= max_paths: raise ValueError("too many paths")
        b, mem, cond, seen = work.pop()
        for _ in range(max_steps):
            seen = seen | {b}
            visited.add(b)
            st, term = blocks[b]
            for _, size, ptr, val in st:
                mem = zstore(mem, z3.simplify(ev(ptr, mem)), z3.simplify(ev(val, mem)), size)
            if term[0] == "goto": b = term[1]; continue
            if term[0] == "ret":
                s = z3.Solver(); s.add(*cond)
                assert s.check() == z3.sat
                paths.append(dict(input=s.model().eval(x, model_completion=True).as_long(), blocks=seen, branches=len(cond)))
                break
            _, c, sense, w, tk, fl = term
            nz = z3.Extract(w - 1, 0, ev(c, mem)) != 0
            taken = nz if sense == "nz" else z3.Not(nz)
            outs = []
            for t, tgt in ((taken, tk), (z3.Not(taken), fl)):
                t = z3.simplify(t)
                if z3.is_true(t): outs = [(tgt, cond)]; break
                if z3.is_false(t): continue
                s = z3.Solver(); s.set("timeout", timeout_ms); s.add(*cond, t)
                r = s.check()
                if r == z3.unknown: undecided.add((b, tgt))
                if r == z3.sat: outs.append((tgt, cond + [t]))
            if not outs:                                    # every side unsat or undecided: this path ends here
                assert any(u[0] == b for u in undecided), "branch with no feasible side"
                break
            for tgt, cnd in outs[1:]: work.append((tgt, mem, cnd, seen))
            b, cond = outs[0]
        else:
            raise ValueError("path too long")
    return paths, sorted(undecided), visited


def coverage(blocks, paths, undecided, visited):
    """Split blocks into: covered (some solved input runs them), proven dead (every way in is unsatisfiable),
    and unknown (behind an undecided branch side, or on a path abandoned at one)."""
    covered = set().union(*(p["blocks"] for p in paths)) if paths else set()
    rest = set(blocks) - covered
    if not undecided:
        assert visited <= covered, "a path was abandoned without an undecided branch"
        return covered, rest, set()
    succ = {b: [] if t[0] == "ret" else [t[1]] if t[0] == "goto" else [t[4], t[5]] for b, (s, t) in blocks.items()}
    unknown, work = (visited & rest), [t for _, t in undecided]
    while work:
        n = work.pop()
        if n in rest and n not in unknown:
            unknown.add(n); work.extend(succ[n])
    return covered, rest - unknown, unknown


class Oracle:
    """Anything with run(x) -> output."""
    def __init__(self, fn): self.run = fn


def compare_c(src, name, oracle, xs):
    """Compile recovered C with gcc and compare with oracle(x) on xs.  Returns the list of mismatches."""
    exe = devirt.build(src, name)
    return devirt.compare(Oracle(oracle), exe, xs)
