"""Unit 07 attack: recover the secret from the shipped binary alone.

Threat model (Kerckhoffs): the attacker knows how minivm works -- its ISA and the shape of the rolling-XOR
cipher -- but not the key, where the blob is, or what the bytecode computes.

  1. scan     every file offset x every key that turns the first byte into an opcode; keep the byte runs that
              decrypt to a well-formed program (valid opcodes, shifts < 64, no stack underflow, ends in HALT)
  2. lift     the bytecode to C, naming each value the program duplicates
  3. confirm  the lifted program against the binary itself on random inputs (and the C, compiled)

    python VMP/07_minivm/attack.py [path/to/vm.exe]
"""
import random
import subprocess
import sys
from pathlib import Path

import build

M64 = (1 << 64) - 1
OPS = {0x10: "INPUT", 0x11: "PUSH", 0x12: "ADD", 0x13: "SUB", 0x14: "MUL", 0x15: "XOR", 0x16: "AND", 0x17: "OR",
       0x18: "SHR", 0x19: "SHL", 0x1A: "ROL", 0x1B: "DUP", 0x1C: "HALT"}
IMM = {"PUSH", "SHR", "SHL", "ROL"}
BIN = {"ADD": "+", "SUB": "-", "MUL": "*", "XOR": "^", "AND": "&", "OR": "|"}
MIN_INSNS = 4          # shorter runs are too easy to hit by chance
MAX_LEN = 1024


def keystream(seed, n=MAX_LEN):
    ks, k = bytearray(n), seed
    for i in range(n):
        ks[i] = k
        k = (k * 31 + 17) & 0xFF
    return bytes(ks)


KS = [keystream(s) for s in range(256)]


def parse(data, off, seed):
    """the program at data[off:] under key `seed`, or None if it is not well-formed"""
    ks, insns, pc, depth = KS[seed], [], 0, 0
    while off + pc < len(data) and pc < MAX_LEN:
        name = OPS.get(data[off + pc] ^ ks[pc])
        if name is None:
            return None
        imm = None
        if name in IMM:
            if off + pc + 9 > len(data) or pc + 9 > MAX_LEN:
                return None
            imm = int.from_bytes(bytes(data[off + pc + 1 + i] ^ ks[pc + 1 + i] for i in range(8)), "little")
            if name != "PUSH" and imm >= 64:
                return None
        need, delta = {"INPUT": (0, 1), "PUSH": (0, 1), "DUP": (1, 1), "HALT": (1, -1)}.get(
            name, (1, 0) if name in IMM else (2, -1))
        if depth < need:
            return None
        depth += delta
        insns.append((pc, name, imm))
        pc += 9 if name in IMM else 1
        if name == "HALT":
            return insns if len(insns) >= MIN_INSNS else None
    return None


def scan(data):
    """every (offset, key, program) in the file that decrypts to a well-formed program"""
    hits = []
    for off in range(len(data)):
        for op in OPS:
            seed = data[off] ^ op                       # the key that makes this byte the opcode `op`
            p = parse(data, off, seed)
            if p:
                hits.append((off, seed, p))
    return hits


# ---- lifting
def lift(insns):
    """C source for the program; a value the program DUPs gets its own variable"""
    stack, lines, temps = [], [], 0

    def leaf(e):
        return e[0] in ("x", "c", "var")

    for pc, name, imm in insns:
        if name == "INPUT":
            stack.append(("x",))
        elif name == "PUSH":
            stack.append(("c", imm))
        elif name in BIN:
            b, a = stack.pop(), stack.pop()
            stack.append((name, a, b))
        elif name in ("SHR", "SHL", "ROL"):
            stack.append((name, stack.pop(), imm))
        elif name == "DUP":
            top = stack.pop()
            if not leaf(top):
                v = f"t{temps}"
                temps += 1
                lines.append(f"    uint64_t {v} = {render(top)};")
                top = ("var", v)
            stack += [top, top]
        elif name == "HALT":
            lines.append(f"    return {render(stack.pop())};")
    return ("#include <stdint.h>\n\n"
            "static uint64_t rotl64(uint64_t x, unsigned n) { n &= 63; return n ? (x << n) | (x >> (64 - n)) : x; }\n\n"
            "uint64_t secret(uint64_t x) {\n" + "\n".join(lines) + "\n}\n")


def render(e, top=True):
    k = e[0]
    if k == "x":
        return "x"
    if k == "var":
        return e[1]
    if k == "c":
        return f"{e[1]:#x}ULL"
    if k == "ROL":
        return f"rotl64({render(e[1])}, {e[2]})"
    if k in ("SHR", "SHL"):
        s = f"{render(e[1], False)} {'>>' if k == 'SHR' else '<<'} {e[2]}"
    else:
        s = f"{render(e[1], False)} {BIN[k]} {render(e[2], False)}"
    return s if top else f"({s})"


def emulate(insns, x):
    """the attacker's own interpreter for the recovered bytecode"""
    st = []
    for pc, name, imm in insns:
        if name == "INPUT": st.append(x)
        elif name == "PUSH": st.append(imm)
        elif name == "DUP": st.append(st[-1])
        elif name == "HALT": return st.pop()
        elif name == "SHR": st.append(st.pop() >> imm)
        elif name == "SHL": st.append(st.pop() << imm & M64)
        elif name == "ROL": st.append(build.rotl(st.pop(), imm))
        else:
            b, a = st.pop(), st.pop()
            st.append({"ADD": a + b, "SUB": a - b, "MUL": a * b, "XOR": a ^ b, "AND": a & b, "OR": a | b}[name] & M64)
    raise ValueError("no HALT")


HARNESS = r"""
#include <stdio.h>
#include <stdlib.h>
uint64_t secret(uint64_t x);
int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) printf("%llu\n", (unsigned long long)secret(strtoull(argv[i], NULL, 0)));
    return 0;
}
"""


def run_binary(exe, xs):
    out = []
    for x in xs:
        rc, o, e = build.run(exe, x)
        out.append(int(o) if rc == 0 else None)
    return out


def compile_lifted(src, out_dir):
    c = out_dir / "recovered.c"
    c.write_text(src + HARNESS, encoding="utf-8")
    return build.cc(c, out_dir / f"recovered{build.EXE}")


def attack(exe, n_inputs=100, out_dir=None):
    data = Path(exe).read_bytes()
    hits = scan(data)
    rng = random.Random(2026)
    xs = [0, 1, M64] + [rng.getrandbits(64) for _ in range(n_inputs - 3)]
    truth = run_binary(exe, xs)
    confirmed = [(off, seed, p) for off, seed, p in hits if [emulate(p, x) for x in xs] == truth]
    result = dict(size=len(data), candidates=len(hits), confirmed=confirmed, inputs=len(xs))
    if len(confirmed) == 1:
        off, seed, p = confirmed[0]
        result.update(offset=off, seed=seed, insns=p, source=lift(p))
        if out_dir is not None and build.compiler():
            out_dir.mkdir(parents=True, exist_ok=True)
            rec = compile_lifted(result["source"], out_dir)
            r = subprocess.run([str(rec), *map(str, xs)], capture_output=True, text=True)
            result["c_matches"] = [int(v) for v in r.stdout.split()] == truth
    return result


def main():
    exe = Path(sys.argv[1]) if len(sys.argv) > 1 else build.GEN / f"vm{build.EXE}"
    if not exe.exists():
        sys.exit(f"{exe} not found: run build.py first")
    r = attack(exe, out_dir=build.GEN / "attack")
    print(f"{exe.name}: {r['size']} bytes, {r['candidates']} well-formed candidate(s), "
          f"{len(r['confirmed'])} agree with the binary on {r['inputs']} inputs")
    if len(r["confirmed"]) != 1:
        sys.exit("FAILED: expected exactly one confirmed program")
    print(f"blob at file offset {r['offset']:#x}, key {r['seed']:#04x}, {len(r['insns'])} instructions")
    for pc, name, imm in r["insns"]:
        print(f"  {pc:04x}: {name:6}" + (f" {imm:#x}" if imm is not None else ""))
    print(r["source"], end="")
    if "c_matches" in r:
        print(f"compiled recovered C matches the binary: {r['c_matches']}")
        if not r["c_matches"]:
            sys.exit("FAILED")


if __name__ == "__main__":
    main()
