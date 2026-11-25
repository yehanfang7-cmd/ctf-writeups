"""Unit 07, diversity: break a shuffled-opcode build with unit 06's method.

Once the protector shuffles the opcode numbering on every build, the unit-07 scanner (attack.py) fails: it
looks for fixed opcode bytes that are no longer there. So we stop trusting the numbering and recover it by
behaviour, exactly as unit 06 does -- run one instruction at a time through the interpreter (here the `oracle`
tool, standing in for vm_run emulated out of the PE) and classify each byte by what it does to the stack.

  classify  ->  recover which byte means INPUT/PUSH/ADD/.../HALT, without reading any table
  scan      ->  with that numbering, decrypt and decode the blob (reusing attack.py)
  confirm   ->  lifted C vs the shipped binary on random inputs

    python VMP/07_minivm/attack_div.py          # builds a shuffled variant and breaks it
"""
import subprocess
import sys
from pathlib import Path

import attack
import build

ERR = {0: "OK", 1: "BAD_OP", 2: "TRUNCATED", 3: "UNDERFLOW", 4: "OVERFLOW", 5: "BAD_SHIFT", 6: "NO_HALT"}
U8 = lambda v: list(int(v).to_bytes(8, "little"))


def oracle(path, code, inp):
    """run the interpreter on chosen bytecode; returns (err, stack bottom->top)"""
    hexed = bytes(code).hex()
    r = subprocess.run([str(path), hexed, str(inp)], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"oracle failed on {hexed}: {r.stderr}")
    parts = r.stdout.split()
    return int(parts[0]), [int(x) for x in parts[2:]]


def classify(path):
    """recover {byte: opcode-name} purely from the interpreter's behaviour"""
    err = lambda code, x=0: oracle(path, code, x)[0]
    stk = lambda code, x=0: oracle(path, code, x)[1]

    valid = [v for v in range(1, 256) if err([v]) != 1]                 # 13 bytes are not BAD_OP
    operand = [v for v in valid if err([v]) == 2]                       # PUSH/SHR/SHL/ROL need an operand
    plain = [v for v in valid if v not in operand]

    names = {}
    # PUSH: give it an operand and nothing to pop; it leaves the immediate on the stack
    push = next(v for v in operand if oracle(path, [v] + U8(0xC0FFEE), 0) == (6, [0xC0FFEE]))
    names[push] = "PUSH"
    # INPUT: a single byte that leaves exactly the input on the stack
    inp = next(v for v in plain if oracle(path, [v], 0xABC) == (6, [0xABC]) and oracle(path, [v], 7) == (6, [7]))
    names[inp] = "INPUT"
    # HALT: pops a value and returns OK; DUP duplicates it
    halt = next(v for v in plain if v != inp and oracle(path, [inp, v], 0x99) == (0, [0x99]))
    dup = next(v for v in plain if v not in (inp, halt) and oracle(path, [inp, v], 0x99) == (6, [0x99, 0x99]))
    names[halt], names[dup] = "HALT", "DUP"
    # binary ops: PUSH a, PUSH b, op, HALT -> a OP b, with a=6 b=3 separating all six
    by_result = {9: "ADD", 3: "SUB", 18: "MUL", 5: "XOR", 2: "AND", 7: "OR"}
    for v in plain:
        if v in names:
            continue
        r = oracle(path, [push] + U8(6) + [push] + U8(3) + [v, halt], 0)
        names[v] = by_result[r[1][0]] if r[0] == 0 and r[1] and r[1][0] in by_result else "?"
    # shift ops: PUSH val, op n, HALT -> val>>n / val<<n / rotl(val,n)
    val, n = 0x8000000000000001, 4
    by_shift = {val >> n: "SHR", (val << n) & build.M64: "SHL", build.rotl(val, n): "ROL"}
    for v in operand:
        if v == push:
            continue
        r = oracle(path, [push] + U8(val) + [v] + U8(n) + [halt], 0)
        names[v] = by_shift.get(r[1][0], "?") if r[0] == 0 and r[1] else "?"
    return names


def break_build(exe, oracle_path, n_inputs=100):
    data = Path(exe).read_bytes()
    ops = classify(oracle_path)                                        # byte -> name, recovered behaviourally
    scanner_fixed = len(attack_fixed_candidates(data))                 # unit-07 scanner, for the record
    hits = attack.scan(data, ops)
    xs = [0, 1, build.M64] + [__import__("random").Random(99).getrandbits(64) for _ in range(n_inputs - 3)]
    truth = [int(build.run(exe, x)[1]) for x in xs]
    confirmed = [(off, seed, p) for off, seed, p in hits if [attack.emulate(p, x) for x in xs] == truth]
    out = dict(ops=ops, scanner_fixed=scanner_fixed, candidates=len(hits), confirmed=confirmed, inputs=len(xs))
    if len(confirmed) == 1:
        off, seed, p = confirmed[0]
        out.update(offset=off, seed=seed, insns=p, source=attack.lift(p))
    return out


def attack_fixed_candidates(data):
    """what attack.py's fixed-opcode scanner finds -- expected to collapse on a shuffled build"""
    return attack.scan(data)


def main():
    if build.compiler() is None:
        sys.exit("no C compiler")
    out_dir = build.GEN / "div"
    b = build.build(out_dir, seed=0xA5, opcode_seed=0x5EED)
    r = break_build(b["ship"], b["oracle"])
    print(f"shuffled build at {out_dir}")
    print(f"unit-07 fixed-opcode scanner: {r['scanner_fixed']} confirmed candidate(s)")
    print("recovered opcode numbering (by behaviour, not by reading the table):")
    for byte, name in sorted(r["ops"].items(), key=lambda kv: kv[1]):
        print(f"  {name:6} = 0x{byte:02x}")
    if len(r["confirmed"]) != 1:
        sys.exit(f"FAILED: {len(r['confirmed'])} confirmed programs")
    print(f"\nblob at offset {r['offset']:#x}, key {r['seed']:#04x}, {len(r['insns'])} instructions")
    print(r["source"], end="")


if __name__ == "__main__":
    main()
