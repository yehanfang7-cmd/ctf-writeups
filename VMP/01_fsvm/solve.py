"""Partially evaluate fsvm; recover its suffix check, not just one accepted flag."""
import argparse
from dataclasses import dataclass
from pathlib import Path
from vm import VMError, decode, number, run, step_data

HERE = Path(__file__).resolve().parent


@dataclass(frozen=True)
class InputTail:
    removed: int = 0


@dataclass(frozen=True)
class Linear:
    index: int | None
    scale: int
    constant: int

    def __str__(self):
        return f"{self.scale} * ord(input[{self.index}]) + {self.constant}"


def integer(value):
    if isinstance(value, Linear):
        return value
    if isinstance(value, str):
        return Linear(None, 0, number(value))
    raise VMError(f"Cannot interpret symbolic value as integer: {value!r}")


def decimal(value):
    return str(value.constant) if value.index is None else value


def add(left, right):
    left, right = integer(left), integer(right)
    if left.index is not None and right.index is not None and left.index != right.index:
        raise VMError("This educational lifter only models single-character linear expressions")
    return decimal(Linear(left.index if left.index is not None else right.index,
                          left.scale + right.scale, left.constant + right.constant))


def concat(left, right):
    if isinstance(left, str) and isinstance(right, str):
        return left + right
    parts = []
    for value in (left, right):
        for part in value if isinstance(value, tuple) else (value,):
            if part != "":
                parts.append(part)
    return tuple(parts)


def lift(instructions):
    regs, prefix, read_count = [""] * 8, [], 0
    by_pc = {ins.pc: ins for ins in instructions}
    for ins in instructions:
        op, a = ins.op, ins.args
        if op == "read":
            read_count += 1
            if read_count != 1:
                raise VMError("Only one input read is supported")
            regs[0] = InputTail()
        elif op == "ord" and isinstance(regs[a[0]], InputTail):
            regs[a[1]] = Linear(-1 - regs[a[0]].removed, 1, 0)
        elif op == "pop" and isinstance(regs[a[0]], InputTail):
            regs[a[0]] = InputTail(regs[a[0]].removed + 1)
        elif op == "add":
            regs[a[2]] = add(regs[a[0]], regs[a[1]])
        elif op == "neg" and isinstance(regs[a[0]], Linear):
            value = regs[a[0]]
            regs[a[0]] = Linear(value.index, -value.scale, -value.constant)
        elif op == "concat":
            regs[a[2]] = concat(regs[a[0]], regs[a[1]])
        elif op in ("je", "jne"):
            terms = regs[6]
            if not isinstance(terms, tuple) or not terms or regs[7] != "0" * len(terms):
                raise VMError("Expected decimal-expression concatenation compared with zero string")
            if not all(isinstance(term, Linear) and term.scale in (-1, 1) for term in terms):
                raise VMError("Cannot reduce this predicate to independent byte equalities")
            values = {}
            for term in terms:
                if term.index in values or term.index is None or term.index >= 0:
                    raise VMError("Non-unique/non-suffix input indexes")
                value = -term.constant // term.scale
                if not 33 <= value <= 126:
                    raise VMError("Expected printable non-whitespace ASCII suffix")
                values[term.index] = value
            size = len(values)
            if sorted(values) != list(range(-size, 0)) or regs[0] != InputTail(size):
                raise VMError("Predicate does not cover a contiguous consumed suffix")
            suffix = "".join(chr(values[i]) for i in range(-size, 0))
            target = ins.next_pc + number(regs[5])

            def finish(pc):
                state, output = list(regs), list(prefix)
                for _ in range(len(instructions)):
                    if pc not in by_pc:
                        raise VMError(f"Bad branch target: {pc:#x}")
                    tail = by_pc[pc]
                    if tail.op == "ret":
                        return output
                    if tail.op in ("jmp", "je", "jne", "jl", "read"):
                        raise VMError("Expected straight-line output tail")
                    # Reject any unmodeled use of the residual symbolic state.
                    source_count = {"clear": 0, "zero": 0, "ord": 1, "chr": 1,
                                    "concat": 2, "add": 2, "append": 1, "pop": 1,
                                    "neg": 1, "print": 0}[tail.op]
                    if any(not isinstance(state[r], str) for r in tail.args[:source_count]):
                        raise VMError("Symbolic state remains live in output tail")
                    if tail.op == "print" and not isinstance(state[4], str):
                        raise VMError("Symbolic output is not supported")
                    step_data(tail, state, "", output)
                    pc = tail.next_pc
                raise VMError("Output tail has no return")

            equal_pc = target if op == "je" else ins.next_pc
            unequal_pc = ins.next_pc if op == "je" else target
            accepted, rejected = finish(equal_pc), finish(unequal_pc)
            if accepted[-1:] != ["ok"] or rejected[-1:] != ["no"]:
                raise VMError("Unexpected accept/reject output")
            return suffix, terms, ins.pc, accepted, rejected
        elif op in ("jmp", "jl", "ret"):
            raise VMError(f"Unsupported control flow before suffix predicate: {op}")
        else:
            # Only concrete sources may enter the normal interpreter.
            if any(not isinstance(regs[r], str) for r in a) and op not in ("clear", "zero"):
                raise VMError(f"Unsupported symbolic operation at {ins.pc:#x}")
            step_data(ins, regs, "", prefix)
    raise VMError("No supported suffix predicate found")


def recovered_source(suffix):
    return '''"""Generated from fsvm bytecode. Domain: ASCII tokens of sufficient length."""
import re


def check(text: str) -> bool:
    if not text.isascii():
        raise ValueError("Only ASCII input is modeled")
    tokens = re.findall(r"[^ \\t\\n\\r\\v\\f]+", text)
    value = tokens[0] if tokens else ""
    expected = bytes(''' + repr(list(suffix.encode("ascii"))) + ''').decode("ascii")
    # Short input invokes ord(empty) in the original; reject safely in this model.
    return len(value) >= len(expected) and value.endswith(expected)


if __name__ == "__main__":
    print("flag:")
    print("ok" if check(input()) else "no")
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bytecode", nargs="?", type=Path, default=HERE / "inputs/bytecode")
    parser.add_argument("--out", type=Path, default=HERE / "generated")
    args = parser.parse_args()
    try:
        instructions = decode(args.bytecode.read_bytes())
        suffix, terms, pc, accepted, rejected = lift(instructions)
        if run(instructions, suffix) != accepted:
            raise VMError("Recovered candidate disagrees with interpreter")
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / "disassembly.txt").write_text("\n".join(map(str, instructions)) + "\n", encoding="utf-8")
        (args.out / "recovered.py").write_text(recovered_source(suffix), encoding="utf-8")
        evidence = [f"instructions: {len(instructions)}", f"predicate PC: {pc:#x}",
                    f"suffix: {suffix}", "Each decimal term must equal zero:",
                    *map(str, terms), f"equal output: {accepted}", f"unequal output: {rejected}"]
        (args.out / "constraints.txt").write_text("\n".join(evidence) + "\n", encoding="utf-8")
        print(f"Recovered {len(terms)} byte constraints from {len(instructions)} instructions")
        print(f"Flag: {suffix}")
        print(f"Behavior: first input token endswith({suffix!r}); prefixes are accepted")
        print(f"Artifacts: {args.out}")
    except (OSError, ValueError, TypeError) as error:
        parser.exit(1, f"error: {error}\n")


if __name__ == "__main__":
    main()
